//go:build linux

package services

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"husmea/internal/checks/checkutil"
	"husmea/internal/core"
	"husmea/internal/heuristics"
	"husmea/internal/unixutil"
)

type check struct{}

func New() core.Check { return check{} }

func (check) Name() string        { return Name }
func (check) Description() string { return "Servicios systemd (sistema y usuario) y scripts SysV init" }
func (check) Phase() int          { return core.PhaseCollect }

var systemDirs = []string{"/etc/systemd/system", "/run/systemd/system", "/usr/local/lib/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"}
var userDirs = []string{"/etc/systemd/user", "/usr/lib/systemd/user", "/usr/local/lib/systemd/user"}

func unitDirs() []string {
	dirs := append(append([]string{}, systemDirs...), userDirs...)
	for _, h := range unixutil.HomeDirs() {
		dirs = append(dirs, filepath.Join(h, ".config/systemd/user"), filepath.Join(h, ".local/share/systemd/user"))
	}
	// /lib is often a symlink to /usr/lib: deduplicate by real path.
	seen := map[string]bool{}
	var out []string
	for _, d := range dirs {
		real, err := filepath.EvalSymlinks(d)
		if err != nil || seen[real] {
			continue
		}
		seen[real] = true
		out = append(out, d)
	}
	return out
}

// enabledUnits returns unit names linked from *.wants / *.requires directories.
func enabledUnits(dirs []string) map[string]bool {
	out := map[string]bool{}
	for _, d := range dirs {
		subs, _ := filepath.Glob(filepath.Join(d, "*.wants"))
		reqs, _ := filepath.Glob(filepath.Join(d, "*.requires"))
		for _, s := range append(subs, reqs...) {
			ents, _ := os.ReadDir(s)
			for _, e := range ents {
				out[e.Name()] = true
			}
		}
	}
	return out
}

func standardUnitDir(p string) bool {
	for _, d := range append(append([]string{}, systemDirs...), userDirs...) {
		if strings.HasPrefix(p, d+"/") {
			return true
		}
	}
	return false
}

func (check) Run(env *core.Env) ([]core.Finding, error) {
	db := unixutil.Packages()
	dirs := unitDirs()
	enabled := enabledUnits(dirs)
	var out []core.Finding
	seen := map[string]bool{}

	for _, d := range dirs {
		files, _ := filepath.Glob(filepath.Join(d, "*.service"))
		dropins, _ := filepath.Glob(filepath.Join(d, "*.service.d", "*.conf"))
		files = append(files, dropins...)
		sort.Strings(files)
		for _, f := range files {
			if env.Ctx.Err() != nil {
				return out, env.Ctx.Err()
			}
			target := f
			if fi, err := os.Lstat(f); err == nil && fi.Mode()&os.ModeSymlink != 0 {
				real, err := filepath.EvalSymlinks(f)
				if err != nil || real == "/dev/null" || standardUnitDir(real) {
					continue // masked, dangling, or analyzed in its own directory
				}
				target = real
			}
			if seen[target] {
				continue
			}
			seen[target] = true
			out = append(out, assessUnitFile(env, db, f, target, enabled)...)
		}
	}
	out = append(out, sysvInit(env, db)...)
	return out, nil
}

func assessUnitFile(env *core.Env, db *unixutil.PackageDB, path, target string, enabled map[string]bool) []core.Finding {
	fh, err := os.Open(target)
	if err != nil {
		return nil
	}
	u := ParseUnit(fh)
	fh.Close()
	name := filepath.Base(path)
	if strings.HasSuffix(filepath.Dir(path), ".service.d") {
		name = strings.TrimSuffix(filepath.Base(filepath.Dir(path)), ".d") + " (drop-in " + filepath.Base(path) + ")"
	}
	owner := db.Owner(target)
	vendor := owner != ""
	userUnit := strings.Contains(path, "/.config/systemd/") || strings.Contains(path, "/.local/share/systemd/")
	unitName := filepath.Base(path)
	isEnabled := enabled[unitName]

	var extra []core.Reason
	if db.Available() && !vendor && (strings.HasPrefix(target, "/usr/lib/") || strings.HasPrefix(target, "/lib/")) {
		extra = append(extra, core.Reason{Severity: core.Medium, Text: "unidad en un directorio del sistema que no pertenece a ningún paquete", MITRE: []string{"T1543.002"}})
	}
	minSev := core.Low
	if vendor {
		minSev = core.Medium
	}
	ev := map[string]string{"unidad": target, "descripción": u.Description, "usuario": u.User}
	if isEnabled {
		ev["habilitada"] = "sí"
	}
	if owner != "" {
		ev["paquete_unidad"] = owner
	}
	scope := "--system"
	kind := "Servicio systemd"
	if userUnit || strings.Contains(path, "/systemd/user") {
		scope, kind = "--user", "Servicio systemd de usuario"
	}
	rec := "Inspeccione la unidad con 'systemctl " + scope + " cat " + unitName + "' y su estado con 'systemctl " + scope + " status " + unitName + "'. " +
		"Si no la reconoce, deténgala y deshabilítela ('systemctl " + scope + " disable --now " + unitName + "'), analice el ejecutable y elimine la unidad. " +
		"Luego ejecute 'systemctl daemon-reload'."

	var out []core.Finding
	reported := false
	for _, cmd := range u.Exec {
		e := unixutil.Inspect(cmd, vendor, db)
		if e.Path != "" {
			env.Artifacts.Add(e.Path, "systemd:"+unitName)
		}
		ev2 := cloneMap(ev)
		ev2["comando"] = cmd
		if f := checkutil.UnixLaunchFinding(kind+" sospechoso: "+name, e, extra, ev2, minSev, rec); f != nil {
			f.MITRE = appendUnique(f.MITRE, "T1543.002")
			out = append(out, *f)
			reported = true
		}
	}
	if !reported && !vendor && db.Available() && len(u.Exec) > 0 {
		out = append(out, core.Finding{
			Severity:       core.Info,
			Title:          kind + " no gestionado por paquetes: " + name,
			Path:           target,
			Evidence:       map[string]string{"comando": strings.Join(u.Exec, "\n"), "descripción": u.Description},
			MITRE:          []string{"T1543.002"},
			Recommendation: "Servicio creado manualmente o por un instalador externo. Verifique que lo reconoce.",
		})
	}
	return out
}

func sysvInit(env *core.Env, db *unixutil.PackageDB) []core.Finding {
	var out []core.Finding
	for _, f := range unixutil.ListFiles("/etc/init.d") {
		base := filepath.Base(f)
		if base == "README" || base == "skeleton" || db.Owner(f) != "" {
			continue
		}
		lines, err := unixutil.ReadLines(f)
		if err != nil {
			continue
		}
		env.Artifacts.Add(f, "init.d")
		var reasons []core.Reason
		for _, l := range ScriptCommands(lines) {
			reasons = append(reasons, heuristics.AssessUnixCommand(l)...)
		}
		sev := core.Info
		var texts, mitre []string
		if len(reasons) > 0 {
			sev, texts, mitre = core.Combine(reasons)
		}
		if !db.Available() && sev == core.Info {
			continue
		}
		out = append(out, core.Finding{
			Severity:       sev,
			Title:          "Script SysV init no gestionado por paquetes: " + base,
			Path:           f,
			Reasons:        texts,
			MITRE:          append(mitre, "T1037.004"),
			Recommendation: "Revise el contenido del script. Si no lo reconoce, deshabilítelo ('update-rc.d " + base + " remove' o 'chkconfig " + base + " off') y analícelo.",
		})
	}
	return out
}

func cloneMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}
