//go:build linux

package tasks

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"husmea/internal/checks/checkutil"
	"husmea/internal/core"
	"husmea/internal/heuristics"
	"husmea/internal/unixutil"
)

type check struct{}

func New() core.Check { return check{} }

func (check) Name() string        { return Name }
func (check) Description() string { return "Tareas programadas: cron, anacron, at y timers de systemd" }
func (check) Phase() int          { return core.PhaseCollect }

func (check) Run(env *core.Env) ([]core.Finding, error) {
	db := unixutil.Packages()
	var out []core.Finding
	denied := 0

	type src struct {
		file   string
		system bool
		owner  string
	}
	var srcs []src
	srcs = append(srcs, src{"/etc/crontab", true, ""})
	for _, f := range unixutil.ListFiles("/etc/cron.d") {
		srcs = append(srcs, src{f, true, ""})
	}
	for _, dir := range []string{"/var/spool/cron/crontabs", "/var/spool/cron"} {
		if _, err := os.ReadDir(dir); err != nil && os.IsPermission(err) {
			denied++
		}
		for _, f := range unixutil.ListFiles(dir) {
			srcs = append(srcs, src{f, false, filepath.Base(f)})
		}
	}

	for _, s := range srcs {
		lines, err := unixutil.ReadLines(s.file)
		if err != nil {
			if os.IsPermission(err) {
				denied++
			}
			continue
		}
		owner := db.Owner(s.file)
		vendor := owner != ""
		for _, e := range ParseCrontab(s.file, lines, s.system, s.owner) {
			out = append(out, assessCron(env, db, e, vendor)...)
		}
	}

	for _, period := range []string{"hourly", "daily", "weekly", "monthly"} {
		for _, f := range unixutil.ListFiles("/etc/cron." + period) {
			if strings.HasPrefix(filepath.Base(f), ".placeholder") || db.Owner(f) != "" {
				continue
			}
			out = append(out, assessScript(env, f, "Script cron."+period+" no gestionado por paquetes: "+filepath.Base(f), db.Available(), "T1053.003")...)
		}
	}

	for _, dir := range []string{"/var/spool/cron/atjobs", "/var/spool/at"} {
		if _, err := os.ReadDir(dir); err != nil && os.IsPermission(err) {
			denied++
		}
		for _, f := range unixutil.ListFiles(dir) {
			if strings.HasPrefix(filepath.Base(f), ".") {
				continue
			}
			fs := assessScript(env, f, "Trabajo 'at' programado: "+filepath.Base(f), true, "T1053.002")
			for i := range fs {
				if fs[i].Severity < core.Low {
					fs[i].Severity = core.Low
				}
			}
			out = append(out, fs...)
		}
	}

	out = append(out, timers(db)...)
	if denied > 0 && !env.IsAdmin {
		env.Logf("tasks: %d ubicaciones de cron/at requieren root (ejecute con sudo para revisarlas)", denied)
	}
	return out, nil
}

func assessCron(env *core.Env, db *unixutil.PackageDB, c CronEntry, vendor bool) []core.Finding {
	e := unixutil.Inspect(c.Command, vendor, db)
	if e.Path != "" {
		env.Artifacts.Add(e.Path, "cron:"+c.File)
	}
	ev := map[string]string{
		"fichero":      fmt.Sprintf("%s (línea %d)", c.File, c.Line),
		"programación": c.Schedule,
		"usuario":      c.User,
		"comando":      c.Command,
	}
	minSev := core.Low
	if vendor {
		minSev = core.Medium
	}
	rec := "Revise la entrada en " + c.File + " (o con 'crontab -l -u " + c.User + "'). Si no la reconoce, elimínela ('crontab -e -u " + c.User +
		"' para crontabs de usuario), analice el programa que lanza y busque otras formas de persistencia."
	if f := checkutil.UnixLaunchFinding("Tarea cron sospechosa: "+short(c.Command), e, nil, ev, minSev, rec); f != nil {
		f.MITRE = append(f.MITRE, "T1053.003")
		return []core.Finding{*f}
	}
	if vendor {
		return nil
	}
	return []core.Finding{{
		Severity:       core.Info,
		Title:          "Tarea cron: " + short(c.Command),
		Path:           e.Path,
		Evidence:       ev,
		MITRE:          []string{"T1053.003"},
		Recommendation: "Sin indicadores sospechosos. Verifique que reconoce esta tarea.",
	}}
}

func assessScript(env *core.Env, f, title string, inventory bool, technique string) []core.Finding {
	lines, err := unixutil.ReadLines(f)
	if err != nil {
		return nil
	}
	env.Artifacts.Add(f, "programada")
	var reasons []core.Reason
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		reasons = append(reasons, heuristics.AssessUnixCommand(l)...)
	}
	if len(reasons) == 0 && !inventory {
		return nil
	}
	sev, texts, mitre := core.Info, []string(nil), []string(nil)
	if len(reasons) > 0 {
		sev, texts, mitre = core.Combine(reasons)
	}
	return []core.Finding{{
		Severity:       sev,
		Title:          title,
		Path:           f,
		Reasons:        texts,
		MITRE:          append(mitre, technique),
		Recommendation: "Revise el contenido del script. Si no lo reconoce, muévalo fuera del directorio para desactivarlo y analícelo.",
	}}
}

func timers(db *unixutil.PackageDB) []core.Finding {
	if !db.Available() {
		return nil
	}
	var out []core.Finding
	dirs := []string{"/etc/systemd/system", "/etc/systemd/user"}
	for _, h := range unixutil.HomeDirs() {
		dirs = append(dirs, filepath.Join(h, ".config/systemd/user"))
	}
	for _, d := range dirs {
		files, _ := filepath.Glob(filepath.Join(d, "*.timer"))
		for _, f := range files {
			if fi, err := os.Lstat(f); err != nil || fi.Mode()&os.ModeSymlink != 0 || db.Owner(f) != "" {
				continue
			}
			unit := strings.TrimSuffix(filepath.Base(f), ".timer") + ".service"
			out = append(out, core.Finding{
				Severity:       core.Info,
				Title:          "Timer systemd no gestionado por paquetes: " + filepath.Base(f),
				Path:           f,
				Evidence:       map[string]string{"servicio": unit},
				MITRE:          []string{"T1053.006"},
				Recommendation: "Revise el timer y el servicio que activa ('systemctl cat " + filepath.Base(f) + " " + unit + "').",
			})
		}
	}
	return out
}

func short(s string) string {
	if r := []rune(s); len(r) > 60 {
		return string(r[:57]) + "…"
	}
	return s
}
