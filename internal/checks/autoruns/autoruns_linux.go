//go:build linux

package autoruns

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

func (check) Name() string { return Name }
func (check) Description() string {
	return "Persistencia: ld.so.preload, ficheros de inicio de shell, autostart, claves SSH, udev, PAM, rc.local"
}
func (check) Phase() int { return core.PhaseCollect }

var systemShellFiles = []string{"/etc/profile", "/etc/bash.bashrc", "/etc/bashrc", "/etc/environment", "/etc/zsh/zshrc", "/etc/zsh/zprofile",
	"/etc/zshrc", "/etc/zprofile", "/etc/zsh/zshenv", "/etc/zshenv", "/etc/csh.cshrc", "/etc/csh.login", "/etc/rc.local", "/etc/rc.d/rc.local"}
var userShellFiles = []string{".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile", ".zshrc", ".zprofile", ".zshenv", ".zlogin", ".xprofile", ".xinitrc", ".xsessionrc", ".config/fish/config.fish"}

func (check) Run(env *core.Env) ([]core.Finding, error) {
	db := unixutil.Packages()
	homes := unixutil.HomeDirs()
	var out []core.Finding

	out = append(out, preload(env)...)

	shellFiles := append([]string{}, systemShellFiles...)
	shellFiles = append(shellFiles, unixutil.ListFiles("/etc/profile.d")...)
	for _, h := range homes {
		for _, f := range userShellFiles {
			shellFiles = append(shellFiles, filepath.Join(h, f))
		}
	}
	for _, f := range shellFiles {
		out = append(out, shellFile(env, f)...)
	}

	out = append(out, autostart(env, db, homes)...)
	out = append(out, sshKeys(homes)...)
	out = append(out, udev(env, db)...)
	out = append(out, pam(db)...)
	out = append(out, motd(env, db)...)
	out = append(out, moduleLoad()...)
	if !env.IsAdmin {
		env.Logf("autoruns: sin root solo se revisan los perfiles de usuario accesibles")
	}
	return out, nil
}

func preload(env *core.Env) []core.Finding {
	lines, err := unixutil.ReadLines("/etc/ld.so.preload")
	if err != nil {
		return nil
	}
	var out []core.Finding
	for _, lib := range parsePreload(lines) {
		env.Artifacts.Add(lib, "ld.so.preload")
		out = append(out, core.Finding{
			Severity:    core.Critical,
			Title:       "Biblioteca precargada globalmente (/etc/ld.so.preload): " + lib,
			Description: "Se inyecta en todos los procesos del sistema. Es la técnica típica de rootkits de usuario (Azazel, Jynx, libprocesshider) para ocultar ficheros y procesos.",
			Path:        lib,
			MITRE:       []string{"T1574.006", "T1014"},
			Recommendation: "Salvo que la haya configurado usted conscientemente, trate el equipo como comprometido. Copie la biblioteca para analizarla, " +
				"vacíe /etc/ld.so.preload desde un sistema de rescate (el rootkit puede ocultarse en el sistema en ejecución) y reinstale.",
		})
	}
	return out
}

func shellFile(env *core.Env, f string) []core.Finding {
	lines, err := unixutil.ReadLines(f)
	if err != nil {
		return nil
	}
	reasons, hits := assessShellLines(lines)
	if len(reasons) == 0 {
		return nil
	}
	env.Artifacts.Add(f, "shell-rc")
	sev, texts, mitre := core.Combine(reasons)
	return []core.Finding{{
		Severity: sev,
		Title:    "Fichero de inicio de shell con comandos sospechosos: " + f,
		Path:     f,
		Evidence: map[string]string{"líneas": strings.Join(hits, "\n")},
		Reasons:  texts,
		MITRE:    append(mitre, "T1546.004"),
		Recommendation: "Estos ficheros se ejecutan en cada inicio de sesión o shell. Revise las líneas indicadas y elimínelas si no las añadió usted; " +
			"después cierre las sesiones abiertas y revise qué ejecutables descargaron o lanzaron.",
	}}
}

func autostart(env *core.Env, db *unixutil.PackageDB, homes []string) []core.Finding {
	dirs := []string{"/etc/xdg/autostart"}
	for _, h := range homes {
		dirs = append(dirs, filepath.Join(h, ".config/autostart"))
	}
	var out []core.Finding
	for _, d := range dirs {
		files, _ := filepath.Glob(filepath.Join(d, "*.desktop"))
		for _, f := range files {
			lines, err := unixutil.ReadLines(f)
			if err != nil {
				continue
			}
			de := parseDesktop(lines)
			if de.Exec == "" {
				continue
			}
			vendor := db.Owner(f) != ""
			cmd := strings.NewReplacer("%u", "", "%U", "", "%f", "", "%F", "", "%i", "", "%c", "", "%k", "").Replace(de.Exec)
			e := unixutil.Inspect(cmd, vendor, db)
			if e.Path != "" {
				env.Artifacts.Add(e.Path, "autostart:"+filepath.Base(f))
			}
			ev := map[string]string{"fichero": f, "comando": de.Exec, "nombre": de.Name}
			if !de.Enabled {
				ev["estado"] = "deshabilitado"
			}
			minSev := core.Low
			if vendor {
				minSev = core.Medium
			}
			rec := "Elimine o deshabilite el fichero " + f + " si no reconoce el programa (también desde 'Aplicaciones al inicio' del escritorio) y analice el ejecutable."
			if fd := checkutil.UnixLaunchFinding("Autoarranque de escritorio sospechoso: "+filepath.Base(f), e, nil, ev, minSev, rec); fd != nil {
				fd.MITRE = append(fd.MITRE, "T1547.013")
				out = append(out, *fd)
			} else if !vendor {
				out = append(out, core.Finding{Severity: core.Info, Title: "Programa de inicio de escritorio: " + filepath.Base(f), Path: e.Path, Evidence: ev,
					MITRE: []string{"T1547.013"}, Recommendation: "Sin indicadores sospechosos. Desactívelo si no lo necesita."})
			}
		}
	}
	return out
}

func sshKeys(homes []string) []core.Finding {
	var out []core.Finding
	for _, h := range homes {
		for _, name := range []string{"authorized_keys", "authorized_keys2"} {
			f := filepath.Join(h, ".ssh", name)
			lines, err := unixutil.ReadLines(f)
			if err != nil {
				continue
			}
			keys := parseAuthorizedKeys(lines)
			if len(keys) == 0 {
				continue
			}
			var desc []string
			for _, k := range keys {
				desc = append(desc, fmt.Sprintf("línea %d: %s %s", k.Line, k.Type, k.Comment))
				if m := cmdOption.FindStringSubmatch(k.Options); m != nil {
					reasons := append([]core.Reason{{Severity: core.Medium, Text: "clave SSH con comando forzado", MITRE: []string{"T1098.004"}}}, heuristics.AssessUnixCommand(m[1])...)
					sev, texts, mitre := core.Combine(reasons)
					out = append(out, core.Finding{Severity: sev, Title: "Clave SSH autorizada con comando forzado en " + f, Path: f,
						Evidence: map[string]string{"comando": m[1], "clave": k.Type + " " + k.Comment}, Reasons: texts, MITRE: mitre,
						Recommendation: "Verifique que el comando forzado es legítimo (p. ej. backups con rrsync). Si no, elimine la clave."})
				}
			}
			sev := core.Info
			if name == "authorized_keys2" {
				sev = core.Low // deprecated file, sometimes used to hide keys
			}
			fi, _ := os.Stat(f)
			ev := map[string]string{"claves": strings.Join(desc, "\n")}
			if fi != nil {
				ev["modificado"] = fi.ModTime().Format("2006-01-02 15:04")
			}
			out = append(out, core.Finding{
				Severity: sev,
				Title:    fmt.Sprintf("%d claves SSH autorizadas en %s", len(keys), f),
				Path:     f,
				Evidence: ev,
				MITRE:    []string{"T1098.004"},
				Recommendation: "Cualquiera con la clave privada correspondiente puede entrar sin contraseña. Elimine las claves que no reconozca " +
					"(compare el comentario y la huella con 'ssh-keygen -lf " + f + "').",
			})
		}
	}
	return out
}

func udev(env *core.Env, db *unixutil.PackageDB) []core.Finding {
	var out []core.Finding
	for _, dir := range []string{"/etc/udev/rules.d", "/run/udev/rules.d", "/usr/lib/udev/rules.d", "/lib/udev/rules.d"} {
		files, _ := filepath.Glob(filepath.Join(dir, "*.rules"))
		for _, f := range files {
			if db.Owner(f) != "" {
				continue
			}
			lines, err := unixutil.ReadLines(f)
			if err != nil {
				continue
			}
			for _, run := range parseUdevRuns(lines) {
				e := unixutil.Inspect(run, false, db)
				if e.Path != "" {
					env.Artifacts.Add(e.Path, "udev:"+filepath.Base(f))
				}
				extra := []core.Reason{{Severity: core.Low, Text: "regla udev no gestionada por paquetes que ejecuta un programa", MITRE: []string{"T1546.017"}}}
				if fd := checkutil.UnixLaunchFinding("Regla udev ejecuta un programa: "+filepath.Base(f), e, extra, map[string]string{"regla": f, "comando": run}, core.Low,
					"Las reglas udev con RUN se ejecutan como root al conectar dispositivos. Si no reconoce esta regla, elimínela y ejecute 'udevadm control --reload'."); fd != nil {
					out = append(out, *fd)
				}
			}
		}
	}
	return out
}

func pam(db *unixutil.PackageDB) []core.Finding {
	var out []core.Finding
	for _, f := range unixutil.ListFiles("/etc/pam.d") {
		lines, err := unixutil.ReadLines(f)
		if err != nil {
			continue
		}
		for _, e := range parsePAM(lines) {
			rs := assessPAM(e)
			if len(rs) == 0 {
				continue
			}
			sev, texts, mitre := core.Combine(rs)
			out = append(out, core.Finding{
				Severity: sev,
				Title:    "Configuración PAM sospechosa en " + f,
				Path:     f,
				Evidence: map[string]string{"línea": fmt.Sprintf("%d: %s %s", e.Line, e.Module, e.Args)},
				Reasons:  texts,
				MITRE:    mitre,
				Recommendation: "Los módulos PAM ven las contraseñas en claro. Si no reconoce esta línea, restaure el fichero desde el paquete " +
					"(p. ej. 'apt install --reinstall libpam-runtime') y cambie las contraseñas.",
			})
		}
	}
	return out
}

func motd(env *core.Env, db *unixutil.PackageDB) []core.Finding {
	if !db.Available() {
		return nil
	}
	var out []core.Finding
	for _, f := range unixutil.ListFiles("/etc/update-motd.d") {
		if db.Owner(f) != "" {
			continue
		}
		lines, err := unixutil.ReadLines(f)
		if err != nil {
			continue
		}
		reasons, hits := assessShellLines(lines)
		reasons = append(reasons, core.Reason{Severity: core.Low, Text: "script de MOTD no gestionado por paquetes (se ejecuta como root en cada login SSH)", MITRE: []string{"T1037"}})
		sev, texts, mitre := core.Combine(reasons)
		env.Artifacts.Add(f, "motd")
		out = append(out, core.Finding{Severity: sev, Title: "Script update-motd.d no gestionado por paquetes: " + filepath.Base(f), Path: f,
			Evidence: map[string]string{"líneas": strings.Join(hits, "\n")}, Reasons: texts, MITRE: mitre,
			Recommendation: "Revise el script; si no lo reconoce, quite el permiso de ejecución ('chmod -x') y analícelo."})
	}
	return out
}

func moduleLoad() []core.Finding {
	files := append([]string{"/etc/modules"}, unixutil.ListFiles("/etc/modules-load.d")...)
	var out []core.Finding
	for _, f := range files {
		lines, err := unixutil.ReadLines(f)
		if err != nil {
			continue
		}
		for _, l := range lines {
			l = strings.TrimSpace(l)
			if l == "" || strings.HasPrefix(l, "#") {
				continue
			}
			if name := strings.Fields(l)[0]; IsRootkitModule(name) {
				out = append(out, core.Finding{Severity: core.Critical, Title: "Carga al arranque de un módulo de rootkit conocido: " + name, Path: f,
					MITRE: []string{"T1547.006", "T1014"}, Recommendation: "El equipo está comprometido a nivel de kernel. Aíslelo y reinstale desde cero."})
			}
		}
	}
	return out
}
