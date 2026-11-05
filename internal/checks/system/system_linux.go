//go:build linux

package system

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"husmea/internal/core"
	"husmea/internal/unixutil"
)

type check struct{}

func New() core.Check { return check{} }

func (check) Name() string { return Name }
func (check) Description() string {
	return "Seguridad del sistema: cuentas, sudo, SSH, módulos del kernel ocultos, rootkits, registros"
}
func (check) Phase() int { return core.PhaseCollect }

func readInt(p string) (int, bool) {
	b, err := os.ReadFile(p)
	if err != nil {
		return 0, false
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(b)))
	return v, err == nil
}

func (check) Run(env *core.Env) ([]core.Finding, error) {
	var out []core.Finding
	users := unixutil.Users()
	out = append(out, assessUsers(users)...)

	if lines, err := unixutil.ReadLines("/etc/shadow"); err == nil {
		out = append(out, assessShadow(lines, users)...)
	} else if !env.IsAdmin {
		env.Logf("system: /etc/shadow y /etc/sudoers requieren root")
	}
	for _, f := range append([]string{"/etc/sudoers"}, unixutil.ListFiles("/etc/sudoers.d")...) {
		if lines, err := unixutil.ReadLines(f); err == nil {
			out = append(out, assessSudoers(f, lines)...)
		}
	}

	seen := map[string]string{}
	var sshdFiles []string
	// Drop-ins are included before the main file's directives take effect, so read them first.
	dropins, _ := filepath.Glob("/etc/ssh/sshd_config.d/*.conf")
	sort.Strings(dropins)
	sshdFiles = append(sshdFiles, dropins...)
	sshdFiles = append(sshdFiles, "/etc/ssh/sshd_config")
	origin := map[string]string{}
	for _, f := range sshdFiles {
		if lines, err := unixutil.ReadLines(f); err == nil {
			parseSSHD(f, lines, seen, origin)
		}
	}
	out = append(out, assessSSHD(seen, origin)...)

	if lines, err := unixutil.ReadLines("/proc/modules"); err == nil {
		live := map[string]bool{}
		ents, _ := os.ReadDir("/sys/module")
		for _, e := range ents {
			if b, err := os.ReadFile(filepath.Join("/sys/module", e.Name(), "initstate")); err == nil && strings.TrimSpace(string(b)) == "live" {
				live[e.Name()] = true
			}
		}
		out = append(out, assessModules(moduleNames(lines), live)...)
	}
	if v, ok := readInt("/proc/sys/kernel/tainted"); ok {
		if f := assessTaint(v); f != nil {
			out = append(out, *f)
		}
	}
	if v, ok := readInt("/proc/sys/kernel/randomize_va_space"); ok && v != 2 {
		out = append(out, core.Finding{Severity: core.Medium, Title: "ASLR no está completamente activado (randomize_va_space=" + strconv.Itoa(v) + ")",
			MITRE: []string{"T1562"}, Recommendation: "Actívelo con 'sysctl -w kernel.randomize_va_space=2' y hágalo persistente en /etc/sysctl.d/. Si se desactivó sin motivo, investigue."})
	}

	out = append(out, lsm()...)
	out = append(out, logTampering(env)...)

	for p, family := range iocFiles {
		if _, err := os.Lstat(p); err == nil {
			env.Artifacts.Add(p, "ioc-fichero")
			out = append(out, core.Finding{Severity: core.Critical, Title: "Fichero asociado a malware conocido: " + p, Description: "Ruta típica de " + family + ".",
				Path: p, MITRE: []string{"T1036"}, Recommendation: "Analice el fichero (sha256sum, VirusTotal). Si se confirma, aísle el equipo y reinstale."})
		}
	}
	return out, nil
}

func lsm() []core.Finding {
	if v, ok := readInt("/sys/fs/selinux/enforce"); ok {
		if v == 0 {
			return []core.Finding{{Severity: core.Low, Title: "SELinux en modo permisivo", MITRE: []string{"T1562.001"},
				Recommendation: "Active el modo enforcing ('setenforce 1' y SELINUX=enforcing en /etc/selinux/config) salvo que tenga un motivo para no hacerlo."}}
		}
		return nil
	}
	if b, err := os.ReadFile("/sys/module/apparmor/parameters/enabled"); err == nil {
		if strings.TrimSpace(string(b)) != "Y" {
			return []core.Finding{{Severity: core.Low, Title: "AppArmor desactivado", MITRE: []string{"T1562.001"},
				Recommendation: "Actívelo ('systemctl enable --now apparmor') salvo que use otro sistema de control de acceso."}}
		}
		return nil
	}
	return []core.Finding{{Severity: core.Info, Title: "No se detectó SELinux ni AppArmor activos",
		Recommendation: "Considere activar un módulo de seguridad (AppArmor o SELinux) para limitar el impacto de un compromiso."}}
}

func logTampering(env *core.Env) []core.Finding {
	var out []core.Finding
	for _, f := range []string{"/var/log/wtmp"} {
		if fi, err := os.Stat(f); err == nil && fi.Size() == 0 {
			out = append(out, core.Finding{Severity: core.Medium, Title: "Registro de accesos vacío: " + f, Path: f, MITRE: []string{"T1070.002"},
				Recommendation: "Un fichero de registro de logins vacío puede indicar borrado de huellas (o una instalación muy reciente/rotación). Revise también journalctl y /var/log/auth.log."})
		}
	}
	for _, h := range unixutil.HomeDirs() {
		for _, name := range []string{".bash_history", ".zsh_history"} {
			p := filepath.Join(h, name)
			if t, err := os.Readlink(p); err == nil && t == "/dev/null" {
				out = append(out, core.Finding{Severity: core.Medium, Title: "Historial de comandos redirigido a /dev/null: " + p, Path: p, MITRE: []string{"T1070.003"},
					Recommendation: "Alguien desactivó el historial para no dejar rastro. Si no fue usted, investigue la actividad de esa cuenta."})
			}
		}
	}
	return out
}
