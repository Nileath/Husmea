// Package system audits Linux security posture and rootkit indicators.
package system

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"husmea/internal/core"
	"husmea/internal/unixutil"
)

const Name = "system"

func assessUsers(users []unixutil.User) []core.Finding {
	var out []core.Finding
	var logins []string
	for _, u := range users {
		if u.UID == 0 && u.Name != "root" {
			out = append(out, core.Finding{
				Severity:       core.Critical,
				Title:          "Cuenta con UID 0 (privilegios de root): " + u.Name,
				Description:    "Cualquier cuenta con UID 0 es equivalente a root. Es una puerta trasera clásica.",
				Evidence:       map[string]string{"usuario": u.Name, "home": u.Home, "shell": u.Shell},
				MITRE:          []string{"T1136.001", "T1078.003"},
				Recommendation: "Si no la creó usted, bloquéela ('usermod -L " + u.Name + "' y 'usermod -s /usr/sbin/nologin " + u.Name + "'), investigue cuándo se creó (/var/log/auth.log) y elimínela.",
			})
		}
		if u.LoginShell() && (u.UID == 0 || u.UID >= 1000) && u.UID < 60000 {
			logins = append(logins, fmt.Sprintf("%s (uid %d, %s)", u.Name, u.UID, u.Shell))
		}
	}
	if len(logins) > 0 {
		out = append(out, core.Finding{
			Severity:       core.Info,
			Title:          fmt.Sprintf("Inventario: %d cuentas con shell de inicio de sesión", len(logins)),
			Evidence:       map[string]string{"cuentas": strings.Join(logins, "\n")},
			Recommendation: "Compruebe que reconoce todas las cuentas.",
		})
	}
	return out
}

// assessShadow flags accounts that can log in without a password.
func assessShadow(lines []string, users []unixutil.User) []core.Finding {
	shells := map[string]bool{}
	for _, u := range users {
		shells[u.Name] = u.LoginShell()
	}
	var out []core.Finding
	for _, l := range lines {
		f := strings.Split(l, ":")
		if len(f) < 2 || f[0] == "" {
			continue
		}
		if f[1] == "" && shells[f[0]] {
			out = append(out, core.Finding{
				Severity:       core.High,
				Title:          "Cuenta sin contraseña: " + f[0],
				MITRE:          []string{"T1078"},
				Recommendation: "Asigne una contraseña ('passwd " + f[0] + "') o bloquee la cuenta ('passwd -l " + f[0] + "').",
			})
		}
	}
	return out
}

func assessSudoers(file string, lines []string) []core.Finding {
	var out []core.Finding
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "Defaults") || strings.HasPrefix(t, "@") {
			continue
		}
		up := strings.ToUpper(t)
		if !strings.Contains(up, "NOPASSWD") || !strings.HasSuffix(strings.TrimSpace(up), "ALL") {
			continue
		}
		who := strings.Fields(t)[0]
		sev := core.Medium
		if who == "ALL" {
			sev = core.Critical
		}
		out = append(out, core.Finding{
			Severity:       sev,
			Title:          "sudo sin contraseña para " + who,
			Description:    "Cualquier proceso que se ejecute como " + who + " puede obtener root sin conocer la contraseña.",
			Path:           file,
			Evidence:       map[string]string{"línea": fmt.Sprintf("%d: %s", i+1, t)},
			MITRE:          []string{"T1548.003"},
			Recommendation: "Si no es imprescindible, elimine NOPASSWD ('visudo -f " + file + "') o limítelo a comandos concretos.",
		})
	}
	return out
}

// parseSSHD collects sshd_config directives; the first occurrence wins and Match blocks are ignored.
func parseSSHD(file string, lines []string, seen, origin map[string]string) {
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		f := strings.Fields(t)
		k := strings.ToLower(f[0])
		if k == "match" {
			return
		}
		if _, ok := seen[k]; !ok && len(f) >= 2 {
			seen[k] = strings.Join(f[1:], " ")
			origin[k] = file
		}
	}
}

var benignKeysCommand = []string{"userdbctl", "sss_ssh_authorizedkeys", "google_authorized_keys", "eic_run_authorized_keys", "ec2-instance-connect", "gcloud", "ipa"}

// assessSSHD evaluates the effective sshd configuration.
func assessSSHD(seen, origin map[string]string) []core.Finding {
	var out []core.Finding
	add := func(key string, sev core.Severity, title, rec string, mitre ...string) {
		out = append(out, core.Finding{Severity: sev, Title: title, Path: origin[key], MITRE: mitre, Recommendation: rec})
	}
	if strings.EqualFold(seen["permitrootlogin"], "yes") {
		add("permitrootlogin", core.Medium, "SSH permite el acceso directo de root con contraseña", "Configure 'PermitRootLogin prohibit-password' o 'no' y reinicie sshd.", "T1078.003", "T1110")
	}
	if strings.EqualFold(seen["permitemptypasswords"], "yes") {
		add("permitemptypasswords", core.High, "SSH permite contraseñas vacías", "Configure 'PermitEmptyPasswords no' y reinicie sshd.", "T1078")
	}
	if v, ok := seen["authorizedkeysfile"]; ok {
		def := map[string]bool{".ssh/authorized_keys": true, ".ssh/authorized_keys2": true, "%h/.ssh/authorized_keys": true, "%h/.ssh/authorized_keys2": true}
		for _, p := range strings.Fields(v) {
			if !def[p] && !strings.EqualFold(p, "none") {
				add("authorizedkeysfile", core.Medium, "SSH usa un fichero de claves autorizadas no estándar: "+p,
					"Una ruta adicional de claves puede usarse para mantener acceso oculto. Verifique ese fichero y su contenido.", "T1098.004")
				break
			}
		}
	}
	if v, ok := seen["authorizedkeyscommand"]; ok && v != "none" {
		benign := false
		for _, b := range benignKeysCommand {
			if strings.Contains(v, b) {
				benign = true
			}
		}
		if !benign {
			add("authorizedkeyscommand", core.Medium, "SSH ejecuta un comando para obtener claves: "+v, "Verifique que el comando es legítimo (p. ej. integración con LDAP/IAM).", "T1098.004")
		}
	}
	return out
}

// moduleNames parses /proc/modules.
func moduleNames(lines []string) map[string]bool {
	out := map[string]bool{}
	for _, l := range lines {
		if f := strings.Fields(l); len(f) > 0 {
			out[f[0]] = true
		}
	}
	return out
}

var rootkitModules = map[string]bool{"diamorphine": true, "reptile": true, "reptile_module": true, "suterusu": true, "kovid": true, "adore": true,
	"adore_ng": true, "enyelkm": true, "nuk3gh0st": true, "phalanx": true, "rootfoo": true, "brokepkg": true, "singularity": true, "khook": true}

// assessModules compares the module list with sysfs: a loaded module missing from
// /proc/modules (or vice versa) is being hidden, a classic LKM rootkit behaviour.
func assessModules(proc map[string]bool, sysLive map[string]bool) []core.Finding {
	var out []core.Finding
	var hidden []string
	for m := range sysLive {
		if !proc[m] {
			hidden = append(hidden, m)
		}
	}
	sort.Strings(hidden)
	for _, m := range hidden {
		out = append(out, core.Finding{
			Severity:       core.Critical,
			Title:          "Módulo del kernel oculto: " + m,
			Description:    "El módulo aparece cargado en /sys/module pero no en /proc/modules (lsmod). Los rootkits de kernel se ocultan así.",
			MITRE:          []string{"T1014", "T1547.006"},
			Recommendation: "Trate el equipo como comprometido a nivel de kernel: aíslelo, preserve evidencias (memoria) y reinstale desde cero.",
		})
	}
	var names []string
	for m := range proc {
		names = append(names, m)
	}
	sort.Strings(names)
	for _, m := range names {
		if rootkitModules[m] {
			out = append(out, core.Finding{Severity: core.Critical, Title: "Módulo de rootkit conocido cargado: " + m, MITRE: []string{"T1014"},
				Recommendation: "El equipo está comprometido a nivel de kernel. Aíslelo y reinstale desde cero."})
		}
	}
	return out
}

func assessTaint(v int) *core.Finding {
	var flags []string
	if v&1 != 0 {
		flags = append(flags, "módulo propietario")
	}
	if v&4096 != 0 {
		flags = append(flags, "módulo fuera del árbol del kernel")
	}
	if v&8192 != 0 {
		flags = append(flags, "módulo sin firma")
	}
	if len(flags) == 0 {
		return nil
	}
	sev := core.Info
	if v&8192 != 0 {
		sev = core.Low
	}
	return &core.Finding{
		Severity:       sev,
		Title:          "Kernel marcado (tainted): " + strings.Join(flags, ", "),
		Evidence:       map[string]string{"valor": strconv.Itoa(v)},
		MITRE:          []string{"T1547.006"},
		Recommendation: "Suele deberse a controladores legítimos (NVIDIA, VirtualBox, VMware). Revise con 'lsmod' y 'modinfo' que reconoce los módulos cargados.",
	}
}

// iocFiles are paths left by well-known Linux malware families.
var iocFiles = map[string]string{
	"/lib/libkeyutils.so.1.9":           "Ebury (backdoor de OpenSSH)",
	"/lib64/libkeyutils.so.1.9":         "Ebury (backdoor de OpenSSH)",
	"/usr/lib/libkeyutils.so.1.9":       "Ebury (backdoor de OpenSSH)",
	"/tmp/kdevtmpfsi":                   "Kinsing / kdevtmpfsi (criptominero)",
	"/var/tmp/kdevtmpfsi":               "Kinsing / kdevtmpfsi (criptominero)",
	"/tmp/kinsing":                      "Kinsing (criptominero)",
	"/var/tmp/kinsing":                  "Kinsing (criptominero)",
	"/etc/cron.hourly/gcc.sh":           "XOR.DDoS",
	"/etc/cron.hourly/cron.sh":          "XOR.DDoS",
	"/lib/libudev.so":                   "XOR.DDoS",
	"/usr/bin/.sshd":                    "backdoor SSH",
	"/dev/.udev/.lib":                   "rootkit de usuario",
	"/usr/lib/libprocesshider.so":       "libprocesshider (oculta procesos)",
	"/usr/local/lib/libprocesshider.so": "libprocesshider (oculta procesos)",
	"/etc/ld.so.preload.bak":            "manipulación de ld.so.preload",
	"/tmp/.ICE-unix/.x":                 "dropper en directorio oculto",
	"/usr/bin/bsd-port/knerl":           "Linux/BillGates (BillGates botnet)",
	"/usr/bin/pojie":                    "Linux/BillGates",
	"/tmp/moni.lod":                     "Linux/BillGates",
	"/etc/rc.d/init.d/DbSecuritySpt":    "Linux/BillGates",
	"/etc/init.d/DbSecuritySpt":         "Linux/BillGates",
	"/etc/init.d/selinux":               "Linux/BillGates (falso servicio selinux)",
}
