package heuristics

import (
	"path"
	"regexp"
	"strings"

	"husmea/internal/core"
)

// This file holds Linux/Unix rules. Paths are POSIX, case-sensitive.

// devDirs are per-user tool directories where executables are expected.
var devDirs = []string{
	".local/", ".cache/gitstatus/", ".cache/puppeteer/", ".cache/bazel/", ".cache/go-build/", ".cargo/", ".rustup/", "go/", ".go/", ".npm/", ".nvm/", ".vscode/", ".vscode-server/",
	".cursor-server/", ".pyenv/", ".sdkman/", ".deno/", ".bun/", "snap/", ".var/app/", ".steam/", ".gradle/", ".m2/",
	".conda/", "anaconda3/", "miniconda3/", ".virtualenvs/", ".rbenv/", ".gem/", ".dotnet/", ".nix-profile/", ".mozilla/",
	".config/Code/", ".config/google-chrome/", ".config/chromium/", ".cache/ms-playwright/", ".cache/JetBrains/",
}

// ClassifyUnixPath returns how suspicious it is for an executable to live at p.
func ClassifyUnixPath(p string) Location {
	p = path.Clean(p)
	hiddenIn := func(rest string) bool {
		for _, c := range strings.Split(rest, "/") {
			if strings.HasPrefix(c, ".") && c != "." && c != ".." {
				return true
			}
		}
		return false
	}
	under := func(prefix string) (string, bool) {
		if strings.HasPrefix(p, prefix) {
			return strings.TrimPrefix(p, prefix), true
		}
		return "", false
	}
	if rest, ok := under("/dev/shm/"); ok {
		return Location{Category: "shm", Label: "memoria compartida /dev/shm", Severity: core.High, RootDrop: !strings.Contains(rest, "/")}
	}
	for _, t := range []string{"/tmp/", "/var/tmp/"} {
		if rest, ok := under(t); ok {
			l := Location{Category: "temp", Label: "directorio temporal " + strings.TrimSuffix(t, "/"), Severity: core.High, RootDrop: !strings.Contains(rest, "/")}
			if hiddenIn(rest) {
				l.Label += " (oculto)"
				l.Category = "temphidden"
			}
			return l
		}
	}
	if _, ok := under("/dev/"); ok {
		return Location{Category: "dev", Label: "directorio de dispositivos /dev", Severity: core.Critical}
	}
	if _, ok := under("/run/user/"); ok {
		return Location{Category: "run", Label: "directorio de ejecución del usuario /run/user", Severity: core.Medium}
	}
	for _, t := range []string{"/var/www/", "/srv/www/", "/srv/http/"} {
		if _, ok := under(t); ok {
			return Location{Category: "web", Label: "directorio web", Severity: core.High}
		}
	}
	home, rest := "", ""
	if r, ok := under("/root/"); ok {
		home, rest = "/root", r
	} else if r, ok := under("/home/"); ok {
		if i := strings.IndexByte(r, '/'); i >= 0 {
			home, rest = "/home/"+r[:i], r[i+1:]
		}
	}
	if home != "" {
		for _, d := range devDirs {
			if strings.HasPrefix(rest, d) {
				return Location{Category: "homedev", Label: "herramientas del usuario (" + strings.TrimSuffix(d, "/") + ")", Severity: core.Info}
			}
		}
		// Per-user tool installers commonly use ~/.<tool>/bin/<exe> (bun, deno, opencode, dotnet...).
		if parts := strings.Split(rest, "/"); len(parts) == 3 && strings.HasPrefix(parts[0], ".") && parts[1] == "bin" {
			return Location{Category: "homedev", Label: "herramientas del usuario (" + parts[0] + "/bin)", Severity: core.Info}
		}
		root := !strings.Contains(rest, "/")
		if hiddenIn(rest) {
			sev := core.Medium
			if root {
				sev = core.High // e.g. ~/.x executable directly in the home directory
			}
			return Location{Category: "homehidden", Label: "directorio oculto del perfil " + home, Severity: sev, RootDrop: root}
		}
		return Location{Category: "home", Label: "directorio personal " + home, Severity: core.Low, RootDrop: root}
	}
	for _, t := range []string{"/snap/", "/var/lib/snapd/", "/var/lib/flatpak/", "/nix/store/", "/var/lib/docker/", "/var/lib/containers/"} {
		if _, ok := under(t); ok {
			return Location{Category: "managed", Label: "software gestionado (" + strings.Trim(t, "/") + ")", Severity: core.Info}
		}
	}
	for _, t := range []string{"/usr/local/", "/opt/"} {
		if _, ok := under(t); ok {
			return Location{Category: "local", Label: "software local " + strings.TrimSuffix(t, "/"), Severity: core.Info}
		}
	}
	if IsUnixSystemPath(p) {
		if hiddenIn(p) {
			return Location{Category: "syshidden", Label: "directorio oculto dentro del sistema", Severity: core.High}
		}
		return Location{Category: "system", Label: "directorio del sistema", Severity: core.Info}
	}
	for _, t := range []string{"/etc/", "/var/", "/boot/", "/mnt/", "/media/"} {
		if _, ok := under(t); ok {
			return Location{Category: "unusual", Label: "ubicación inusual para ejecutables (" + strings.TrimSuffix(t, "/") + ")", Severity: core.Medium}
		}
	}
	return Location{Category: "other", Label: "otra ubicación", Severity: core.Info}
}

// IsUnixSystemPath reports whether p is under directories managed by the package manager.
func IsUnixSystemPath(p string) bool {
	for _, t := range []string{"/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib/", "/usr/lib32/", "/usr/lib64/", "/usr/libexec/", "/lib/", "/lib32/", "/lib64/", "/usr/share/", "/usr/games/"} {
		if strings.HasPrefix(p, t) {
			return true
		}
	}
	return false
}

// IsUnixBinDir reports whether p is in a classic binary directory (stronger expectation of package ownership).
func IsUnixBinDir(p string) bool {
	d := path.Dir(p)
	return d == "/usr/bin" || d == "/usr/sbin" || d == "/bin" || d == "/sbin"
}

// unixDaemons maps well-known process names to the directories they legitimately run from.
var unixDaemons = map[string][]string{
	"sshd":           {"/usr/sbin/", "/sbin/", "/usr/bin/"},
	"systemd":        {"/usr/lib/systemd/", "/lib/systemd/", "/usr/bin/", "/bin/"},
	"init":           {"/sbin/", "/usr/sbin/", "/usr/lib/systemd/", "/lib/systemd/"},
	"cron":           {"/usr/sbin/", "/sbin/"},
	"crond":          {"/usr/sbin/", "/sbin/"},
	"dbus-daemon":    {"/usr/bin/", "/bin/"},
	"rsyslogd":       {"/usr/sbin/", "/sbin/"},
	"auditd":         {"/usr/sbin/", "/sbin/"},
	"udevd":          {"/usr/lib/systemd/", "/lib/systemd/", "/sbin/"},
	"agetty":         {"/usr/sbin/", "/sbin/"},
	"polkitd":        {"/usr/lib/polkit-1/", "/usr/libexec/", "/usr/lib/"},
	"NetworkManager": {"/usr/sbin/", "/usr/bin/"},
}

// UnixMasquerade detects files named like system daemons but located elsewhere.
func UnixMasquerade(p string) *core.Reason {
	name := path.Base(p)
	dirs, ok := unixDaemons[name]
	if !ok {
		return nil
	}
	for _, d := range dirs {
		if strings.HasPrefix(p, d) {
			return nil
		}
	}
	if ClassifyUnixPath(p).Category == "managed" {
		return nil
	}
	return &core.Reason{Severity: core.Critical, Text: "nombre de demonio del sistema (" + name + ") fuera de su ubicación habitual", MITRE: []string{"T1036.005"}}
}

var unixRules = []cmdRule{
	rule(`/dev/(tcp|udp)/`, core.Critical, "redirección a /dev/tcp (reverse shell típica de bash)", "T1059.004"),
	rule(`\b(nc|ncat|netcat|nc\.traditional|nc\.openbsd)\b.*\s-(e|c)\s`, core.Critical, "netcat ejecutando un intérprete (reverse/bind shell)", "T1059.004"),
	rule(`mkfifo\b.*\b(nc|ncat|netcat|openssl)\b`, core.Critical, "named pipe + netcat/openssl (reverse shell)", "T1059.004"),
	rule(`\bsocat\b.*exec:`, core.High, "socat ejecutando comandos (posible shell remota)", "T1059.004"),
	rule(`(python[0-9.]*|perl|ruby|php)\b.*\s-(c|e|r)\s.*socket`, core.High, "intérprete abriendo sockets desde código en línea (posible reverse shell)", "T1059.006"),
	rule(`\b(curl|wget|fetch)\b[^|;&]*https?://[^|;&]*\|\s*(sudo\s+)?(ba|da|z|k)?sh\b`, core.High, "descarga y ejecución directa (curl|sh)", "T1105", "T1059.004"),
	rule(`base64\s+(-d|--decode)[^|]*\|\s*(ba|da|z)?sh\b`, core.High, "decodifica Base64 y lo ejecuta en una shell", "T1027", "T1140"),
	rule(`\b(xmrig|xmr-stak|minerd|cpuminer|kdevtmpfsi|kinsing|cryptonight|nicehash)\b|stratum\+(tcp|ssl)://|--donate-level`, core.Critical, "minero de criptomonedas", "T1496"),
	rule(`\bLD_PRELOAD=`, core.High, "uso de LD_PRELOAD para inyectar bibliotecas", "T1574.006"),
	rule(`\bsetenforce\s+0\b|systemctl\s+(stop|disable|mask)\s+(apparmor|auditd|firewalld|ufw|falcon|wazuh|osquery)|\bufw\s+disable\b|iptables\s+-F\b`, core.High, "desactivación de controles de seguridad", "T1562.001"),
	rule(`unset\s+HISTFILE|HISTFILE=/dev/null|history\s+-c\b|HISTSIZE=0`, core.Medium, "borrado o desactivación del historial de comandos", "T1070.003"),
	rule(`(rm|shred)\s+(-[a-z]+\s+)*/var/log/|>\s*/var/log/(wtmp|btmp|lastlog|auth\.log|secure|syslog)`, core.High, "borrado de registros del sistema", "T1070.002"),
	rule(`>>?\s*\S*\.ssh/authorized_keys`, core.High, "añade claves SSH autorizadas", "T1098.004"),
	rule(`\b(useradd|usermod)\b.*(-o\b.*-u\s*0|-u\s*0\b.*-o\b)`, core.High, "crea un usuario con UID 0", "T1136.001"),
	rule(`chmod\s+(\+x|[0-7]*[1357][0-7]{0,2}|u\+s|[2467][0-7]{3})\s+/(tmp|dev/shm|var/tmp)/`, core.High, "da permisos de ejecución a ficheros en directorios temporales", "T1222.002"),
	rule(`(^|[;&|]\s*|\b(sh|bash|dash|nohup|exec|setsid|source|python[0-9.]*|perl)\s+|\.\s+)/(dev/shm|tmp|var/tmp)/\S+`, core.High, "ejecuta ficheros desde directorios temporales", "T1059.004"),
	rule(`https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`, core.High, "URL apuntando directamente a una dirección IP", "T1105"),
	rule(`\b(curl|wget)\b.*https?://`, core.Medium, "descarga de ficheros desde Internet", "T1105"),
	rule(`[A-Za-z0-9+/]{200,}={0,2}`, core.Medium, "cadena larga tipo Base64", "T1027"),
}

// AssessUnixCommand applies Linux/Unix command-line heuristics (reverse shells, droppers, miners...).
func AssessUnixCommand(cmd string) []core.Reason {
	var out []core.Reason
	seen := map[string]bool{}
	for _, r := range unixRules {
		if !r.re.MatchString(cmd) {
			continue
		}
		// Generic download/IP rules are redundant when a stronger downloader rule matched.
		if r.text == "descarga de ficheros desde Internet" && (seen["descarga y ejecución directa (curl|sh)"] || seen["URL apuntando directamente a una dirección IP"]) {
			continue
		}
		seen[r.text] = true
		out = append(out, core.Reason{Severity: r.sev, Text: r.text, MITRE: r.mitre})
	}
	return out
}

var shellRe = regexp.MustCompile(`^(ba|da|z|k|c|tc|fi)?sh$|^(python[0-9.]*|perl|ruby|php[0-9.]*|nc|ncat|netcat|socat|curl|wget)$`)
var webServers = map[string]bool{"apache2": true, "httpd": true, "nginx": true, "lighttpd": true, "caddy": true, "tomcat": true, "catalina": true, "w3wp": true}

// UnixParentChild flags web servers spawning shells/interpreters (webshells).
func UnixParentChild(parent, child string) *core.Reason {
	if (webServers[parent] || strings.HasPrefix(parent, "php-fpm")) && shellRe.MatchString(child) {
		return &core.Reason{Severity: core.High, Text: "servidor web " + parent + " lanzó " + child + " (posible webshell)", MITRE: []string{"T1505.003"}}
	}
	return nil
}

// IsShell reports whether a process name is an interactive shell.
func IsShell(name string) bool {
	switch name {
	case "sh", "bash", "dash", "zsh", "ksh", "csh", "tcsh", "fish", "ash", "busybox":
		return true
	}
	return false
}

// standardSUID lists setuid/setgid binaries shipped by mainstream distributions.
var standardSUID = map[string]bool{
	"passwd": true, "sudo": true, "su": true, "mount": true, "umount": true, "chsh": true, "chfn": true, "newgrp": true,
	"gpasswd": true, "pkexec": true, "ping": true, "ping6": true, "fusermount": true, "fusermount3": true, "ssh-keysign": true,
	"dbus-daemon-launch-helper": true, "polkit-agent-helper-1": true, "Xorg.wrap": true, "chrome-sandbox": true,
	"snap-confine": true, "unix_chkpwd": true, "pam_timestamp_check": true, "crontab": true, "at": true, "expiry": true,
	"chage": true, "wall": true, "write": true, "ssh-agent": true, "dotlockfile": true, "mount.nfs": true, "mount.cifs": true,
	"ntfs-3g": true, "pppd": true, "vmware-user-suid-wrapper": true, "VBoxHeadless": true, "VBoxNetAdpCtl": true,
	"VBoxNetDHCP": true, "VBoxNetNAT": true, "VBoxSDL": true, "VirtualBoxVM": true, "Xorg": true, "staprun": true,
	"traceroute6.iputils": true, "newuidmap": true, "newgidmap": true, "sg": true, "doas": true, "mlocate": true, "plocate": true,
	"locate": true, "bsd-write": true, "utempter": true, "kismet_cap_linux_wifi": true, "kismet_cap_linux_bluetooth": true,
	"kismet_cap_nrf_mousejack": true, "kismet_cap_ti_cc_2540": true, "kismet_cap_ti_cc_2531": true, "kismet_cap_nxp_kw41z": true,
	"kismet_cap_rz_killerbee": true, "kismet_cap_nrf_51822": true, "kismet_cap_nrf_52840": true, "kismet_cap_ubertooth_one": true,
	"kismet_cap_hak5_wifi_coconut": true, "kismet_cap_linux_bluetooth_btle": true, "Xvnc": true, "procmail": true, "lockfile": true,
	"mail-lock": true, "mail-unlock": true, "mail-touchlock": true, "camel-lock-helper-1.2": true,
	"exim4": true, "sendmail": true, "postdrop": true, "postqueue": true, "dumpcap": true, "spice-client-glib-usb-acl-helper": true,
	"cdrecord": true, "ksu": true, "nvidia-modprobe": true, "userhelper": true, "usernetctl": true, "mount.ecryptfs_private": true,
	"lxc-user-nic": true, "qemu-bridge-helper": true, "rsh-redone-rsh": true, "rsh-redone-rlogin": true, "ssh-askpass": true,
}

// gtfoSUID lists binaries that give a root shell when setuid (GTFOBins).
var gtfoSUID = map[string]bool{
	"bash": true, "sh": true, "dash": true, "zsh": true, "ksh": true, "csh": true, "tcsh": true, "fish": true, "busybox": true,
	"find": true, "vim": true, "vim.basic": true, "vi": true, "nano": true, "less": true, "more": true, "env": true, "awk": true,
	"gawk": true, "mawk": true, "python": true, "python2": true, "python3": true, "perl": true, "ruby": true, "php": true, "lua": true,
	"nmap": true, "cp": true, "mv": true, "tar": true, "zip": true, "rsync": true, "nc": true, "ncat": true, "socat": true, "tee": true,
	"dd": true, "docker": true, "node": true, "gdb": true, "strace": true, "make": true, "git": true, "ed": true, "expect": true,
	"taskset": true, "nice": true, "time": true, "timeout": true, "xargs": true, "systemctl": true, "openssl": true, "base64": true,
	"chmod": true, "chown": true, "install": true, "ld.so": true, "watch": true, "flock": true, "ionice": true, "stdbuf": true,
}

type SUIDVerdict struct {
	Severity core.Severity
	Text     string
}

// AssessSUID evaluates a setuid/setgid file. packaged is nil when the package DB is unavailable.
func AssessSUID(p string, setuid bool, packaged *bool) *SUIDVerdict {
	name := path.Base(p)
	bit := "setgid"
	if setuid {
		bit = "setuid"
	}
	loc := ClassifyUnixPath(p)
	switch {
	case loc.Severity >= core.Medium || loc.Category == "home":
		return &SUIDVerdict{core.Critical, "binario " + bit + " en " + loc.Label}
	case gtfoSUID[name] && setuid:
		return &SUIDVerdict{core.Critical, name + " con bit setuid permite obtener una shell de root (GTFOBins)"}
	case gtfoSUID[name]:
		return &SUIDVerdict{core.High, name + " con bit setgid (GTFOBins)"}
	case standardSUID[name]:
		return nil
	case packaged != nil && !*packaged && IsUnixSystemPath(p):
		return &SUIDVerdict{core.High, "binario " + bit + " no estándar que no pertenece a ningún paquete"}
	case packaged != nil && *packaged:
		return nil
	case loc.Category == "local":
		return &SUIDVerdict{core.Medium, "binario " + bit + " no estándar en " + loc.Label}
	}
	return &SUIDVerdict{core.Low, "binario " + bit + " no estándar"}
}

// UnixExe describes an executable referenced by a Linux persistence entry or process.
type UnixExe struct {
	Path        string
	Exists      bool
	PkgKnown    bool   // package database available
	Owner       string // owning package ("" if none)
	CommandLine string
	// Vendor is true when the entry itself (unit file, cron file...) belongs to a package.
	Vendor bool
}

var inlineInterp = regexp.MustCompile(`(^|/)(ba|da|z)?sh\s+-c\s|(^|/)(python[0-9.]*|perl|ruby)\s+-(c|e)\s`)

// AssessUnixExecutable applies Linux location, ownership, naming and command-line heuristics.
func AssessUnixExecutable(e UnixExe) []core.Reason {
	var out []core.Reason
	if e.Path != "" && strings.HasPrefix(e.Path, "/") {
		loc := ClassifyUnixPath(e.Path)
		if !e.Exists {
			sev := core.Low
			if loc.Severity >= core.Medium {
				sev = core.Medium
			}
			out = append(out, core.Reason{Severity: sev, Text: "el ejecutable referenciado no existe"})
		}
		managed := e.Vendor || e.Owner != ""
		if loc.Severity >= core.Low && (!managed || loc.Severity >= core.High) {
			text := "ubicado en " + loc.Label
			if loc.RootDrop {
				text += " (directamente en la raíz)"
			}
			out = append(out, core.Reason{Severity: loc.Severity, Text: text, MITRE: []string{"T1074.001"}})
		}
		if r := UnixMasquerade(e.Path); r != nil && e.Owner == "" {
			out = append(out, *r)
		}
		if strings.HasPrefix(path.Base(e.Path), ".") && !managed {
			out = append(out, core.Reason{Severity: core.Medium, Text: "ejecutable con nombre oculto", MITRE: []string{"T1564.001"}})
		}
		if e.Exists && e.PkgKnown && e.Owner == "" && IsUnixSystemPath(e.Path) {
			sev := core.Medium
			if IsUnixBinDir(e.Path) {
				sev = core.High
			}
			out = append(out, core.Reason{Severity: sev, Text: "binario en un directorio del sistema que no pertenece a ningún paquete", MITRE: []string{"T1036.005"}})
		}
	}
	if e.CommandLine != "" {
		out = append(out, AssessUnixCommand(e.CommandLine)...)
		if !e.Vendor && inlineInterp.MatchString(e.CommandLine) {
			out = append(out, core.Reason{Severity: core.Low, Text: "lanza un intérprete con código en línea", MITRE: []string{"T1059.004"}})
		}
	}
	return out
}

// SplitUnixCommand returns the executable of a shell-like command line (first token, quotes removed).
func SplitUnixCommand(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return ""
	}
	if cmd[0] == '"' || cmd[0] == '\'' {
		if end := strings.IndexByte(cmd[1:], cmd[0]); end >= 0 {
			return cmd[1 : end+1]
		}
	}
	// Skip leading environment assignments (FOO=bar cmd ...) and common wrappers.
	fields := strings.Fields(cmd)
	for i, f := range fields {
		if strings.Contains(f, "=") && !strings.HasPrefix(f, "/") {
			continue
		}
		switch path.Base(f) {
		case "env", "nohup", "nice", "ionice", "exec", "sudo", "setsid", "flock":
			if i+1 < len(fields) {
				continue
			}
		}
		if strings.HasPrefix(f, "-") {
			continue
		}
		return f
	}
	return fields[0]
}

var benignPreload = regexp.MustCompile(`^(libmozsandbox\.so|libgtk3-nocsd\.so(\.\d+)?|libjemalloc\.so(\.\d+)?|libtcmalloc.*|libasan\.so.*|libstdbuf\.so|libvglfaker.*|libdlfaker.*|libnvidia.*|libVkLayer.*|libgamemodeauto\.so.*|libmangohud.*|libsandbox\.so|libtrash\.so)$`)

// AssessPreload evaluates an LD_PRELOAD value (several libraries may be separated by ':' or spaces).
func AssessPreload(v string) []core.Reason {
	var out []core.Reason
	for _, lib := range strings.FieldsFunc(v, func(r rune) bool { return r == ':' || r == ' ' }) {
		switch {
		case benignPreload.MatchString(path.Base(lib)) && (!strings.Contains(lib, "/") || IsUnixSystemPath(lib)):
		case !strings.Contains(lib, "/"):
			out = append(out, core.Reason{Severity: core.Low, Text: "LD_PRELOAD=" + lib, MITRE: []string{"T1574.006"}})
		case IsUnixSystemPath(lib):
			out = append(out, core.Reason{Severity: core.Medium, Text: "LD_PRELOAD=" + lib, MITRE: []string{"T1574.006"}})
		default:
			out = append(out, core.Reason{Severity: core.High, Text: "LD_PRELOAD con biblioteca fuera del sistema: " + lib, MITRE: []string{"T1574.006"}})
		}
	}
	return out
}
