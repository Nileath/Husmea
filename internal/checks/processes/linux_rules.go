package processes

import (
	"path"
	"strconv"
	"strings"

	"husmea/internal/core"
	"husmea/internal/heuristics"
)

// lproc is a Linux process as read from /proc.
type lproc struct {
	PID, PPID  int
	UID        int
	Comm       string
	Argv0      string
	Cmdline    string
	Exe        string // "" when unreadable (kernel thread or permission denied)
	Deleted    bool
	ParentComm string
	ForeignNS  bool // runs in another mount namespace (container)
	StdSocket  bool // stdin/stdout is a network socket
	LDPreload  string
	// Replaced is true when a deleted image has been replaced by a new file at the same path (package upgrade).
	Replaced bool
}

func assessLinux(p lproc, pkgKnown bool, owner string) *core.Finding {
	var reasons []core.Reason
	// Kernel threads have no executable; a user process whose argv[0] looks like "[kworker/0:1]" is hiding.
	if a := strings.TrimSpace(p.Argv0); strings.HasPrefix(a, "[") && strings.HasSuffix(a, "]") && p.Exe != "" {
		reasons = append(reasons, core.Reason{Severity: core.Critical, Text: "proceso de usuario disfrazado de hilo del kernel (" + a + ")", MITRE: []string{"T1036.004"}})
	}
	if p.Exe != "" {
		switch {
		case p.Deleted && p.Replaced && heuristics.IsUnixSystemPath(p.Exe):
			// Normal after package upgrades until the process restarts: not suspicious by itself.
		case p.Deleted:
			reasons = append(reasons, core.Reason{Severity: core.High, Text: "el ejecutable del proceso fue borrado del disco tras lanzarse", MITRE: []string{"T1070.004"}})
		}
		e := heuristics.UnixExe{Path: p.Exe, Exists: true}
		if !p.ForeignNS && !p.Deleted {
			e.PkgKnown, e.Owner = pkgKnown, owner
		}
		if p.ForeignNS {
			e.Path = "" // paths inside containers are not comparable with the host
		}
		reasons = append(reasons, heuristics.AssessUnixExecutable(e)...)
		if dirs := daemonName(p.Comm); dirs && path.Base(p.Exe) != p.Comm && !p.ForeignNS {
			reasons = append(reasons, core.Reason{Severity: core.Critical, Text: "el proceso se hace llamar '" + p.Comm + "' pero su ejecutable es " + p.Exe, MITRE: []string{"T1036.005"}})
		}
	}
	reasons = append(reasons, heuristics.AssessUnixCommand(p.Cmdline)...)
	if p.StdSocket && heuristics.IsShell(p.Comm) {
		reasons = append(reasons, core.Reason{Severity: core.Critical, Text: "shell con la entrada/salida conectada a un socket de red (reverse/bind shell)", MITRE: []string{"T1059.004", "T1571"}})
	}
	if p.LDPreload != "" {
		reasons = append(reasons, heuristics.AssessPreload(p.LDPreload)...)
	}
	if r := heuristics.UnixParentChild(p.ParentComm, p.Comm); r != nil {
		reasons = append(reasons, *r)
	}
	if len(reasons) == 0 {
		return nil
	}
	sev, texts, mitre := core.Combine(reasons)
	if sev < core.Low {
		return nil
	}
	pid := strconv.Itoa(p.PID)
	ev := map[string]string{
		"pid":     pid,
		"proceso": p.Comm,
		"padre":   p.ParentComm + " (" + strconv.Itoa(p.PPID) + ")",
		"uid":     strconv.Itoa(p.UID),
		"comando": p.Cmdline,
	}
	if owner != "" {
		ev["paquete"] = owner
	}
	if p.ForeignNS {
		ev["contenedor"] = "sí (otro espacio de nombres de montaje)"
	}
	return &core.Finding{
		Severity: sev,
		Title:    "Proceso sospechoso: " + p.Comm + " (PID " + pid + ")",
		Path:     p.Exe,
		Evidence: ev,
		Reasons:  texts,
		MITRE:    mitre,
		Recommendation: "Inspeccione el proceso ('ls -l /proc/" + pid + "/exe', 'cat /proc/" + pid + "/cmdline | tr \\\\0 \" \"', 'ss -tunap | grep " + pid + "'). " +
			"Si el binario fue borrado, puede recuperarlo para analizarlo con 'cp /proc/" + pid + "/exe /root/muestra.bin'. " +
			"Si no lo reconoce, aísle el equipo de la red, finalice el proceso ('kill -9 " + pid + "') y localice su persistencia (revise los demás hallazgos).",
	}
}

func daemonName(comm string) bool {
	switch comm {
	case "sshd", "systemd", "cron", "crond", "dbus-daemon", "rsyslogd", "auditd", "agetty", "polkitd":
		return true
	}
	return false
}
