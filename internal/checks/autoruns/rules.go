// Package autoruns inspects classic Windows persistence locations
// (Run keys, Startup folders, Winlogon, IFEO, AppInit_DLLs...).
package autoruns

import (
	"strings"

	"husmea/internal/checks/checkutil"
	"husmea/internal/core"
	"husmea/internal/heuristics"
)

const Name = "autoruns"

type kind int

const (
	kindRun kind = iota
	kindStartupFolder
	kindWinlogon
	kindIFEO
	kindSilentExit
	kindAppInit
	kindCmdAutoRun
	kindLogonScript
	kindBootExecute
)

type entry struct {
	Kind     kind
	Location string // registry key or folder
	Name     string // value name or file name
	Command  string // raw command / value data
	Launch   heuristics.Launch
}

var kindMeta = map[kind]struct {
	label string
	mitre string
	sev   core.Severity // baseline severity just for existing (0 = inventory only)
}{
	kindRun:           {"Clave Run del registro", "T1547.001", core.Info},
	kindStartupFolder: {"Carpeta de Inicio", "T1547.001", core.Info},
	kindWinlogon:      {"Winlogon modificado", "T1547.004", core.High},
	kindIFEO:          {"Image File Execution Options (Debugger)", "T1546.012", core.High},
	kindSilentExit:    {"SilentProcessExit (MonitorProcess)", "T1546.012", core.High},
	kindAppInit:       {"AppInit_DLLs activo", "T1546.010", core.High},
	kindCmdAutoRun:    {"AutoRun de cmd.exe", "T1546", core.High},
	kindLogonScript:   {"Script de inicio de sesión (UserInitMprLogonScript)", "T1037.001", core.High},
	kindBootExecute:   {"BootExecute modificado", "T1547.001", core.High},
}

// Known-good defaults for values that should normally not be changed.
func winlogonExpected(name, value string) bool {
	v := strings.ToLower(strings.TrimSpace(value))
	switch strings.ToLower(name) {
	case "shell":
		return v == "explorer.exe" || v == `c:\windows\explorer.exe`
	case "userinit":
		v = strings.TrimSuffix(v, ",")
		return v == `c:\windows\system32\userinit.exe` || v == "userinit.exe"
	}
	return true
}

func bootExecuteExpected(value string) bool {
	v := strings.ToLower(strings.Join(strings.Fields(value), " "))
	return v == "" || v == "autocheck autochk *"
}

// ifeoBenign lists debuggers set by legitimate tooling.
func ifeoBenign(cmd string) bool {
	c := strings.ToLower(cmd)
	return strings.Contains(c, "vsjitdebugger.exe") || strings.Contains(c, `\windows kits\`) || strings.Contains(c, "procexp")
}

func assess(e entry) *core.Finding {
	meta := kindMeta[e.Kind]
	var extra []core.Reason
	switch e.Kind {
	case kindWinlogon:
		if winlogonExpected(e.Name, e.Command) {
			return nil
		}
		extra = append(extra, core.Reason{Severity: core.High, Text: "valor " + e.Name + " de Winlogon distinto del predeterminado", MITRE: []string{meta.mitre}})
	case kindBootExecute:
		if bootExecuteExpected(e.Command) {
			return nil
		}
		extra = append(extra, core.Reason{Severity: core.High, Text: "BootExecute contiene entradas adicionales a 'autocheck autochk *'", MITRE: []string{meta.mitre}})
	case kindIFEO:
		sev := core.High
		if ifeoBenign(e.Command) {
			sev = core.Low
		}
		extra = append(extra, core.Reason{Severity: sev, Text: "depurador asignado a " + e.Name + ": se ejecutará en su lugar cada vez que se lance", MITRE: []string{meta.mitre}})
	case kindSilentExit, kindAppInit, kindCmdAutoRun, kindLogonScript:
		extra = append(extra, core.Reason{Severity: meta.sev, Text: meta.label, MITRE: []string{meta.mitre}})
	case kindRun, kindStartupFolder:
		if heuristics.IsScript(e.Launch.Exe.Path) {
			extra = append(extra, core.Reason{Severity: core.Medium, Text: "script ejecutado al iniciar sesión", MITRE: []string{"T1059"}})
		}
	}

	ev := map[string]string{"ubicación": e.Location, "nombre": e.Name, "comando": e.Command}
	title := meta.label + ": " + e.Name
	f := checkutil.LaunchFinding(title, e.Launch, extra, ev, core.Low, checkutil.RecPersistence)
	if f != nil {
		f.MITRE = appendUnique(f.MITRE, meta.mitre)
		return f
	}
	// Inventory: report everything that runs at logon as info so the HTML report lists it.
	inv := &core.Finding{
		Severity:       core.Info,
		Title:          "Programa de inicio: " + e.Name,
		Path:           e.Launch.Exe.Path,
		Evidence:       ev,
		MITRE:          []string{meta.mitre},
		Recommendation: "Elemento de inicio sin indicadores sospechosos. Desactívelo desde el Administrador de tareas > Inicio si no lo necesita.",
	}
	if e.Launch.Exe.Sig.Valid() {
		inv.Signer = e.Launch.Exe.Sig.SignerName()
	}
	return inv
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}
