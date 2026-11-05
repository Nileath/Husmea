// Package services inspects Windows services and drivers for suspicious binaries.
package services

import (
	"strconv"
	"strings"

	"husmea/internal/checks/checkutil"
	"husmea/internal/core"
	"husmea/internal/heuristics"
)

const Name = "services"

type serviceInfo struct {
	Name        string
	DisplayName string
	ImagePath   string
	Account     string
	Type        uint64
	Start       uint64
}

func (s serviceInfo) isDriver() bool { return s.Type&0x3 != 0 }

func startName(v uint64) string {
	switch v {
	case 0:
		return "boot"
	case 1:
		return "system"
	case 2:
		return "automático"
	case 3:
		return "manual"
	case 4:
		return "deshabilitado"
	}
	return strconv.FormatUint(v, 10)
}

// assess evaluates one service. l.Payload carries the ServiceDll for svchost-hosted services.
func assess(s serviceInfo, l heuristics.Launch) *core.Finding {
	var extra []core.Reason
	exe := heuristics.Norm(l.Exe.Path)
	base := heuristics.BaseName(exe)

	if s.isDriver() && l.Exe.Path != "" && !strings.Contains(exe, `\windows\system32\drivers\`) &&
		!strings.Contains(exe, `\windows\system32\driverstore\`) {
		sev := core.Medium
		if !heuristics.IsTrustedLocation(l.Exe.Path) {
			sev = core.High
		}
		extra = append(extra, core.Reason{Severity: sev, Text: "controlador de kernel fuera de System32\\drivers", MITRE: []string{"T1543.003", "T1014"}})
	}
	if s.isDriver() && l.Exe.Exists && l.Exe.Sig.Known() && !l.Exe.Sig.Valid() {
		extra = append(extra, core.Reason{Severity: core.High, Text: "controlador de kernel sin firma válida", MITRE: []string{"T1014", "T1553.002"}})
	}
	if l.Exe.Path != "" && heuristics.ParseCommandLine(l.Exe.CommandLine, nil).UnquotedSpaces && !heuristics.IsWindowsDir(l.Exe.Path) {
		extra = append(extra, core.Reason{Severity: core.Medium, Text: "ruta del servicio con espacios y sin comillas (Unquoted Service Path)", MITRE: []string{"T1574.009"}})
	}
	if base == "svchost.exe" && l.Payload != nil && l.Payload.Path != "" && !heuristics.IsSystem32(l.Payload.Path) {
		extra = append(extra, core.Reason{Severity: core.High, Text: "ServiceDll de svchost fuera de System32", MITRE: []string{"T1543.003", "T1574"}})
	}

	ev := map[string]string{
		"servicio": s.Name,
		"nombre":   s.DisplayName,
		"comando":  s.ImagePath,
		"inicio":   startName(s.Start),
		"cuenta":   s.Account,
	}
	if s.isDriver() {
		ev["tipo"] = "controlador"
	}
	kind := "Servicio"
	if s.isDriver() {
		kind = "Controlador"
	}
	f := checkutil.LaunchFinding(kind+" sospechoso: "+s.Name, l, extra, ev, core.Low,
		"Revise el servicio con 'sc qc "+s.Name+"' y services.msc. Si no lo reconoce: deténgalo ('sc stop "+s.Name+
			"'), cambie el inicio a deshabilitado ('sc config "+s.Name+" start= disabled') y analice el binario antes de eliminarlo. "+
			checkutil.RecUnsigned)
	if f == nil {
		return nil
	}
	if s.Start == 4 && f.Severity > core.Low {
		f.Severity--
		f.Reasons = append(f.Reasons, "(severidad reducida: el servicio está deshabilitado)")
	}
	if f.Severity == core.Low && strings.HasPrefix(f.Reasons[0], "[BAJO] el ejecutable referenciado no existe") && len(f.Reasons) == 1 {
		f.Title = kind + " huérfano (binario inexistente): " + s.Name
		f.Recommendation = "El servicio apunta a un fichero que ya no existe (restos de software desinstalado o de malware eliminado). " +
			"Si no lo reconoce, elimínelo con 'sc delete " + s.Name + "' como administrador."
	}
	return f
}
