package heuristics

import (
	"husmea/internal/core"
)

// ExeRef describes an executable referenced by some persistence or runtime artifact.
type ExeRef struct {
	Path        string
	Exists      bool
	Sig         core.Signature
	CommandLine string
}

var highRiskCategories = map[string]bool{"recycle": true, "temp": true, "inetcache": true, "sysmisc": true, "perflogs": true, "public": true, "default": true}

// AssessExecutable applies location, naming, signature and command-line heuristics.
func AssessExecutable(ref ExeRef) []core.Reason {
	var out []core.Reason
	if ref.Path != "" {
		loc := ClassifyPath(ref.Path)
		if !ref.Exists {
			sev := core.Low
			if loc.Severity >= core.Medium {
				sev = core.Medium
			}
			out = append(out, core.Reason{Severity: sev, Text: "el ejecutable referenciado no existe (entrada huérfana o fichero eliminado)"})
		}
		// Validly signed software installed per-user (OneDrive, Teams, Defender platform...)
		// is normal; only high-risk folders or root drops stay suspicious when signed.
		signedBenign := ref.Sig.Valid() && !highRiskCategories[loc.Category] && !loc.RootDrop
		if loc.Severity >= core.Low && !signedBenign {
			sev := loc.Severity
			text := "ubicado en " + loc.Label
			if loc.RootDrop {
				text += " (directamente en la raíz de la carpeta)"
			}
			out = append(out, core.Reason{Severity: sev, Text: text, MITRE: []string{"T1074.001"}})
		}
		if r := Masquerade(ref.Path); r != nil {
			out = append(out, *r)
		}
		if r := DoubleExtension(ref.Path); r != nil {
			out = append(out, *r)
		}
		if ref.Exists && ref.Sig.Known() && IsPE(ref.Path) {
			switch ref.Sig.Status {
			case "Valid":
			case "NotSigned":
				sev := core.Medium
				if IsTrustedLocation(ref.Path) {
					sev = core.Low
				}
				out = append(out, core.Reason{Severity: sev, Text: "binario sin firma digital", MITRE: []string{"T1553.002"}})
			case "HashMismatch":
				out = append(out, core.Reason{Severity: core.High, Text: "la firma digital no coincide con el contenido (fichero modificado)", MITRE: []string{"T1553.002"}})
			default:
				out = append(out, core.Reason{Severity: core.Medium, Text: "firma digital no válida o no confiable (" + ref.Sig.Status + ")", MITRE: []string{"T1553.002"}})
			}
		}
	}
	if ref.CommandLine != "" {
		out = append(out, AssessCommandLine(ref.CommandLine)...)
	}
	return out
}

// MaxSeverity returns the highest severity among reasons.
func MaxSeverity(rs []core.Reason) core.Severity {
	var m core.Severity
	for _, r := range rs {
		if r.Severity > m {
			m = r.Severity
		}
	}
	return m
}

var interpreters = map[string]bool{"cmd.exe": true, "powershell.exe": true, "pwsh.exe": true, "wscript.exe": true, "cscript.exe": true, "mshta.exe": true, "rundll32.exe": true, "regsvr32.exe": true}

// Launch is a persistence entry that starts Exe (with its CommandLine) and optionally a Payload.
type Launch struct {
	Exe     ExeRef
	Payload *ExeRef
	// Vendor is true for entries registered by the OS vendor (e.g. \Microsoft\ tasks),
	// where launching system interpreters is routine and not suspicious by itself.
	Vendor bool
}

// AssessLaunch evaluates a persistence command (service, Run key, task...).
func AssessLaunch(l Launch) []core.Reason {
	out := AssessExecutable(l.Exe)
	if base := BaseName(Norm(l.Exe.Path)); interpreters[base] && !l.Vendor {
		sev := core.Medium
		if (base == "rundll32.exe" || base == "regsvr32.exe") && l.Payload != nil && IsTrustedLocation(l.Payload.Path) && (l.Payload.Sig.Valid() || !l.Payload.Sig.Known()) {
			sev = core.Low
		}
		out = append(out, core.Reason{Severity: sev, Text: "la persistencia lanza un intérprete/proxy (" + base + ")", MITRE: []string{"T1059", "T1218"}})
	}
	if l.Payload != nil && l.Payload.Path != "" {
		for _, r := range AssessExecutable(ExeRef{Path: l.Payload.Path, Exists: l.Payload.Exists, Sig: l.Payload.Sig}) {
			r.Text = "carga útil " + BaseName(l.Payload.Path) + ": " + r.Text
			out = append(out, r)
		}
	}
	return out
}
