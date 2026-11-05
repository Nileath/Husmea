// Package paths looks for executables and scripts dropped in folders commonly abused by malware.
package paths

import (
	"fmt"
	"time"

	"husmea/internal/core"
	"husmea/internal/heuristics"
)

const Name = "paths"

type fileEntry struct {
	Path    string
	Depth   int // 1 = directly inside the scanned root
	Size    int64
	ModTime time.Time
}

var wshExts = map[string]bool{".vbs": true, ".vbe": true, ".jse": true, ".wsf": true, ".wsh": true, ".hta": true}
var shellScriptExts = map[string]bool{".ps1": true, ".psm1": true, ".bat": true, ".cmd": true}
var libExts = map[string]bool{".dll": true, ".sys": true, ".cpl": true, ".ocx": true, ".drv": true}

// interesting reports whether a file is worth inspecting at the given depth.
func interesting(path string, depth int) bool {
	e := heuristics.Ext(path)
	switch {
	case heuristics.IsPE(path), wshExts[e], shellScriptExts[e], e == ".jar", e == ".lnk", e == ".msi":
		return true
	case e == ".js":
		return depth <= 2
	}
	return heuristics.DoubleExtension(path) != nil
}

func lower(s core.Severity) core.Severity {
	if s > core.Low {
		return s - 1
	}
	return core.Low
}

// assess returns a finding for a suspicious file, or nil.
func assess(fe fileEntry, sig core.Signature, now time.Time) *core.Finding {
	var reasons []core.Reason
	if r := heuristics.Masquerade(fe.Path); r != nil {
		reasons = append(reasons, *r)
	}
	if r := heuristics.DoubleExtension(fe.Path); r != nil {
		reasons = append(reasons, *r)
	}
	loc := heuristics.ClassifyPath(fe.Path)
	e := heuristics.Ext(fe.Path)
	where := loc.Label
	if loc.RootDrop {
		where += " (raíz de la carpeta)"
	}

	switch {
	case heuristics.IsPE(fe.Path):
		if sig.Valid() {
			break
		}
		sev := loc.Severity
		if sev < core.Low {
			sev = core.Low
		}
		if libExts[e] && !loc.RootDrop {
			sev = lower(sev)
		}
		if loc.Category == "downloads" || loc.Category == "desktop" || (loc.Category == "temp" && !loc.RootDrop) {
			sev = lower(sev)
		}
		switch sig.Status {
		case "HashMismatch":
			reasons = append(reasons, core.Reason{Severity: core.High, Text: "firma digital alterada (el fichero fue modificado)", MITRE: []string{"T1553.002"}})
		case "NotSigned":
			reasons = append(reasons, core.Reason{Severity: sev, Text: "binario sin firma en " + where, MITRE: []string{"T1074.001", "T1553.002"}})
		case "", "Unknown":
			reasons = append(reasons, core.Reason{Severity: lower(sev), Text: "binario en " + where + " (firma no verificada)", MITRE: []string{"T1074.001"}})
		default:
			reasons = append(reasons, core.Reason{Severity: sev, Text: "binario con firma no válida (" + sig.Status + ") en " + where, MITRE: []string{"T1553.002"}})
		}
	case wshExts[e] || e == ".js":
		sev := core.Medium
		if loc.Severity >= core.High || loc.Category == "startup" {
			sev = core.High
		}
		reasons = append(reasons, core.Reason{Severity: sev, Text: "script de Windows Script Host (" + e + ") en " + where, MITRE: []string{"T1059.005", "T1059.007"}})
	case shellScriptExts[e]:
		switch {
		case loc.Category == "public" || loc.Category == "recycle" || loc.Category == "sysmisc" || loc.Category == "perflogs" || loc.Category == "startup":
			reasons = append(reasons, core.Reason{Severity: core.Medium, Text: "script (" + e + ") en " + where, MITRE: []string{"T1059"}})
		case fe.Depth <= 1 && loc.Severity >= core.Medium:
			reasons = append(reasons, core.Reason{Severity: core.Low, Text: "script (" + e + ") en " + where, MITRE: []string{"T1059"}})
		}
	case e == ".jar" && loc.Severity >= core.Medium:
		reasons = append(reasons, core.Reason{Severity: core.Medium, Text: "fichero Java (.jar) en " + where, MITRE: []string{"T1059"}})
	}

	if len(reasons) == 0 {
		return nil
	}
	sev, texts, mitre := core.Combine(reasons)
	if sev < core.Low {
		return nil
	}
	ev := map[string]string{
		"tamaño":     humanSize(fe.Size),
		"modificado": fe.ModTime.Format("2006-01-02 15:04"),
		"ubicación":  loc.Label,
	}
	if sig.Known() {
		ev["firma"] = sig.Status
	}
	if !fe.ModTime.IsZero() && now.Sub(fe.ModTime) < 7*24*time.Hour {
		ev["reciente"] = "modificado en los últimos 7 días"
	}
	f := &core.Finding{
		Severity: sev,
		Title:    "Fichero sospechoso: " + heuristics.BaseName(fe.Path),
		Path:     fe.Path,
		Evidence: ev,
		Reasons:  texts,
		MITRE:    mitre,
		Recommendation: "Compruebe si reconoce el fichero y de dónde procede. Súbalo/consulte su hash en VirusTotal o analícelo con su antivirus. " +
			"Si es malicioso, no lo ejecute: elimínelo o póngalo en cuarentena con su antivirus y revise también las entradas de persistencia que lo referencien.",
	}
	if sig.Valid() {
		f.Signer = sig.SignerName()
	}
	return f
}

func humanSize(n int64) string {
	units := []string{"B", "KB", "MB", "GB"}
	f := float64(n)
	i := 0
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d B", n)
	}
	return fmt.Sprintf("%.1f %s", f, units[i])
}
