package heuristics

import (
	"strings"

	"husmea/internal/core"
)

// systemBinaries maps well-known Windows process names to their legitimate directories.
var systemBinaries = map[string][]string{
	"svchost.exe":       {`\windows\system32\`, `\windows\syswow64\`},
	"lsass.exe":         {`\windows\system32\`},
	"csrss.exe":         {`\windows\system32\`},
	"smss.exe":          {`\windows\system32\`},
	"services.exe":      {`\windows\system32\`},
	"wininit.exe":       {`\windows\system32\`},
	"winlogon.exe":      {`\windows\system32\`},
	"spoolsv.exe":       {`\windows\system32\`},
	"taskhostw.exe":     {`\windows\system32\`},
	"taskhost.exe":      {`\windows\system32\`},
	"lsm.exe":           {`\windows\system32\`},
	"conhost.exe":       {`\windows\system32\`},
	"dllhost.exe":       {`\windows\system32\`, `\windows\syswow64\`},
	"rundll32.exe":      {`\windows\system32\`, `\windows\syswow64\`},
	"regsvr32.exe":      {`\windows\system32\`, `\windows\syswow64\`},
	"ctfmon.exe":        {`\windows\system32\`, `\windows\syswow64\`},
	"sihost.exe":        {`\windows\system32\`},
	"runtimebroker.exe": {`\windows\system32\`},
	"searchindexer.exe": {`\windows\system32\`},
	"wmiprvse.exe":      {`\windows\system32\wbem\`, `\windows\syswow64\wbem\`},
	"dwm.exe":           {`\windows\system32\`},
	"fontdrvhost.exe":   {`\windows\system32\`},
	"userinit.exe":      {`\windows\system32\`},
	"cmd.exe":           {`\windows\system32\`, `\windows\syswow64\`},
	"powershell.exe":    {`\windows\system32\windowspowershell\v1.0\`, `\windows\syswow64\windowspowershell\v1.0\`},
	"explorer.exe":      {`\windows\`},
	"msmpeng.exe":       {`\programdata\microsoft\windows defender\platform\`, `\program files\windows defender\`},
}

// SystemBinaryNames returns the list of protected names (useful for typosquatting checks).
func SystemBinaryNames() []string {
	out := make([]string, 0, len(systemBinaries))
	for k := range systemBinaries {
		out = append(out, k)
	}
	return out
}

// Masquerade detects files named like Windows system binaries but located elsewhere,
// and names that are one edit away from them (e.g. "scvhost.exe").
func Masquerade(path string) *core.Reason {
	n := Norm(path)
	name := BaseName(n)
	dir := stripDrive(DirName(n)) + `\`
	if dirs, ok := systemBinaries[name]; ok {
		for _, d := range dirs {
			if strings.HasPrefix(dir, d) {
				return nil
			}
		}
		// WinSxS / servicing copies are legitimate.
		if strings.HasPrefix(dir, `\windows\winsxs\`) || strings.HasPrefix(dir, `\windows\servicing\`) {
			return nil
		}
		return &core.Reason{
			Severity: core.Critical,
			Text:     "nombre de binario del sistema (" + name + ") fuera de su ubicación legítima",
			MITRE:    []string{"T1036.005"},
		}
	}
	if !strings.HasSuffix(name, ".exe") || len(name) < 8 {
		return nil
	}
	for sys := range systemBinaries {
		if len(sys) < 8 {
			continue
		}
		if editDistance(name, sys) == 1 {
			return &core.Reason{
				Severity: core.High,
				Text:     "nombre muy parecido a un binario del sistema (" + name + " ≈ " + sys + ")",
				MITRE:    []string{"T1036.005"},
			}
		}
	}
	return nil
}

var docExts = []string{".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".jpg", ".jpeg", ".png", ".gif", ".mp3", ".mp4", ".zip", ".rar", ".rtf", ".csv"}

var execExts = []string{".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".ps1", ".lnk", ".cpl", ".msi", ".jar"}

// DoubleExtension detects names like "factura.pdf.exe".
func DoubleExtension(path string) *core.Reason {
	// Right-to-left override character used to disguise extensions.
	if strings.ContainsRune(BaseName(path), '\u202e') {
		return &core.Reason{Severity: core.Critical, Text: "nombre con carácter RTLO para ocultar la extensión", MITRE: []string{"T1036.002"}}
	}
	name := BaseName(Norm(path))
	e := ext(name)
	if !contains(execExts, e) {
		return nil
	}
	inner := ext(strings.TrimSuffix(name, e))
	if contains(docExts, inner) {
		return &core.Reason{Severity: core.High, Text: "doble extensión engañosa (" + inner + e + ")", MITRE: []string{"T1036.007"}}
	}
	return nil
}

func ext(name string) string {
	if i := strings.LastIndex(name, "."); i >= 0 {
		return strings.ToLower(name[i:])
	}
	return ""
}

// Ext returns the lowercased extension (with dot) of a path.
func Ext(path string) string { return ext(BaseName(path)) }

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

var peExts = []string{".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".ocx", ".pif", ".drv", ".efi"}
var scriptExts = []string{".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".ps1", ".psm1"}

func IsPE(path string) bool     { return contains(peExts, Ext(path)) }
func IsScript(path string) bool { return contains(scriptExts, Ext(path)) }

// editDistance is the optimal string alignment distance (Levenshtein + adjacent transpositions),
// so "scvhost" is one edit away from "svchost".
func editDistance(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	d := make([][]int, len(ra)+1)
	for i := range d {
		d[i] = make([]int, len(rb)+1)
		d[i][0] = i
	}
	for j := range d[0] {
		d[0][j] = j
	}
	for i := 1; i <= len(ra); i++ {
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			d[i][j] = min(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+cost)
			if i > 1 && j > 1 && ra[i-1] == rb[j-2] && ra[i-2] == rb[j-1] {
				d[i][j] = min(d[i][j], d[i-2][j-2]+1)
			}
		}
	}
	return d[len(ra)][len(rb)]
}
