// Package heuristics contains platform-independent detection rules shared by checks.
// Paths are treated as Windows paths (case-insensitive, backslash separated).
package heuristics

import (
	"strings"

	"husmea/internal/core"
)

// Norm lowercases a Windows path and normalizes separators and quotes.
func Norm(p string) string {
	p = strings.TrimSpace(strings.Trim(strings.TrimSpace(p), `"`))
	p = strings.ReplaceAll(p, "/", `\`)
	return strings.ToLower(p)
}

// BaseName returns the last element of a Windows path.
func BaseName(p string) string {
	p = strings.TrimRight(strings.ReplaceAll(p, "/", `\`), `\`)
	if i := strings.LastIndex(p, `\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// DirName returns the directory part of a Windows path (without trailing separator).
func DirName(p string) string {
	p = strings.ReplaceAll(p, "/", `\`)
	if i := strings.LastIndex(p, `\`); i >= 0 {
		return p[:i]
	}
	return ""
}

type Location struct {
	Category string
	Label    string
	Severity core.Severity
	// RootDrop is true when the file sits directly in the root of a broad,
	// user-writable folder (e.g. %APPDATA%\evil.exe), a classic dropper pattern.
	RootDrop bool
}

func (l Location) Suspicious() bool { return l.Severity >= core.Medium }

type locRule struct {
	marker   string
	category string
	label    string
	sev      core.Severity
	rootSev  core.Severity
}

// Order matters: more specific markers first.
var locRules = []locRule{
	{`\$recycle.bin\`, "recycle", "Papelera de reciclaje", core.Critical, core.Critical},
	{`\appdata\local\temp\`, "temp", "carpeta temporal del usuario (%TEMP%)", core.High, core.High},
	{`\windows\temp\`, "temp", "carpeta temporal del sistema (C:\\Windows\\Temp)", core.High, core.High},
	{`\appdata\local\microsoft\windows\inetcache\`, "inetcache", "caché del navegador (INetCache)", core.High, core.High},
	{`\windows\fonts\`, "sysmisc", "carpeta de fuentes de Windows", core.High, core.High},
	{`\windows\debug\`, "sysmisc", "carpeta Windows\\Debug", core.High, core.High},
	{`\windows\tasks\`, "sysmisc", "carpeta Windows\\Tasks", core.High, core.High},
	{`\windows\tracing\`, "sysmisc", "carpeta Windows\\Tracing", core.High, core.High},
	{`\windows\system32\tasks\`, "sysmisc", "carpeta System32\\Tasks", core.High, core.High},
	{`\windows\system32\spool\drivers\color\`, "sysmisc", "carpeta spool\\drivers\\color", core.High, core.High},
	{`\perflogs\`, "perflogs", "carpeta PerfLogs", core.High, core.High},
	{`\users\public\`, "public", "carpeta pública de usuarios", core.High, core.High},
	{`\users\default\`, "default", "perfil Default", core.High, core.High},
	{`\start menu\programs\startup\`, "startup", "carpeta de Inicio", core.Medium, core.Medium},
	{`\downloads\`, "downloads", "carpeta Descargas", core.Medium, core.Medium},
	{`\desktop\`, "desktop", "Escritorio", core.Medium, core.Medium},
	{`\appdata\roaming\`, "roaming", "AppData\\Roaming", core.Medium, core.High},
	{`\appdata\locallow\`, "locallow", "AppData\\LocalLow", core.Medium, core.High},
	{`\appdata\local\`, "local", "AppData\\Local", core.Low, core.High},
	{`\programdata\`, "programdata", "ProgramData", core.Medium, core.High},
	{`\temp\`, "temp", "carpeta temporal", core.High, core.High},
}

// ClassifyPath returns how suspicious it is for an executable to live at path.
func ClassifyPath(path string) Location {
	n := Norm(path)
	if strings.HasPrefix(n, `\\`) && !strings.HasPrefix(n, `\\?\`) {
		return Location{Category: "unc", Label: "ruta de red (UNC)", Severity: core.Medium}
	}
	for _, r := range locRules {
		i := strings.Index(n, r.marker)
		if i < 0 {
			continue
		}
		rest := n[i+len(r.marker):]
		root := !strings.Contains(rest, `\`)
		loc := Location{Category: r.category, Label: r.label, Severity: r.sev, RootDrop: root}
		if root {
			loc.Severity = r.rootSev
		}
		return loc
	}
	switch {
	case IsWindowsDir(n):
		return Location{Category: "windows", Label: "directorio de Windows", Severity: core.Info}
	case IsProgramFiles(n):
		return Location{Category: "programfiles", Label: "Program Files", Severity: core.Info}
	}
	return Location{Category: "other", Label: "otra ubicación", Severity: core.Info}
}

func stripDrive(n string) string {
	n = strings.TrimPrefix(n, `\\?\`)
	n = strings.TrimPrefix(n, `\??\`)
	if len(n) >= 2 && n[1] == ':' {
		return n[2:]
	}
	return n
}

func IsWindowsDir(path string) bool {
	return strings.HasPrefix(stripDrive(Norm(path)), `\windows\`)
}

func IsSystem32(path string) bool {
	s := stripDrive(Norm(path))
	return strings.HasPrefix(s, `\windows\system32\`) || strings.HasPrefix(s, `\windows\syswow64\`)
}

func IsProgramFiles(path string) bool {
	s := stripDrive(Norm(path))
	return strings.HasPrefix(s, `\program files\`) || strings.HasPrefix(s, `\program files (x86)\`)
}

// IsTrustedLocation reports whether path is under directories that normally
// require administrative rights to write (Windows, Program Files).
func IsTrustedLocation(path string) bool {
	if l := ClassifyPath(path); l.Severity >= core.Medium {
		return false
	}
	return IsWindowsDir(path) || IsProgramFiles(path)
}
