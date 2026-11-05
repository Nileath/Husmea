package autoruns

import (
	"fmt"
	"regexp"
	"strings"

	"husmea/internal/core"
	"husmea/internal/heuristics"
)

// Linux persistence parsers and rules (pure, testable on any OS).

var aliasHijack = regexp.MustCompile(`^\s*alias\s+(sudo|su|ssh|scp|passwd|gpg|doas|pkexec)\s*=`)
var funcHijack = regexp.MustCompile(`^\s*(function\s+)?(sudo|su|ssh|passwd|doas)\s*\(\)\s*\{?`)

// assessShellLines evaluates startup shell files (.bashrc, /etc/profile...). It returns
// the merged reasons and the offending lines.
func assessShellLines(lines []string) ([]core.Reason, []string) {
	var reasons []core.Reason
	var hits []string
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		var rs []core.Reason
		if aliasHijack.MatchString(t) || funcHijack.MatchString(t) {
			rs = append(rs, core.Reason{Severity: core.High, Text: "redefine un comando sensible (alias/función de sudo, ssh, su…) para capturar credenciales", MITRE: []string{"T1546.004", "T1056"}})
		}
		rs = append(rs, heuristics.AssessUnixCommand(t)...)
		if len(rs) > 0 {
			reasons = append(reasons, rs...)
			hits = append(hits, fmt.Sprintf("%d: %s", i+1, truncate(t, 200)))
		}
	}
	return reasons, hits
}

// parsePreload returns the libraries listed in /etc/ld.so.preload.
func parsePreload(lines []string) []string {
	var out []string
	for _, l := range lines {
		if i := strings.IndexByte(l, '#'); i >= 0 {
			l = l[:i]
		}
		out = append(out, strings.FieldsFunc(l, func(r rune) bool { return r == ' ' || r == '\t' || r == ':' })...)
	}
	return out
}

type desktopEntry struct {
	Name    string
	Exec    string
	Enabled bool
}

func parseDesktop(lines []string) desktopEntry {
	d := desktopEntry{Enabled: true}
	in := false
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "[") {
			in = l == "[Desktop Entry]"
			continue
		}
		k, v, ok := strings.Cut(l, "=")
		if !in || !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "Name":
			d.Name = v
		case "Exec":
			d.Exec = v
		case "Hidden":
			if strings.EqualFold(v, "true") {
				d.Enabled = false
			}
		case "X-GNOME-Autostart-enabled":
			if strings.EqualFold(v, "false") {
				d.Enabled = false
			}
		}
	}
	return d
}

type sshKey struct {
	Line    int
	Options string
	Type    string
	Comment string
}

var keyTypes = regexp.MustCompile(`(^|\s)(ssh-(rsa|dss|ed25519)|ecdsa-sha2-\S+|sk-\S+)\s`)

func parseAuthorizedKeys(lines []string) []sshKey {
	var out []sshKey
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		loc := keyTypes.FindStringSubmatchIndex(t + " ")
		if loc == nil {
			continue
		}
		k := sshKey{Line: i + 1, Options: strings.TrimSpace(t[:loc[4]]), Type: t[loc[4]:loc[5]]}
		if f := strings.Fields(t[loc[5]:]); len(f) >= 2 {
			k.Comment = strings.Join(f[1:], " ")
		}
		out = append(out, k)
	}
	return out
}

var cmdOption = regexp.MustCompile(`command="((?:[^"\\]|\\.)*)"`)

var udevRun = regexp.MustCompile(`RUN(\{program\})?\s*\+?=\s*"([^"]+)"`)

func parseUdevRuns(lines []string) []string {
	var out []string
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "#") {
			continue
		}
		for _, m := range udevRun.FindAllStringSubmatch(t, -1) {
			out = append(out, m[2])
		}
	}
	return out
}

type pamEntry struct {
	Line   int
	Module string
	Args   string
}

func parsePAM(lines []string) []pamEntry {
	var out []pamEntry
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "@include") {
			continue
		}
		f := strings.Fields(t)
		if len(f) < 3 {
			continue
		}
		modIdx := 2
		if strings.HasPrefix(f[1], "[") { // control like [success=1 default=ignore]
			for j := 1; j < len(f); j++ {
				if strings.HasSuffix(f[j], "]") {
					modIdx = j + 1
					break
				}
			}
		}
		if modIdx >= len(f) {
			continue
		}
		out = append(out, pamEntry{Line: i + 1, Module: f[modIdx], Args: strings.Join(f[modIdx+1:], " ")})
	}
	return out
}

// assessPAM flags pam_exec hooks and modules loaded from non-standard paths (credential theft backdoors).
func assessPAM(e pamEntry) []core.Reason {
	var out []core.Reason
	if strings.HasPrefix(e.Module, "/") && !strings.Contains(e.Module, "/security/") {
		out = append(out, core.Reason{Severity: core.High, Text: "módulo PAM cargado desde una ruta no estándar (" + e.Module + ")", MITRE: []string{"T1556.003"}})
	}
	if strings.HasPrefix(e.Module, "/") {
		if l := heuristics.ClassifyUnixPath(e.Module); l.Severity >= core.Medium {
			out = append(out, core.Reason{Severity: l.Severity, Text: "módulo PAM en " + l.Label, MITRE: []string{"T1556.003"}})
		}
	}
	if strings.Contains(e.Module, "pam_exec") {
		out = append(out, core.Reason{Severity: core.Medium, Text: "pam_exec ejecuta un programa durante la autenticación: " + e.Args, MITRE: []string{"T1556.003"}})
		out = append(out, heuristics.AssessUnixCommand(e.Args)...)
		for _, a := range strings.Fields(e.Args) {
			if strings.HasPrefix(a, "/") {
				if l := heuristics.ClassifyUnixPath(a); l.Severity >= core.Medium {
					out = append(out, core.Reason{Severity: l.Severity, Text: "pam_exec lanza un programa en " + l.Label, MITRE: []string{"T1556.003"}})
				}
			}
		}
	}
	return out
}

var rootkitModules = map[string]bool{"diamorphine": true, "reptile": true, "reptile_module": true, "suterusu": true, "kovid": true, "adore": true,
	"adore_ng": true, "enyelkm": true, "nuk3gh0st": true, "phalanx": true, "rootfoo": true, "brokepkg": true, "singularity": true, "khook": true}

func IsRootkitModule(name string) bool {
	return rootkitModules[strings.ToLower(strings.ReplaceAll(name, "-", "_"))]
}

func truncate(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}
