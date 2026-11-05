// Package winutil contains Windows helpers. Pure helpers live in untagged files so
// they can be unit-tested on any OS; OS-specific code uses build tags.
package winutil

import (
	"os"
	"regexp"
	"strings"
)

var envRe = regexp.MustCompile(`%([^%\s]+)%`)

// ExpandEnv expands Windows-style %VAR% references using lookup; unknown vars are kept.
func ExpandEnv(s string, lookup func(string) (string, bool)) string {
	if lookup == nil {
		lookup = os.LookupEnv
	}
	return envRe.ReplaceAllStringFunc(s, func(m string) string {
		if v, ok := lookup(m[1 : len(m)-1]); ok {
			return v
		}
		return m
	})
}

// NormalizeImagePath converts the many forms found in the registry (services, drivers)
// into a regular absolute path or command line.
func NormalizeImagePath(raw, systemRoot string, lookup func(string) (string, bool)) string {
	s := strings.TrimSpace(ExpandEnv(raw, lookup))
	if s == "" {
		return s
	}
	quoted := strings.HasPrefix(s, `"`)
	body := strings.TrimPrefix(s, `"`)
	lower := strings.ToLower(body)
	switch {
	case strings.HasPrefix(lower, `\systemroot\`):
		body = systemRoot + body[len(`\systemroot`):]
	case strings.HasPrefix(lower, `\??\`):
		body = body[4:]
	case strings.HasPrefix(lower, `\\?\`):
		body = body[4:]
	case strings.HasPrefix(lower, `system32\`), strings.HasPrefix(lower, `syswow64\`):
		body = systemRoot + `\` + body
	}
	if quoted {
		return `"` + body
	}
	return body
}

// Resolve finds a bare executable name (e.g. "powershell.exe") in dirs.
func Resolve(exe string, dirs []string, exists func(string) bool) string {
	if exe == "" || strings.ContainsAny(exe, `\/`) {
		return exe
	}
	cands := []string{exe}
	if !strings.Contains(exe, ".") {
		cands = append(cands, exe+".exe", exe+".com", exe+".bat", exe+".cmd")
	}
	for _, d := range dirs {
		if d == "" {
			continue
		}
		for _, c := range cands {
			p := strings.TrimRight(d, `\`) + `\` + c
			if exists(p) {
				return p
			}
		}
	}
	return exe
}

// FileExists reports whether a regular file exists at p.
func FileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
