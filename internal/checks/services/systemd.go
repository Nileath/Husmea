package services

import (
	"bufio"
	"io"
	"strings"
)

// Unit is the subset of a systemd unit file relevant for persistence analysis.
type Unit struct {
	Path        string
	Name        string
	Description string
	Exec        []string // ExecStart/ExecStartPre/... commands, prefixes stripped
	User        string
	WantedBy    []string
}

var execKeys = map[string]bool{"ExecStart": true, "ExecStartPre": true, "ExecStartPost": true, "ExecStop": true, "ExecStopPost": true, "ExecReload": true, "ExecCondition": true}

// ParseUnit parses a systemd unit (or drop-in) file. Line continuations are honored.
func ParseUnit(r io.Reader) Unit {
	var u Unit
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	section := ""
	var pending string
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if pending != "" {
			line = pending + " " + line
			pending = ""
		}
		if strings.HasSuffix(line, `\`) {
			pending = strings.TrimSuffix(line, `\`)
			continue
		}
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '[' {
			section = strings.Trim(line, "[]")
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch {
		case section == "Unit" && k == "Description":
			u.Description = v
		case section == "Service" && execKeys[k] && v != "":
			u.Exec = append(u.Exec, stripExecPrefix(v))
		case section == "Service" && k == "User":
			u.User = v
		case section == "Install" && k == "WantedBy":
			u.WantedBy = append(u.WantedBy, strings.Fields(v)...)
		}
	}
	return u
}

// stripExecPrefix removes systemd special prefixes ("-", "@", ":", "+", "!", "!!", "|").
func stripExecPrefix(v string) string {
	at := false
	for len(v) > 0 && strings.ContainsRune("-@:+!|", rune(v[0])) {
		if v[0] == '@' {
			at = true
		}
		v = v[1:]
	}
	v = strings.TrimSpace(v)
	if at {
		// "@/path argv0 args": drop the overridden argv[0].
		if f := strings.Fields(v); len(f) >= 2 {
			v = f[0] + " " + strings.Join(f[2:], " ")
		}
	}
	return strings.TrimSpace(v)
}

// ScriptCommands returns the non-comment lines of a shell script (for SysV init, rc.local...).
func ScriptCommands(lines []string) []string {
	var out []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		out = append(out, l)
	}
	return out
}
