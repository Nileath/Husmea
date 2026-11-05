package tasks

import (
	"regexp"
	"strings"
)

// CronEntry is one scheduled command from a crontab.
type CronEntry struct {
	File     string
	Line     int
	Schedule string
	User     string
	Command  string
}

var envAssign = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*\s*=`)

// ParseCrontab parses crontab lines. systemFormat is true for /etc/crontab and /etc/cron.d
// files, which carry a user field after the schedule. owner is used for user crontabs.
func ParseCrontab(file string, lines []string, systemFormat bool, owner string) []CronEntry {
	var out []CronEntry
	for i, raw := range lines {
		l := strings.TrimSpace(raw)
		if l == "" || l[0] == '#' || envAssign.MatchString(l) {
			continue
		}
		f := strings.Fields(l)
		n := 5
		if strings.HasPrefix(f[0], "@") {
			n = 1
		}
		if systemFormat {
			n++
		}
		if len(f) <= n {
			continue
		}
		e := CronEntry{File: file, Line: i + 1, User: owner}
		if strings.HasPrefix(f[0], "@") {
			e.Schedule = f[0]
		} else {
			e.Schedule = strings.Join(f[:5], " ")
		}
		if systemFormat {
			e.User = f[n-1]
		}
		// Keep the original spacing of the command part.
		rest := l
		for k := 0; k < n; k++ {
			rest = strings.TrimLeft(rest, " \t")
			if j := strings.IndexAny(rest, " \t"); j >= 0 {
				rest = rest[j:]
			}
		}
		e.Command = strings.TrimSpace(rest)
		out = append(out, e)
	}
	return out
}
