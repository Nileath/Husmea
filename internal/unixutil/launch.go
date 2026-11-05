package unixutil

import (
	"os"
	"path/filepath"
	"strings"

	"husmea/internal/heuristics"
)

var searchPath = []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"}

// Resolve finds a bare command name in the standard PATH directories.
func Resolve(exe string) string {
	if exe == "" || strings.HasPrefix(exe, "/") {
		return exe
	}
	for _, d := range searchPath {
		p := filepath.Join(d, exe)
		if fileExists(p) {
			return p
		}
	}
	return exe
}

// Inspect resolves the executable of a command line and gathers context for heuristics.
// vendor marks entries whose definition file belongs to a package.
func Inspect(cmd string, vendor bool, db *PackageDB) heuristics.UnixExe {
	exe := Resolve(heuristics.SplitUnixCommand(cmd))
	e := heuristics.UnixExe{Path: exe, CommandLine: cmd, Vendor: vendor}
	switch {
	case strings.Contains(exe, "%") || strings.Contains(exe, "$"):
		// systemd specifiers (%i, %h…) or shell variables: the real path is only known at runtime.
		e.Exists = true
		return e
	case strings.HasPrefix(exe, "/"):
		_, err := os.Stat(exe)
		e.Exists = err == nil
	default:
		e.Path = "" // shell builtin or unresolved name: only the command line is assessed
	}
	if db != nil && db.Available() {
		e.PkgKnown = true
		if e.Exists {
			e.Owner = db.Owner(exe)
		}
	}
	return e
}
