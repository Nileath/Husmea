package paths

import (
	"os"
	"testing"
	"time"

	"husmea/internal/core"
)

func TestAssessUnixFiles(t *testing.T) {
	now := time.Now()
	exe := os.FileMode(0o755)
	cases := []struct {
		f    unixFile
		want core.Severity
	}{
		{unixFile{Path: "/tmp/x", Mode: exe, ELF: true}, core.High},
		{unixFile{Path: "/tmp/.x", Mode: exe, ELF: true}, core.Critical},
		{unixFile{Path: "/tmp/.ICE-unix/k", Mode: exe, ELF: true}, core.Critical},
		{unixFile{Path: "/dev/shm/k", Mode: exe, ELF: true}, core.High},
		{unixFile{Path: "/tmp/jna123/libjnidispatch.so", Mode: 0o644, ELF: true}, core.Medium},
		{unixFile{Path: "/tmp/.bun-1000-71b650bef1b3e52c.node", Mode: 0o644, ELF: true}, core.Low},
		{unixFile{Path: "/tmp/run.sh", Mode: exe, Shebang: true}, core.Medium},
		{unixFile{Path: "/home/a/.cache/x/miner", Mode: exe, ELF: true}, core.Medium},
		{unixFile{Path: "/home/a/.local/kitty.app/bin/kitty", Mode: exe, ELF: true}, -1},
		{unixFile{Path: "/tmp/notes.txt", Mode: 0o644}, -1},
	}
	for _, c := range cases {
		f := assessUnixFile(c.f, now)
		switch {
		case c.want < 0 && f != nil:
			t.Errorf("%s: unexpected %s %v", c.f.Path, f.Severity, f.Reasons)
		case c.want >= 0 && f == nil:
			t.Errorf("%s: no finding", c.f.Path)
		case c.want >= 0 && f.Severity != c.want:
			t.Errorf("%s: %s, want %s (%v)", c.f.Path, f.Severity, c.want, f.Reasons)
		}
	}
}

func TestAssessSUIDFile(t *testing.T) {
	yes := true
	f := unixFile{Path: "/usr/bin/find", Mode: 0o755 | os.ModeSetuid}
	if fd := assessSUIDFile(f, &yes, "findutils", time.Now()); fd == nil || fd.Severity != core.Critical {
		t.Errorf("suid find = %+v", fd)
	}
	f.Mode = 0o755
	if fd := assessSUIDFile(f, &yes, "findutils", time.Now()); fd != nil {
		t.Errorf("non-suid reported: %+v", fd)
	}
}
