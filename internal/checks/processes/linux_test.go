package processes

import (
	"testing"

	"husmea/internal/core"
)

func TestAssessLinuxProcesses(t *testing.T) {
	cases := []struct {
		name  string
		p     lproc
		owner string
		want  core.Severity // -1: no finding
	}{
		{"packaged daemon", lproc{PID: 1, Comm: "sshd", Argv0: "sshd:", Cmdline: "sshd: /usr/sbin/sshd -D", Exe: "/usr/sbin/sshd"}, "openssh-server", -1},
		{"kernel thread disguise", lproc{PID: 2, Comm: "kworker", Argv0: "[kworker/0:1]", Cmdline: "[kworker/0:1]", Exe: "/dev/shm/.k"}, "", core.Critical},
		{"deleted binary in tmp", lproc{PID: 3, Comm: "x", Cmdline: "/tmp/x", Exe: "/tmp/x", Deleted: true}, "", core.Critical},
		{"upgraded binary", lproc{PID: 4, Comm: "VBoxClient", Cmdline: "/usr/bin/VBoxClient --draganddrop", Exe: "/usr/bin/VBoxClient", Deleted: true, Replaced: true}, "", -1},
		{"socket shell", lproc{PID: 5, Comm: "bash", Cmdline: "bash -i", Exe: "/usr/bin/bash", StdSocket: true}, "bash", core.Critical},
		{"fake sshd name", lproc{PID: 6, Comm: "sshd", Cmdline: "sshd", Exe: "/home/a/.cache/s"}, "", core.Critical},
		{"miner", lproc{PID: 7, Comm: "xmrig", Cmdline: "./xmrig -o stratum+tcp://p:3333", Exe: "/home/a/xmrig"}, "", core.Critical},
		{"firefox preload", lproc{PID: 8, Comm: "firefox-esr", Cmdline: "/usr/lib/firefox-esr/firefox-esr", Exe: "/usr/lib/firefox-esr/firefox-esr", LDPreload: "libmozsandbox.so"}, "firefox-esr", -1},
		{"webshell", lproc{PID: 9, Comm: "sh", Cmdline: "sh -c id", Exe: "/usr/bin/dash", ParentComm: "apache2"}, "dash", core.High},
		{"container process", lproc{PID: 10, Comm: "app", Cmdline: "/usr/bin/app", Exe: "/usr/bin/app", ForeignNS: true}, "", -1},
	}
	for _, c := range cases {
		f := assessLinux(c.p, true, c.owner)
		switch {
		case c.want < 0 && f != nil:
			t.Errorf("%s: unexpected %s %v", c.name, f.Severity, f.Reasons)
		case c.want >= 0 && f == nil:
			t.Errorf("%s: no finding", c.name)
		case c.want >= 0 && f.Severity != c.want:
			t.Errorf("%s: %s, want %s (%v)", c.name, f.Severity, c.want, f.Reasons)
		}
	}
}
