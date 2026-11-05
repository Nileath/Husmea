package system

import (
	"strings"
	"testing"

	"husmea/internal/core"
	"husmea/internal/unixutil"
)

func TestUsersAndShadow(t *testing.T) {
	users := unixutil.ParsePasswd(strings.NewReader("root:x:0:0::/root:/bin/bash\ntoor:x:0:0::/root:/bin/bash\nbob:x:1000:1000::/home/bob:/bin/bash\nsvc:x:998:998::/:/usr/sbin/nologin\n"))
	fs := assessUsers(users)
	if len(fs) != 2 || fs[0].Severity != core.Critical || !strings.Contains(fs[0].Title, "toor") {
		t.Errorf("users = %+v", fs)
	}
	sh := assessShadow([]string{"root:$y$j9T$abc:19000:0:99999:7:::", "bob::19000:0:99999:7:::", "svc::19000::::::"}, users)
	if len(sh) != 1 || !strings.Contains(sh[0].Title, "bob") {
		t.Errorf("shadow = %+v", sh)
	}
}

func TestSudoers(t *testing.T) {
	fs := assessSudoers("/etc/sudoers", []string{
		"Defaults env_reset",
		"root ALL=(ALL:ALL) ALL",
		"%sudo ALL=(ALL:ALL) ALL",
		"deploy ALL=(ALL) NOPASSWD: ALL",
		"ALL ALL=(ALL) NOPASSWD: ALL",
		"backup ALL=(root) NOPASSWD: /usr/bin/rsync",
	})
	if len(fs) != 2 || fs[0].Severity != core.Medium || fs[1].Severity != core.Critical {
		t.Errorf("sudoers = %+v", fs)
	}
}

func TestSSHD(t *testing.T) {
	seen, origin := map[string]string{}, map[string]string{}
	parseSSHD("/etc/ssh/sshd_config.d/20-systemd-userdb.conf", []string{"AuthorizedKeysCommand /usr/bin/userdbctl ssh-authorized-keys %u"}, seen, origin)
	parseSSHD("/etc/ssh/sshd_config", []string{
		"PermitRootLogin yes",
		"AuthorizedKeysCommand /tmp/k",
		"AuthorizedKeysFile .ssh/authorized_keys /var/lib/.k",
		"Match User bob",
		"PermitEmptyPasswords yes",
	}, seen, origin)
	fs := assessSSHD(seen, origin)
	titles := []string{}
	for _, f := range fs {
		titles = append(titles, f.Title)
	}
	joined := strings.Join(titles, "|")
	if len(fs) != 2 || !strings.Contains(joined, "root") || !strings.Contains(joined, "/var/lib/.k") || strings.Contains(joined, "vacías") {
		t.Errorf("sshd = %v", titles)
	}
}

func TestModulesAndTaint(t *testing.T) {
	proc := moduleNames([]string{"ext4 1 0 - Live 0x0", "diamorphine 1 0 - Live 0x0"})
	fs := assessModules(proc, map[string]bool{"ext4": true, "hidden_rk": true})
	if len(fs) != 2 || !strings.Contains(fs[0].Title, "hidden_rk") || !strings.Contains(fs[1].Title, "diamorphine") {
		t.Errorf("modules = %+v", fs)
	}
	if f := assessTaint(0); f != nil {
		t.Error("clean kernel reported")
	}
	if f := assessTaint(4096 | 8192); f == nil || f.Severity != core.Low {
		t.Errorf("taint = %+v", f)
	}
}
