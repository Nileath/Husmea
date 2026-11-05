package tasks

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"

	"husmea/internal/core"
	"husmea/internal/heuristics"
)

const sampleTask = `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>Updater</Author>
    <URI>\OneUpdate</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled></LogonTrigger>
    <TimeTrigger><StartBoundary>2024-01-01T00:00:00</StartBoundary></TimeTrigger>
  </Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><Hidden>true</Hidden><Enabled>true</Enabled></Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Users\bob\AppData\Roaming\upd\upd.exe</Command>
      <Arguments>--silent</Arguments>
    </Exec>
  </Actions>
</Task>`

func utf16le(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := []byte{0xFF, 0xFE}
	for _, c := range u {
		b = binary.LittleEndian.AppendUint16(b, c)
	}
	return b
}

func TestParseTaskUTF16(t *testing.T) {
	task, err := ParseTask("", utf16le(sampleTask))
	if err != nil {
		t.Fatal(err)
	}
	if task.Name != `\OneUpdate` || !task.Hidden || !task.Enabled || task.Author != "Updater" || task.RunLevel != "HighestAvailable" {
		t.Errorf("task = %+v", task)
	}
	if len(task.Actions) != 1 || task.Actions[0].CommandLine() != `C:\Users\bob\AppData\Roaming\upd\upd.exe --silent` {
		t.Errorf("actions = %+v", task.Actions)
	}
	if len(task.Triggers) != 2 || task.Triggers[0] != "LogonTrigger" {
		t.Errorf("triggers = %v", task.Triggers)
	}
	if _, err := ParseTask("x", []byte("<<<")); err == nil {
		t.Error("expected parse error")
	}
}

func TestCommandLineQuoting(t *testing.T) {
	a := execAction{Command: `C:\Program Files\X\x.exe`, Arguments: "-a"}
	if a.CommandLine() != `"C:\Program Files\X\x.exe" -a` {
		t.Errorf("CommandLine = %q", a.CommandLine())
	}
}

func TestAssessTask(t *testing.T) {
	task, _ := ParseTask("", utf16le(sampleTask))
	l := heuristics.Launch{Exe: heuristics.ExeRef{Path: `C:\Users\bob\AppData\Roaming\upd\upd.exe`, Exists: true, Sig: core.Signature{Status: "NotSigned"}, CommandLine: task.Actions[0].CommandLine()}}
	f := assess(task, task.Actions[0], l)
	if f == nil || f.Severity < core.High {
		t.Fatalf("suspicious task = %+v", f)
	}

	ms := &Task{Name: `\Microsoft\Windows\Defrag\ScheduledDefrag`, Enabled: true}
	msl := heuristics.Launch{Exe: heuristics.ExeRef{Path: `C:\Windows\System32\defrag.exe`, Exists: true, Sig: core.Signature{Status: "Valid", Signer: "CN=Microsoft Windows, O=Microsoft Corporation"}}}
	if f := assess(ms, execAction{Command: `%windir%\system32\defrag.exe`}, msl); f != nil {
		t.Errorf("benign Microsoft task reported: %+v", f)
	}
	msl.Exe.Path = `C:\ProgramData\x\defrag.exe`
	msl.Exe.Sig = core.Signature{Status: "NotSigned"}
	if f := assess(ms, execAction{Command: msl.Exe.Path}, msl); f == nil || f.Severity < core.High {
		t.Errorf("hijacked Microsoft task = %+v", f)
	}
}
