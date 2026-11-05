package processes

import (
	"testing"

	"husmea/internal/core"
)

func TestAssessProcesses(t *testing.T) {
	ms := core.Signature{Status: "Valid", Signer: "CN=Microsoft Windows, O=Microsoft Corporation"}
	if f := assess(procInfo{PID: 10, Name: "svchost.exe", Exe: `C:\Windows\System32\svchost.exe`, ParentName: "services.exe"}, true, ms); f != nil {
		t.Errorf("legit svchost reported: %+v", f)
	}
	f := assess(procInfo{PID: 11, Name: "svchost.exe", Exe: `C:\Users\a\AppData\Roaming\svchost.exe`, ParentName: "explorer.exe"}, true, core.Signature{Status: "NotSigned"})
	if f == nil || f.Severity != core.Critical {
		t.Errorf("fake svchost = %+v", f)
	}
	f = assess(procInfo{PID: 12, Name: "powershell.exe", Exe: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, ParentName: "WINWORD.EXE",
		Cmdline: "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0A"}, true, ms)
	if f == nil || f.Severity != core.Critical {
		t.Errorf("office spawning encoded powershell = %+v", f)
	}
	f = assess(procInfo{PID: 13, Name: "x.exe", Exe: `C:\Program Files\X\x.exe`}, false, core.Signature{})
	if f == nil || f.Severity < core.High {
		t.Errorf("deleted image = %+v", f)
	}
}
