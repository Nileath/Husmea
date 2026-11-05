package services

import (
	"strings"
	"testing"

	"husmea/internal/core"
	"husmea/internal/heuristics"
)

var msSig = core.Signature{Status: "Valid", Signer: "CN=Microsoft Windows, O=Microsoft Corporation"}

func TestAssessServices(t *testing.T) {
	// Normal svchost service with a system DLL.
	l := heuristics.Launch{
		Exe:     heuristics.ExeRef{Path: `C:\Windows\system32\svchost.exe`, Exists: true, Sig: msSig, CommandLine: `C:\Windows\system32\svchost.exe -k netsvcs -p`},
		Payload: &heuristics.ExeRef{Path: `C:\Windows\system32\schedsvc.dll`, Exists: true, Sig: msSig},
	}
	if f := assess(serviceInfo{Name: "Schedule", Start: 2, Type: 0x20}, l); f != nil {
		t.Errorf("legit service reported: %+v", f)
	}

	// svchost hosting a DLL from ProgramData.
	l.Payload = &heuristics.ExeRef{Path: `C:\ProgramData\x\evil.dll`, Exists: true, Sig: core.Signature{Status: "NotSigned"}}
	if f := assess(serviceInfo{Name: "Evil", Start: 2, Type: 0x20}, l); f == nil || f.Severity != core.Critical {
		t.Errorf("svchost with foreign ServiceDll = %+v", f)
	}

	// Unquoted service path.
	cmd := `C:\Program Files\Vendor App\svc.exe -run`
	l = heuristics.Launch{Exe: heuristics.ExeRef{Path: `C:\Program Files\Vendor App\svc.exe`, Exists: true, Sig: core.Signature{Status: "Valid", Signer: "CN=Vendor"}, CommandLine: cmd}}
	f := assess(serviceInfo{Name: "VendorSvc", Start: 2, Type: 0x10, ImagePath: cmd}, l)
	if f == nil || f.Severity != core.Medium || !strings.Contains(strings.Join(f.Reasons, " "), "Unquoted") {
		t.Errorf("unquoted path = %+v", f)
	}

	// Kernel driver outside drivers dir and unsigned.
	l = heuristics.Launch{Exe: heuristics.ExeRef{Path: `C:\Users\a\AppData\Local\Temp\rk.sys`, Exists: true, Sig: core.Signature{Status: "NotSigned"}}}
	if f := assess(serviceInfo{Name: "rk", Start: 1, Type: 0x1}, l); f == nil || f.Severity != core.Critical || !strings.HasPrefix(f.Title, "Controlador") {
		t.Errorf("rootkit driver = %+v", f)
	}

	// Orphan service: disabled? no, manual with missing binary.
	l = heuristics.Launch{Exe: heuristics.ExeRef{Path: `C:\Program Files\Old\old.exe`, Exists: false}}
	if f := assess(serviceInfo{Name: "Old", Start: 3, Type: 0x10}, l); f == nil || f.Severity != core.Low || !strings.Contains(f.Title, "huérfano") {
		t.Errorf("orphan service = %+v", f)
	}

	// Disabled services get one severity level less.
	l = heuristics.Launch{Exe: heuristics.ExeRef{Path: `C:\Users\Public\x.exe`, Exists: true, Sig: core.Signature{Status: "Valid", Signer: "CN=X"}}}
	if f := assess(serviceInfo{Name: "Dis", Start: 4, Type: 0x10}, l); f == nil || f.Severity != core.Medium {
		t.Errorf("disabled service = %+v", f)
	}
}
