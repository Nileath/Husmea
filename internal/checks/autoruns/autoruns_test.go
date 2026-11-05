package autoruns

import (
	"bytes"
	"encoding/binary"
	"testing"
	"unicode/utf16"

	"husmea/internal/core"
	"husmea/internal/heuristics"
)

func buildLnk(target, args string) []byte {
	var b bytes.Buffer
	hdr := make([]byte, 0x4C)
	binary.LittleEndian.PutUint32(hdr[0:], 0x4C)
	binary.LittleEndian.PutUint32(hdr[0x14:], hasLinkInfo|hasArguments|isUnicode)
	b.Write(hdr)

	// LinkInfo with header size 0x1C (ANSI LocalBasePath only).
	lbp := append([]byte(target), 0)
	size := 0x1C + len(lbp)
	li := make([]byte, 0x1C)
	binary.LittleEndian.PutUint32(li[0:], uint32(size))
	binary.LittleEndian.PutUint32(li[4:], 0x1C)
	binary.LittleEndian.PutUint32(li[8:], 1)
	binary.LittleEndian.PutUint32(li[16:], 0x1C)
	b.Write(li)
	b.Write(lbp)

	u := utf16.Encode([]rune(args))
	_ = binary.Write(&b, binary.LittleEndian, uint16(len(u)))
	_ = binary.Write(&b, binary.LittleEndian, u)
	return b.Bytes()
}

func TestParseLnk(t *testing.T) {
	raw := buildLnk(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "-w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0A")
	sc, err := ParseLnk(raw)
	if err != nil {
		t.Fatal(err)
	}
	if sc.Target != `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` || sc.Arguments != "-w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0A" {
		t.Errorf("ParseLnk = %+v", sc)
	}
	if _, err := ParseLnk([]byte("not a link")); err == nil {
		t.Error("expected error for garbage")
	}
	// Truncated input must not panic.
	for i := 0; i < len(raw); i++ {
		_, _ = ParseLnk(raw[:i])
	}
}

func TestWinlogonAndBootExecute(t *testing.T) {
	if !winlogonExpected("Userinit", `C:\Windows\system32\userinit.exe,`) || !winlogonExpected("Shell", "explorer.exe") {
		t.Error("defaults flagged")
	}
	if winlogonExpected("Userinit", `C:\Windows\system32\userinit.exe, C:\Users\a\evil.exe`) {
		t.Error("modified userinit not flagged")
	}
	if !bootExecuteExpected("autocheck  autochk *") || bootExecuteExpected("autocheck autochk * evil") {
		t.Error("bootexecute check wrong")
	}
	f := assess(entry{Kind: kindWinlogon, Name: "Shell", Command: `explorer.exe, C:\Users\a\AppData\Roaming\x.exe`,
		Launch: heuristics.Launch{Exe: heuristics.ExeRef{Path: `C:\Users\a\AppData\Roaming\x.exe`, Exists: true, Sig: core.Signature{Status: "NotSigned"}}}})
	if f == nil || f.Severity != core.Critical {
		t.Errorf("hijacked shell = %+v", f)
	}
	if f := assess(entry{Kind: kindWinlogon, Name: "Shell", Command: "explorer.exe"}); f != nil {
		t.Errorf("default shell reported: %+v", f)
	}
}

func TestAssessRunEntries(t *testing.T) {
	signed := core.Signature{Status: "Valid", Signer: "CN=Contoso"}
	f := assess(entry{Kind: kindRun, Name: "Contoso", Command: `"C:\Program Files\Contoso\c.exe"`,
		Launch: heuristics.Launch{Exe: heuristics.ExeRef{Path: `C:\Program Files\Contoso\c.exe`, Exists: true, Sig: signed}}})
	if f == nil || f.Severity != core.Info || f.Signer != "Contoso" {
		t.Errorf("benign run entry = %+v", f)
	}
	cmd := `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0A`
	f = assess(entry{Kind: kindRun, Name: "Updater", Command: cmd,
		Launch: heuristics.Launch{Exe: heuristics.ExeRef{Path: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, Exists: true, CommandLine: cmd,
			Sig: core.Signature{Status: "Valid", Signer: "CN=Microsoft Windows, O=Microsoft Corporation"}}}})
	if f == nil || f.Severity < core.High {
		t.Errorf("encoded powershell run entry = %+v", f)
	}
	f = assess(entry{Kind: kindIFEO, Name: "sethc.exe", Command: `C:\Windows\System32\cmd.exe`,
		Launch: heuristics.Launch{Exe: heuristics.ExeRef{Path: `C:\Windows\System32\cmd.exe`, Exists: true}}})
	if f == nil || f.Severity < core.High {
		t.Errorf("IFEO sethc = %+v", f)
	}
}
