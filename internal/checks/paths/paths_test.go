package paths

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"husmea/internal/core"
)

func TestAssessFiles(t *testing.T) {
	now := time.Now()
	unsigned := core.Signature{Status: "NotSigned"}
	signed := core.Signature{Status: "Valid", Signer: "CN=Vendor"}
	cases := []struct {
		path string
		sig  core.Signature
		want core.Severity // -1 = no finding
	}{
		{`C:\Users\a\AppData\Roaming\evil.exe`, unsigned, core.High},
		{`C:\Users\a\AppData\Roaming\evil.exe`, signed, -1},
		{`C:\Users\a\AppData\Roaming\Vendor\lib.dll`, unsigned, core.Low},
		{`C:\Users\a\AppData\Local\Temp\setup\setup.exe`, unsigned, core.Medium},
		{`C:\Users\a\AppData\Local\Temp\x.exe`, unsigned, core.High},
		{`C:\Users\Public\run.vbs`, core.Signature{}, core.High},
		{`C:\Users\a\Downloads\factura.pdf.exe`, unsigned, core.High},
		{`C:\Users\a\AppData\Roaming\svchost.exe`, signed, core.Critical},
		{`C:\Users\a\AppData\Roaming\notes.ps1`, core.Signature{}, core.Low},
	}
	// Shell scripts deeper in AppData are common and not reported.
	if f := assess(fileEntry{Path: `C:\Users\a\AppData\Roaming\x\y\notes.ps1`, Depth: 3}, core.Signature{}, now); f != nil {
		t.Errorf("deep script reported: %+v", f)
	}
	for _, c := range cases {
		f := assess(fileEntry{Path: c.path, Depth: 1, ModTime: now}, c.sig, now)
		switch {
		case c.want < 0 && f != nil:
			t.Errorf("%s (%s): unexpected finding %s %v", c.path, c.sig.Status, f.Severity, f.Reasons)
		case c.want >= 0 && f == nil:
			t.Errorf("%s (%s): no finding, want %s", c.path, c.sig.Status, c.want)
		case c.want >= 0 && f.Severity != c.want:
			t.Errorf("%s (%s): severity %s, want %s (%v)", c.path, c.sig.Status, f.Severity, c.want, f.Reasons)
		}
	}
}

func TestWalkDepthAndFilters(t *testing.T) {
	dir := t.TempDir()
	mk := func(rel string) {
		p := filepath.Join(dir, rel)
		_ = os.MkdirAll(filepath.Dir(p), 0o700)
		_ = os.WriteFile(p, []byte("x"), 0o600)
	}
	mk("a.exe")
	mk("notes.txt")
	mk("sub/b.dll")
	mk("sub/deep/c.exe")
	mk("node_modules/x/d.exe")
	mk("sub/e.js")
	mk("sub/deep/f.js")

	var got []string
	_, err := walk(context.Background(), root{Dir: dir, MaxDepth: 2}, 1000, func(fe fileEntry) {
		rel, _ := filepath.Rel(dir, fe.Path)
		got = append(got, filepath.ToSlash(rel))
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"a.exe": true, "sub/b.dll": true, "sub/e.js": true}
	if len(got) != len(want) {
		t.Fatalf("walk = %v", got)
	}
	for _, g := range got {
		if !want[g] {
			t.Errorf("unexpected %s", g)
		}
	}

	truncated, _ := walk(context.Background(), root{Dir: dir, MaxDepth: 5}, 1, func(fileEntry) {})
	if !truncated {
		t.Error("expected truncation")
	}
}
