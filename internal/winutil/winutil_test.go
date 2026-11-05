package winutil

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func lookup(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func TestExpandEnv(t *testing.T) {
	l := lookup(map[string]string{"SystemRoot": `C:\Windows`, "APPDATA": `C:\Users\a\AppData\Roaming`})
	if got := ExpandEnv(`%SystemRoot%\x %APPDATA%\y %NOPE%`, l); got != `C:\Windows\x C:\Users\a\AppData\Roaming\y %NOPE%` {
		t.Errorf("ExpandEnv = %q", got)
	}
}

func TestNormalizeImagePath(t *testing.T) {
	l := lookup(map[string]string{"SystemRoot": `C:\Windows`})
	cases := map[string]string{
		`\SystemRoot\System32\drivers\x.sys`:           `C:\Windows\System32\drivers\x.sys`,
		`System32\drivers\y.sys`:                       `C:\Windows\System32\drivers\y.sys`,
		`\??\C:\Program Files\X\x.sys`:                 `C:\Program Files\X\x.sys`,
		`%SystemRoot%\system32\svchost.exe -k netsvcs`: `C:\Windows\system32\svchost.exe -k netsvcs`,
		`"C:\Program Files\App\a.exe" -s`:              `"C:\Program Files\App\a.exe" -s`,
	}
	for in, want := range cases {
		if got := NormalizeImagePath(in, `C:\Windows`, l); got != want {
			t.Errorf("NormalizeImagePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestResolve(t *testing.T) {
	exists := func(p string) bool { return p == `C:\Windows\System32\cmd.exe` }
	dirs := []string{`C:\Windows\System32\`, `C:\Windows`}
	if got := Resolve("cmd", dirs, exists); got != `C:\Windows\System32\cmd.exe` {
		t.Errorf("Resolve(cmd) = %q", got)
	}
	if got := Resolve(`C:\x\y.exe`, dirs, exists); got != `C:\x\y.exe` {
		t.Errorf("absolute path changed: %q", got)
	}
	if got := Resolve("missing.exe", dirs, exists); got != "missing.exe" {
		t.Errorf("Resolve(missing) = %q", got)
	}
}

func TestPSVerifierBatchingAndCache(t *testing.T) {
	calls := 0
	run := func(_ context.Context, _ string, in []byte) ([]byte, error) {
		calls++
		var paths []string
		if err := json.Unmarshal(in, &paths); err != nil {
			return nil, err
		}
		var rows []sigRow
		for _, p := range paths {
			if p == `C:\fail.exe` {
				continue // simulate missing row
			}
			rows = append(rows, sigRow{P: p, S: "Valid", N: "CN=Test"})
		}
		return json.Marshal(rows)
	}
	v := newPSVerifier(run)
	ctx := context.Background()
	v.Prefetch(ctx, []string{`C:\a.exe`, `c:\A.exe`, `C:\b.exe`, `C:\fail.exe`, ""})
	if calls != 1 {
		t.Fatalf("calls = %d", calls)
	}
	if s := v.Lookup(ctx, `C:\A.EXE`); s.Status != "Valid" || s.Signer != "CN=Test" {
		t.Errorf("Lookup a = %+v", s)
	}
	if s := v.Lookup(ctx, `C:\fail.exe`); s.Status != "Unknown" {
		t.Errorf("Lookup fail = %+v", s)
	}
	if calls != 1 {
		t.Errorf("cached lookups should not run powershell, calls = %d", calls)
	}
	v.Lookup(ctx, `C:\new.exe`)
	if calls != 2 {
		t.Errorf("uncached lookup should run once, calls = %d", calls)
	}

	failing := newPSVerifier(func(context.Context, string, []byte) ([]byte, error) { return nil, errors.New("no ps") })
	if s := failing.Lookup(ctx, `C:\x.exe`); s.Status != "Unknown" {
		t.Errorf("failing verifier = %+v", s)
	}
}

func TestEncodePS(t *testing.T) {
	// "a" in UTF-16LE is 0x61 0x00 -> base64 "YQA="
	if got := encodePS("a"); got != "YQA=" {
		t.Errorf("encodePS = %q", got)
	}
}
