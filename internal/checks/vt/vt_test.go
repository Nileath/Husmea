package vt

import (
	"testing"

	"husmea/internal/core"
	"husmea/internal/intel/virustotal"
)

func TestSelectCandidates(t *testing.T) {
	prior := []core.Finding{
		{Severity: core.Low, Path: `C:\low.exe`},
		{Severity: core.High, Path: `C:\high.exe`, Evidence: map[string]string{"carga_util": `C:\payload.dll`}},
		{Severity: core.Critical, Path: `C:\crit.exe`},
		{Severity: core.Medium, Path: `C:\missing.exe`},
	}
	arts := []core.Artifact{{Path: `C:\unsigned.exe`}, {Path: `C:\signed.exe`}, {Path: `C:\script.ps1`}}
	sig := func(p string) core.Signature {
		if p == `C:\signed.exe` {
			return core.Signature{Status: "Valid"}
		}
		return core.Signature{Status: "NotSigned"}
	}
	exists := func(p string) bool { return p != `C:\missing.exe` }

	got := selectCandidates(prior, arts, sig, exists, 10)
	want := []string{`C:\crit.exe`, `C:\high.exe`, `C:\payload.dll`, `C:\unsigned.exe`}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d] = %s, want %s", i, got[i], want[i])
		}
	}
	if got := selectCandidates(prior, arts, sig, exists, 1); len(got) != 1 || got[0] != `C:\crit.exe` {
		t.Errorf("limit not applied: %v", got)
	}
}

func TestVerdict(t *testing.T) {
	cases := []struct {
		r    virustotal.Result
		sev  core.Severity
		flag bool
	}{
		{virustotal.Result{Malicious: 30}, core.Critical, true},
		{virustotal.Result{Malicious: 3}, core.High, true},
		{virustotal.Result{Malicious: 1}, core.Medium, true},
		{virustotal.Result{Suspicious: 2}, core.Medium, true},
		{virustotal.Result{Harmless: 70}, core.Info, false},
	}
	for _, c := range cases {
		if sev, bad := verdict(c.r); sev != c.sev || bad != c.flag {
			t.Errorf("verdict(%+v) = %s %v", c.r, sev, bad)
		}
	}
}
