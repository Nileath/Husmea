package core

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type fakeCheck struct {
	name  string
	phase int
	run   func(*Env) ([]Finding, error)
}

func (f fakeCheck) Name() string                  { return f.name }
func (f fakeCheck) Description() string           { return f.name }
func (f fakeCheck) Phase() int                    { return f.phase }
func (f fakeCheck) Run(e *Env) ([]Finding, error) { return f.run(e) }

func newEnv(timeout time.Duration) *Env {
	return &Env{Ctx: context.Background(), Opts: &Options{CheckTimeout: timeout}, Artifacts: NewArtifacts()}
}

func TestRunnerPhasesStatusesAndSorting(t *testing.T) {
	var sawPrior int
	checks := []Check{
		fakeCheck{"a", PhaseCollect, func(e *Env) ([]Finding, error) {
			return []Finding{{Severity: Low, Title: "low"}, {Severity: Critical, Title: "crit"}}, nil
		}},
		fakeCheck{"skip", PhaseCollect, func(*Env) ([]Finding, error) { return nil, ErrSkipped{Reason: "nope"} }},
		fakeCheck{"boom", PhaseCollect, func(*Env) ([]Finding, error) { panic("kaboom") }},
		fakeCheck{"err", PhaseCollect, func(*Env) ([]Finding, error) { return nil, errors.New("bad") }},
		fakeCheck{"slow", PhaseCollect, func(e *Env) ([]Finding, error) { <-e.Ctx.Done(); return nil, e.Ctx.Err() }},
		fakeCheck{"post", PhaseAnalyze, func(e *Env) ([]Finding, error) {
			sawPrior = len(e.PriorFindings())
			return []Finding{{Severity: High, Title: "high"}}, nil
		}},
	}
	r := &Runner{Checks: checks}
	out := r.Run(newEnv(200 * time.Millisecond))

	if sawPrior != 2 {
		t.Errorf("phase-2 check saw %d prior findings, want 2", sawPrior)
	}
	want := map[string]CheckStatus{"a": StatusOK, "skip": StatusSkipped, "boom": StatusError, "err": StatusError, "slow": StatusTimeout, "post": StatusOK}
	for i, res := range out.Results {
		if res.Name != checks[i].Name() {
			t.Errorf("results not in check order: %d=%s", i, res.Name)
		}
		if want[res.Name] != res.Status {
			t.Errorf("%s status = %s (%s)", res.Name, res.Status, res.Message)
		}
	}
	if len(out.Findings) != 3 || out.Findings[0].Severity != Critical || out.Findings[2].Severity != Low {
		t.Errorf("findings not sorted: %+v", out.Findings)
	}
	if out.Findings[0].Check != "a" || out.Findings[1].Check != "post" {
		t.Errorf("check name not set on findings: %+v", out.Findings)
	}
}

func TestCombine(t *testing.T) {
	sev, texts, mitre := Combine([]Reason{{Medium, "a", []string{"T1"}}, {High, "b", []string{"T1", "T2"}}})
	if sev != Critical || len(texts) != 2 || len(mitre) != 2 {
		t.Errorf("Combine = %s %v %v", sev, texts, mitre)
	}
	if sev, _, _ := Combine([]Reason{{Medium, "a", nil}, {Low, "b", nil}}); sev != Medium {
		t.Errorf("single strong reason should not escalate: %s", sev)
	}
}

func TestSeverityJSONRoundTrip(t *testing.T) {
	b, _ := High.MarshalJSON()
	var s Severity
	if err := s.UnmarshalJSON(b); err != nil || s != High {
		t.Errorf("roundtrip = %s %v", s, err)
	}
	if _, err := ParseSeverity("bogus"); err == nil {
		t.Error("expected error")
	}
}

func TestAllowlist(t *testing.T) {
	a := NewAllowlist([]string{`C:\Tools\*`}, []string{"ABC"}, []string{"Contoso"}, []string{"Tarea programada de terceros:*"})
	fs := []Finding{
		{Path: `c:\tools\sub\x.exe`},
		{SHA256: "abc"},
		{Signer: "Contoso Ltd"},
		{Title: "Tarea programada de terceros: \\Foo"},
		{Path: `C:\Other\x.exe`, Title: "keep"},
	}
	out, n := a.Filter(fs)
	if n != 4 || len(out) != 1 || out[0].Title != "keep" {
		t.Errorf("Filter = %v, %d", out, n)
	}
}

func TestArtifactsHash(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f.bin")
	if err := os.WriteFile(p, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := NewArtifacts()
	a.Add(p, "x")
	a.Add(p, "x")
	a.Add(p, "y")
	if l := a.List(); len(l) != 1 || len(l[0].Sources) != 2 {
		t.Fatalf("List = %+v", l)
	}
	h, err := a.Hash(p, 0)
	if err != nil || h.SHA256 != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" || h.MD5 != "900150983cd24fb0d6963f7d28e17f72" {
		t.Fatalf("Hash = %+v %v", h, err)
	}
	if _, err := HashFile(p, 1); !errors.Is(err, ErrTooLarge) {
		t.Errorf("size limit not enforced: %v", err)
	}
}

func TestSummarize(t *testing.T) {
	s := Summarize([]Finding{{Severity: Critical}, {Severity: Critical}, {Severity: Critical}, {Severity: Low}})
	if s.RiskScore != 100 || s.RiskLevel != "Crítico" || s.Counts["critical"] != 3 || s.Total != 4 {
		t.Errorf("Summarize = %+v", s)
	}
	if s := Summarize(nil); s.RiskScore != 0 || s.Counts["info"] != 0 {
		t.Errorf("empty Summarize = %+v", s)
	}
}

func TestSignatureHelpers(t *testing.T) {
	s := Signature{Status: "Valid", Signer: `CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond`}
	if !s.IsMicrosoft() || s.SignerName() != "Microsoft Windows" {
		t.Errorf("signature helpers: %v %q", s.IsMicrosoft(), s.SignerName())
	}
	if (Signature{Status: "Unknown"}).Known() {
		t.Error("Unknown should not be Known")
	}
}
