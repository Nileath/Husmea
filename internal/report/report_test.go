package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"husmea/internal/core"
)

func sample() *Report {
	return New(Meta{Tool: "husmea", Version: "test", Host: "pc", Started: time.Now(), Duration: "1s"}, core.RunOutput{
		Results: []core.CheckResult{{Name: "services", Status: core.StatusOK, Findings: 2}},
		Findings: []core.Finding{
			{Check: "services", Severity: core.Critical, Title: `<script>alert(1)</script>`, Path: `C:\x\"evil".exe`,
				Evidence: map[string]string{"informe": "https://www.virustotal.com/gui/file/abc", "cmd": `"><img src=x onerror=alert(1)>`},
				MITRE:    []string{"T1059.001", `javascript:alert(1)`}},
			{Check: "services", Severity: core.Info, Title: "inventario"},
		},
	})
}

func TestHTMLEscapesAttackerControlledData(t *testing.T) {
	b, err := sample().RenderHTML()
	if err != nil {
		t.Fatal(err)
	}
	html := string(b)
	if strings.Contains(html, "<script>alert(1)</script>") || strings.Contains(html, `<img src=x`) {
		t.Error("unescaped attacker data in HTML")
	}
	if strings.Contains(html, `href="javascript:`) {
		t.Error("javascript: URL rendered as link")
	}
	if !strings.Contains(html, "https://attack.mitre.org/techniques/T1059/001/") {
		t.Error("MITRE link missing")
	}
	if !strings.Contains(html, `href="https://www.virustotal.com/gui/file/abc"`) {
		t.Error("VirusTotal link missing")
	}
}

func TestJSONAndConsole(t *testing.T) {
	r := sample()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"severity":"critical"`) || !strings.Contains(string(b), `"risk_level":"Crítico"`) {
		t.Errorf("json = %s", b)
	}
	var buf bytes.Buffer
	c := Console{W: &buf, MinLevel: core.Low}
	c.Findings(r)
	c.Summary(r)
	out := buf.String()
	if !strings.Contains(out, "CRÍTICO") || strings.Contains(out, "inventario") || !strings.Contains(out, "1 hallazgos de menor severidad ocultos") {
		t.Errorf("console output:\n%s", out)
	}
	if strings.Contains(out, "\033[") {
		t.Error("colors emitted while disabled")
	}
}
