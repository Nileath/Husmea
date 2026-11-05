package defender

import (
	"strings"
	"testing"

	"husmea/internal/core"
)

// Shapes taken from PowerShell 5.1 ConvertTo-Json output.
const healthy = `{"status":{"AMServiceEnabled":true,"AntivirusEnabled":true,"RealTimeProtectionEnabled":true,"BehaviorMonitorEnabled":true,
"IoavProtectionEnabled":true,"OnAccessProtectionEnabled":true,"AntivirusSignatureAge":0,"IsTamperProtected":true,"AMRunningMode":"Normal"},
"prefs":{"ExclusionPath":null,"ExclusionExtension":null,"ExclusionProcess":null,"ExclusionIpAddress":null,"DisableRealtimeMonitoring":false},
"threats":[],"av":[{"displayName":"Windows Defender","productState":397568,"pathToSignedProductExe":"windowsdefender://"}]}`

const compromised = `{"status":{"AMServiceEnabled":true,"AntivirusEnabled":true,"RealTimeProtectionEnabled":false,"BehaviorMonitorEnabled":false,
"IoavProtectionEnabled":true,"OnAccessProtectionEnabled":true,"AntivirusSignatureAge":45,"IsTamperProtected":false,"AMRunningMode":"Normal"},
"prefs":{"ExclusionPath":["C:\\","C:\\Tools\\build"],"ExclusionExtension":"exe","ExclusionProcess":["C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"],"ExclusionIpAddress":null,"DisableRealtimeMonitoring":true},
"threats":[{"ThreatID":"2147735503","ThreatName":"Trojan:Win32/Wacatac.B!ml","Resources":"file:_C:\\Users\\a\\x.exe","Time":"2026-11-01T10:00:00","ActionSuccess":false}],
"av":[{"displayName":"Windows Defender","productState":393472,"pathToSignedProductExe":"windowsdefender://"}]}`

func TestDefenderHealthy(t *testing.T) {
	r, err := parseReport([]byte(healthy))
	if err != nil {
		t.Fatal(err)
	}
	if fs := assess(r, true); len(fs) != 0 {
		t.Errorf("healthy defender produced findings: %+v", fs)
	}
}

func TestDefenderCompromised(t *testing.T) {
	r, err := parseReport([]byte(compromised))
	if err != nil {
		t.Fatal(err)
	}
	fs := assess(r, true)
	titles := map[string]core.Severity{}
	for _, f := range fs {
		titles[f.Title] = f.Severity
	}
	expect := map[string]core.Severity{
		"Protección en tiempo real de Defender desactivada":              core.High,
		"Firmas de Defender desactualizadas (45 días)":                   core.High,
		"Protección contra alteraciones (Tamper Protection) desactivada": core.Low,
		`Exclusión de Defender (ruta): C:\`:                              core.Critical,
		`Exclusión de Defender (ruta): C:\Tools\build`:                   core.Medium,
		"Exclusión de Defender (extensión): exe":                         core.Critical,
		"Defender detectó: Trojan:Win32/Wacatac.B!ml":                    core.Critical,
	}
	for title, sev := range expect {
		if got, ok := titles[title]; !ok || got != sev {
			t.Errorf("%q: got %v (present=%v), want %s", title, got, ok, sev)
		}
	}
	found := false
	for title := range titles {
		if strings.HasPrefix(title, "Componentes de Defender desactivados") {
			found = true
		}
	}
	if !found {
		t.Error("disabled components not reported")
	}
}

func TestThirdPartyAV(t *testing.T) {
	js := `{"status":{"AMServiceEnabled":true,"AntivirusEnabled":false,"RealTimeProtectionEnabled":false,"AMRunningMode":"Passive Mode"},
"prefs":{"ExclusionPath":["N/A: Must be an administrator to view exclusions"]},"threats":[],
"av":[{"displayName":"ESET Security","productState":266240,"pathToSignedProductExe":"C:\\Program Files\\ESET\\ecmds.exe"}]}`
	r, err := parseReport([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	fs := assess(r, false)
	for _, f := range fs {
		if f.Severity > core.Info {
			t.Errorf("third-party AV active, unexpected %s: %s", f.Severity, f.Title)
		}
	}
	if len(fs) != 2 {
		t.Errorf("expected AV inventory + admin notice, got %+v", fs)
	}
}

func TestExclusionSeverity(t *testing.T) {
	if exclusionSeverity("ruta", `%TEMP%\x`) != core.High || exclusionSeverity("proceso", "rundll32.exe") != core.Critical ||
		exclusionSeverity("extensión", ".log") != core.Medium {
		t.Error("exclusion severity mismatch")
	}
}
