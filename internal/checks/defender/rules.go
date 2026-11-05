// Package defender inspects the state and configuration of Microsoft Defender Antivirus.
package defender

import (
	"encoding/json"
	"fmt"
	"strings"

	"husmea/internal/core"
)

const Name = "defender"

// strList accepts null, a JSON string or an array of strings (PowerShell output varies).
type strList []string

func (s *strList) UnmarshalJSON(b []byte) error {
	var arr []string
	if err := json.Unmarshal(b, &arr); err == nil {
		*s = arr
		return nil
	}
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		if one != "" {
			*s = []string{one}
		}
		return nil
	}
	*s = nil
	return nil
}

type status struct {
	AMServiceEnabled          *bool
	AntivirusEnabled          *bool
	RealTimeProtectionEnabled *bool
	BehaviorMonitorEnabled    *bool
	IoavProtectionEnabled     *bool
	OnAccessProtectionEnabled *bool
	AntivirusSignatureAge     *int
	IsTamperProtected         *bool
	AMRunningMode             string
}

type prefs struct {
	ExclusionPath             strList
	ExclusionExtension        strList
	ExclusionProcess          strList
	ExclusionIpAddress        strList
	DisableRealtimeMonitoring *bool
}

type threat struct {
	ThreatID      string
	ThreatName    string
	Resources     string
	Time          string
	ActionSuccess *bool
}

type avProduct struct {
	DisplayName  string `json:"displayName"`
	ProductState int64  `json:"productState"`
	Path         string `json:"pathToSignedProductExe"`
}

type report struct {
	Status      *status     `json:"status"`
	StatusError string      `json:"statusError"`
	Prefs       *prefs      `json:"prefs"`
	PrefsError  string      `json:"prefsError"`
	Threats     []threat    `json:"threats"`
	AV          []avProduct `json:"av"`
}

const script = `
$r = @{}
try {
  $r.status = Get-MpComputerStatus -ErrorAction Stop | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,OnAccessProtectionEnabled,AntivirusSignatureAge,IsTamperProtected,AMRunningMode
} catch { $r.statusError = $_.Exception.Message }
try {
  $r.prefs = Get-MpPreference -ErrorAction Stop | Select-Object ExclusionPath,ExclusionExtension,ExclusionProcess,ExclusionIpAddress,DisableRealtimeMonitoring
} catch { $r.prefsError = $_.Exception.Message }
try {
  $names = @{}
  Get-MpThreat -ErrorAction Stop | ForEach-Object { $names[[string]$_.ThreatID] = $_.ThreatName }
  $r.threats = @(Get-MpThreatDetection -ErrorAction Stop | Sort-Object InitialDetectionTime -Descending | Select-Object -First 25 |
    ForEach-Object { [pscustomobject]@{ ThreatID = [string]$_.ThreatID; ThreatName = $names[[string]$_.ThreatID]; Resources = ($_.Resources -join '; '); Time = $_.InitialDetectionTime.ToString('s'); ActionSuccess = $_.ActionSuccess } })
} catch { $r.threats = @() }
try {
  $r.av = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop | Select-Object displayName,productState,pathToSignedProductExe)
} catch { $r.av = @() }
ConvertTo-Json -InputObject $r -Depth 5 -Compress
`

func parseReport(b []byte) (*report, error) {
	var r report
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (p avProduct) enabled() bool  { return (p.ProductState>>8)&0x10 != 0 }
func (p avProduct) outdated() bool { return p.ProductState&0xFF == 0x10 }
func (p avProduct) isDefender() bool {
	return strings.Contains(strings.ToLower(p.DisplayName), "defender")
}

func isFalse(b *bool) bool { return b != nil && !*b }
func isTrue(b *bool) bool  { return b != nil && *b }

var broadPaths = []string{`\temp`, `\appdata`, `\downloads`, `\programdata`, `\users`, `%temp%`, `%appdata%`, `%userprofile%`, `\desktop`, `\public`}
var riskyExts = []string{"exe", "dll", "ps1", "bat", "cmd", "vbs", "js", "scr", "hta", "lnk", "msi", "com", "jar"}
var riskyProcs = []string{"powershell.exe", "pwsh.exe", "cmd.exe", "rundll32.exe", "regsvr32.exe", "wscript.exe", "cscript.exe", "mshta.exe", "msiexec.exe", "explorer.exe", "svchost.exe"}

func exclusionSeverity(kind, value string) core.Severity {
	v := strings.ToLower(strings.TrimSpace(value))
	switch kind {
	case "ruta":
		t := strings.TrimRight(v, `\*`)
		if len(t) <= 2 || t == `c:\windows` || t == `c:\users` {
			return core.Critical
		}
		for _, b := range broadPaths {
			if strings.Contains(v, b) {
				return core.High
			}
		}
	case "extensión":
		e := strings.TrimPrefix(strings.TrimPrefix(v, "*"), ".")
		for _, x := range riskyExts {
			if e == x {
				return core.Critical
			}
		}
	case "proceso":
		for _, p := range riskyProcs {
			if strings.HasSuffix(v, p) {
				return core.Critical
			}
		}
	}
	return core.Medium
}

func restricted(list strList) bool {
	return len(list) == 1 && strings.HasPrefix(list[0], "N/A")
}

func assess(r *report, isAdmin bool) []core.Finding {
	var out []core.Finding
	const tamper = "T1562.001"

	thirdParty := []string{}
	anyEnabled := false
	for _, p := range r.AV {
		if p.enabled() {
			anyEnabled = true
		}
		if !p.isDefender() {
			state := "desactivado"
			if p.enabled() {
				state = "activo"
				thirdParty = append(thirdParty, p.DisplayName)
			}
			if p.outdated() {
				state += ", firmas desactualizadas"
			}
			out = append(out, core.Finding{Severity: core.Info, Title: "Antivirus registrado: " + p.DisplayName + " (" + state + ")", Path: p.Path,
				Recommendation: "Mantenga un único antivirus activo y actualizado."})
		}
	}
	passive := r.Status != nil && strings.Contains(strings.ToLower(r.Status.AMRunningMode), "passive")
	defenderPrimary := len(thirdParty) == 0 && !passive

	if r.Status == nil {
		if len(thirdParty) == 0 {
			out = append(out, core.Finding{
				Severity:       core.High,
				Title:          "No se pudo consultar el estado de Microsoft Defender",
				Description:    r.StatusError,
				MITRE:          []string{tamper},
				Recommendation: "Compruebe en Seguridad de Windows que hay un antivirus activo. Si Defender está deshabilitado y no instaló otro antivirus, puede indicar que un malware lo ha desactivado.",
			})
		}
	} else {
		s := r.Status
		if !anyEnabled && (isFalse(s.AntivirusEnabled) || isFalse(s.AMServiceEnabled)) {
			out = append(out, core.Finding{
				Severity:       core.Critical,
				Title:          "No hay ningún antivirus activo",
				MITRE:          []string{tamper},
				Recommendation: "Active Microsoft Defender (Seguridad de Windows > Protección antivirus y contra amenazas) o instale un antivirus. Si no se puede activar, el equipo puede estar comprometido.",
			})
		}
		if defenderPrimary {
			if isFalse(s.RealTimeProtectionEnabled) || isTrue(r.prefsDisableRT()) {
				out = append(out, core.Finding{
					Severity:       core.High,
					Title:          "Protección en tiempo real de Defender desactivada",
					MITRE:          []string{tamper},
					Recommendation: "Actívela en Seguridad de Windows > Protección antivirus y contra amenazas > Administrar configuración. Si se vuelve a desactivar sola, sospeche de malware o de una directiva de grupo.",
				})
			}
			var off []string
			if isFalse(s.BehaviorMonitorEnabled) {
				off = append(off, "monitorización de comportamiento")
			}
			if isFalse(s.IoavProtectionEnabled) {
				off = append(off, "análisis de descargas (IOAV)")
			}
			if isFalse(s.OnAccessProtectionEnabled) {
				off = append(off, "protección al acceso")
			}
			if len(off) > 0 {
				out = append(out, core.Finding{
					Severity:       core.Medium,
					Title:          "Componentes de Defender desactivados: " + strings.Join(off, ", "),
					MITRE:          []string{tamper},
					Recommendation: "Revise la configuración de Defender y las directivas de grupo (gpedit.msc > Plantillas administrativas > Componentes de Windows > Antivirus de Microsoft Defender).",
				})
			}
			if s.AntivirusSignatureAge != nil && *s.AntivirusSignatureAge > 7 {
				sev := core.Medium
				if *s.AntivirusSignatureAge > 30 {
					sev = core.High
				}
				out = append(out, core.Finding{
					Severity:       sev,
					Title:          fmt.Sprintf("Firmas de Defender desactualizadas (%d días)", *s.AntivirusSignatureAge),
					MITRE:          []string{tamper},
					Recommendation: "Actualice las firmas (Seguridad de Windows > Buscar actualizaciones, o 'Update-MpSignature'). Si fallan las actualizaciones, revise el fichero hosts y el proxy.",
				})
			}
			if isFalse(s.IsTamperProtected) {
				out = append(out, core.Finding{
					Severity:       core.Low,
					Title:          "Protección contra alteraciones (Tamper Protection) desactivada",
					MITRE:          []string{tamper},
					Recommendation: "Actívela en Seguridad de Windows > Protección antivirus y contra amenazas > Administrar configuración para impedir que el malware desactive Defender.",
				})
			}
		}
	}

	if r.Prefs != nil {
		groups := []struct {
			kind string
			list strList
		}{{"ruta", r.Prefs.ExclusionPath}, {"extensión", r.Prefs.ExclusionExtension}, {"proceso", r.Prefs.ExclusionProcess}, {"IP", r.Prefs.ExclusionIpAddress}}
		hidden := false
		for _, g := range groups {
			if restricted(g.list) {
				hidden = true
				continue
			}
			for _, v := range g.list {
				out = append(out, core.Finding{
					Severity:    exclusionSeverity(g.kind, v),
					Title:       "Exclusión de Defender (" + g.kind + "): " + v,
					Description: "Defender no analiza este elemento. El malware añade exclusiones para evitar ser detectado.",
					Evidence:    map[string]string{"tipo": g.kind, "valor": v},
					MITRE:       []string{tamper},
					Recommendation: "Si no añadió usted esta exclusión (o no la exige un software de confianza), elimínela en Seguridad de Windows > " +
						"Protección antivirus > Administrar configuración > Exclusiones, y analice el contenido excluido.",
				})
			}
		}
		if hidden && !isAdmin {
			out = append(out, core.Finding{
				Severity:       core.Info,
				Title:          "Las exclusiones de Defender solo son visibles como administrador",
				Recommendation: "Ejecute husmea como administrador para revisar las exclusiones.",
			})
		}
	}

	for _, t := range r.Threats {
		sev := core.High
		state := "estado de la acción desconocido"
		if isTrue(t.ActionSuccess) {
			sev, state = core.Medium, "neutralizada"
		}
		if isFalse(t.ActionSuccess) {
			sev = core.Critical
			state = "acción NO completada"
		}
		name := t.ThreatName
		if name == "" {
			name = "amenaza " + string(t.ThreatID)
		}
		out = append(out, core.Finding{
			Severity:    sev,
			Title:       "Defender detectó: " + name,
			Description: "Detección registrada el " + t.Time + " (" + state + ").",
			Evidence:    map[string]string{"recursos": strings.ReplaceAll(t.Resources, "; ", "\n"), "fecha": t.Time, "id": string(t.ThreatID)},
			Recommendation: "Revise el Historial de protección en Seguridad de Windows. Si la acción no se completó, ejecute un análisis completo o " +
				"'Microsoft Defender sin conexión'. Investigue cómo llegó la amenaza (descargas, correo, USB).",
		})
	}
	return out
}

func (r *report) prefsDisableRT() *bool {
	if r.Prefs == nil {
		return nil
	}
	return r.Prefs.DisableRealtimeMonitoring
}
