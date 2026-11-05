// Package checkutil holds helpers shared by several checks.
package checkutil

import (
	"husmea/internal/core"
	"husmea/internal/heuristics"
)

// LaunchFinding turns the heuristics verdict for a persistence entry into a finding.
// It returns nil when nothing reaches minSev.
func LaunchFinding(title string, l heuristics.Launch, extra []core.Reason, evidence map[string]string, minSev core.Severity, recommendation string) *core.Finding {
	reasons := append(heuristics.AssessLaunch(l), extra...)
	if len(reasons) == 0 {
		return nil
	}
	sev, texts, mitre := core.Combine(reasons)
	if sev < minSev {
		return nil
	}
	f := &core.Finding{
		Severity:       sev,
		Title:          title,
		Path:           l.Exe.Path,
		Evidence:       evidence,
		Reasons:        texts,
		MITRE:          mitre,
		Recommendation: recommendation,
	}
	if l.Exe.Sig.Valid() {
		f.Signer = l.Exe.Sig.SignerName()
	}
	if f.Evidence == nil {
		f.Evidence = map[string]string{}
	}
	if l.Exe.Sig.Known() {
		f.Evidence["firma"] = l.Exe.Sig.Status
	}
	if l.Payload != nil && l.Payload.Path != "" {
		f.Evidence["carga_util"] = l.Payload.Path
	}
	return f
}

// Recommendations reused across checks (Spanish, user-facing).
const (
	RecPersistence = "Verifique si reconoce este programa. Si no lo reconoce: analice el fichero en VirusTotal o con su antivirus, " +
		"desactive la entrada (Autoruns de Sysinternals permite hacerlo de forma reversible) y elimine el fichero tras confirmar que es malicioso. " +
		"Si se confirma malware, cambie sus contraseñas desde otro equipo limpio."
	RecUnsigned = "Un binario sin firma no es necesariamente malicioso, pero conviene comprobar su origen (editor, fecha de instalación) y su hash en VirusTotal."
)

// UnixLaunchFinding is the Linux counterpart of LaunchFinding.
func UnixLaunchFinding(title string, e heuristics.UnixExe, extra []core.Reason, evidence map[string]string, minSev core.Severity, recommendation string) *core.Finding {
	reasons := append(heuristics.AssessUnixExecutable(e), extra...)
	if len(reasons) == 0 {
		return nil
	}
	sev, texts, mitre := core.Combine(reasons)
	if sev < minSev {
		return nil
	}
	if evidence == nil {
		evidence = map[string]string{}
	}
	if e.Owner != "" {
		evidence["paquete"] = e.Owner
	} else if e.PkgKnown && e.Exists {
		evidence["paquete"] = "(ninguno)"
	}
	return &core.Finding{
		Severity:       sev,
		Title:          title,
		Path:           e.Path,
		Evidence:       evidence,
		Reasons:        texts,
		MITRE:          mitre,
		Recommendation: recommendation,
	}
}

// RecUnixPersistence is the generic advice for suspicious Linux persistence entries.
const RecUnixPersistence = "Compruebe si reconoce esta entrada y el programa que lanza. Si no la reconoce: copie el fichero para analizarlo " +
	"(sha256sum, VirusTotal), elimine o comente la entrada, finalice los procesos relacionados y revise el resto de mecanismos de persistencia. " +
	"Si se confirma un compromiso, reinstale desde una fuente fiable y cambie credenciales y claves SSH."
