// Package processes inspects running processes (image path, signature, ancestry, command line).
package processes

import (
	"strconv"
	"strings"

	"husmea/internal/core"
	"husmea/internal/heuristics"
)

const Name = "processes"

type procInfo struct {
	PID        int32
	PPID       int32
	Name       string
	Exe        string
	Cmdline    string
	User       string
	ParentName string
	Started    string
}

func assess(p procInfo, exeExists bool, sig core.Signature) *core.Finding {
	var reasons []core.Reason
	if p.Exe != "" {
		reasons = append(reasons, heuristics.AssessExecutable(heuristics.ExeRef{Path: p.Exe, Exists: true, Sig: sig, CommandLine: p.Cmdline})...)
		if !exeExists {
			reasons = append(reasons, core.Reason{Severity: core.High, Text: "el ejecutable del proceso ya no existe en disco (borrado tras ejecutarse)", MITRE: []string{"T1070.004"}})
		}
	} else if p.Cmdline != "" {
		reasons = append(reasons, heuristics.AssessCommandLine(p.Cmdline)...)
	}
	name := strings.ToLower(p.Name)
	if r := heuristics.ParentChild(p.ParentName, name); r != nil {
		reasons = append(reasons, *r)
	}
	if len(reasons) == 0 {
		return nil
	}
	sev, texts, mitre := core.Combine(reasons)
	if sev < core.Low {
		return nil
	}
	ev := map[string]string{
		"pid":     strconv.Itoa(int(p.PID)),
		"proceso": p.Name,
		"padre":   p.ParentName + " (" + strconv.Itoa(int(p.PPID)) + ")",
		"usuario": p.User,
		"inicio":  p.Started,
	}
	if p.Cmdline != "" {
		ev["comando"] = p.Cmdline
	}
	if sig.Known() {
		ev["firma"] = sig.Status
	}
	f := &core.Finding{
		Severity: sev,
		Title:    "Proceso sospechoso: " + p.Name + " (PID " + strconv.Itoa(int(p.PID)) + ")",
		Path:     p.Exe,
		Evidence: ev,
		Reasons:  texts,
		MITRE:    mitre,
		Recommendation: "Identifique el programa (Process Explorer de Sysinternals muestra firma, padre y conexiones y permite consultar VirusTotal). " +
			"Si no lo reconoce, desconecte el equipo de la red, finalice el proceso ('taskkill /PID " + strconv.Itoa(int(p.PID)) + " /F'), " +
			"localice cómo se inicia (revise los hallazgos de persistencia) y analice el binario antes de eliminarlo.",
	}
	if sig.Valid() {
		f.Signer = sig.SignerName()
	}
	return f
}
