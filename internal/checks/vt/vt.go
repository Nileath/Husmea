// Package vt enriches suspicious artifacts with VirusTotal hash lookups (opt-in, online).
package vt

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"husmea/internal/core"
	"husmea/internal/heuristics"
	"husmea/internal/intel/virustotal"
)

const Name = "virustotal"

type check struct{}

func New() core.Check { return check{} }

func (check) Name() string { return Name }
func (check) Description() string {
	return "Consulta en VirusTotal los hashes de los ficheros más sospechosos (opcional, online)"
}
func (check) Phase() int { return core.PhaseAnalyze }

// selectCandidates prioritizes files referenced by the most severe findings,
// then unsigned executables, up to max entries.
func selectCandidates(prior []core.Finding, arts []core.Artifact, sig func(string) core.Signature, exists func(string) bool, max int) []string {
	fs := append([]core.Finding(nil), prior...)
	sort.SliceStable(fs, func(i, j int) bool { return fs[i].Severity > fs[j].Severity })
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		k := strings.ToLower(p)
		if p == "" || seen[k] || len(out) >= max || !exists(p) {
			return
		}
		seen[k] = true
		out = append(out, p)
	}
	for _, f := range fs {
		if f.Severity >= core.Medium {
			add(f.Path)
			if p := f.Evidence["carga_util"]; p != "" {
				add(p)
			}
		}
	}
	for _, a := range arts {
		if heuristics.IsPE(a.Path) {
			if s := sig(a.Path); s.Known() && !s.Valid() {
				add(a.Path)
			}
		}
	}
	return out
}

func verdict(r virustotal.Result) (core.Severity, bool) {
	switch {
	case r.Malicious >= 5:
		return core.Critical, true
	case r.Malicious >= 2:
		return core.High, true
	case r.Malicious == 1 || r.Suspicious >= 2:
		return core.Medium, true
	}
	return core.Info, false
}

func regularFile(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}

func (check) Run(env *core.Env) ([]core.Finding, error) {
	if !env.Opts.VTEnabled {
		return nil, core.ErrSkipped{Reason: "desactivado (use --vt y la variable VT_API_KEY)"}
	}
	if env.Opts.VTKey == "" {
		return nil, core.ErrSkipped{Reason: "falta la API key: defina la variable de entorno VT_API_KEY"}
	}
	limit := env.Opts.VTMax
	if limit <= 0 {
		limit = 20
	}
	perMin := env.Opts.VTPerMinute
	if perMin <= 0 {
		perMin = 4
	}
	cands := selectCandidates(env.PriorFindings(), env.Artifacts.List(),
		func(p string) core.Signature { return env.Sig.Lookup(env.Ctx, p) }, regularFile, limit)
	if len(cands) == 0 {
		return nil, nil
	}
	client := virustotal.New(env.Opts.VTKey, perMin)
	defer client.SaveCache()
	env.Logf("virustotal: consultando %d hashes (límite %d/min)…", len(cands), perMin)

	var out []core.Finding
	var unknown []string
	for i, p := range cands {
		h, err := env.Artifacts.Hash(p, env.Opts.MaxHashSize)
		if err != nil {
			continue
		}
		r, err := client.Lookup(env.Ctx, h.SHA256)
		if err != nil {
			if errors.Is(err, virustotal.ErrUnauthorized) || env.Ctx.Err() != nil {
				return out, err
			}
			env.Logf("virustotal: %s: %v", p, err)
			continue
		}
		env.Logf("virustotal: [%d/%d] %s → %d/%d", i+1, len(cands), heuristics.BaseName(p), r.Malicious, r.Malicious+r.Suspicious+r.Harmless+r.Undetected)
		if !r.Found {
			unknown = append(unknown, p+"  ("+h.SHA256+")")
			continue
		}
		sev, bad := verdict(r)
		if !bad {
			continue
		}
		title := fmt.Sprintf("VirusTotal: %d motores detectan %s", r.Malicious, heuristics.BaseName(p))
		if r.Label != "" {
			title += " (" + r.Label + ")"
		}
		out = append(out, core.Finding{
			Severity: sev,
			Title:    title,
			Path:     p,
			SHA256:   h.SHA256,
			Evidence: map[string]string{
				"maliciosos":  fmt.Sprint(r.Malicious),
				"sospechosos": fmt.Sprint(r.Suspicious),
				"total":       fmt.Sprint(r.Malicious + r.Suspicious + r.Harmless + r.Undetected),
				"informe":     r.Link(),
			},
			Recommendation: "Revise el informe de VirusTotal. Con varias detecciones, ponga el fichero en cuarentena con su antivirus, elimine su persistencia " +
				"y cambie sus contraseñas desde otro equipo. Con 1 detección puede tratarse de un falso positivo: compruebe el nombre de la detección y el editor.",
		})
	}
	if len(unknown) > 0 {
		out = append(out, core.Finding{
			Severity:       core.Info,
			Title:          fmt.Sprintf("VirusTotal: %d ficheros sospechosos no conocidos", len(unknown)),
			Evidence:       map[string]string{"ficheros": strings.Join(unknown, "\n")},
			Recommendation: "Un fichero desconocido para VirusTotal puede ser software interno o malware nuevo/personalizado. Si los otros indicadores son sospechosos, considere subirlo manualmente para su análisis (tenga en cuenta la privacidad).",
		})
	}
	return out, nil
}
