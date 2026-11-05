package report

import (
	"bytes"
	_ "embed"
	"html/template"
	"os"
	"sort"
	"strings"

	"husmea/internal/core"
)

//go:embed template.html
var htmlTemplate string

type kv struct{ K, V string }

var funcs = template.FuncMap{
	"sevClass": func(s core.Severity) string { return s.String() },
	"sevLabel": func(s core.Severity) string { return s.Label() },
	"evidence": func(m map[string]string) []kv {
		out := make([]kv, 0, len(m))
		for k, v := range m {
			if v != "" {
				out = append(out, kv{k, v})
			}
		}
		sort.Slice(out, func(i, j int) bool { return out[i].K < out[j].K })
		return out
	},
	"mitreURL": func(id string) template.URL {
		// Only technique IDs (T1234 or T1234.001) are turned into links.
		for _, r := range id {
			if !(r == 'T' || r == '.' || (r >= '0' && r <= '9')) {
				return ""
			}
		}
		return template.URL("https://attack.mitre.org/techniques/" + strings.ReplaceAll(id, ".", "/") + "/")
	},
	"isVTLink":  func(s string) bool { return strings.HasPrefix(s, "https://www.virustotal.com/gui/file/") },
	"count":     func(s core.Summary, k string) int { return s.Counts[k] },
	"adminWord": adminWord,
}

func (r *Report) RenderHTML() ([]byte, error) {
	t, err := template.New("report").Funcs(funcs).Parse(htmlTemplate)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, r); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (r *Report) WriteHTML(path string) error {
	b, err := r.RenderHTML()
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}
