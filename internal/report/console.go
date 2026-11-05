package report

import (
	"fmt"
	"io"
	"runtime"
	"sort"
	"strings"
	"time"

	"husmea/internal/core"
)

type Console struct {
	W        io.Writer
	Color    bool
	MinLevel core.Severity
	Verbose  bool
}

const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	dim    = "\033[2m"
	red    = "\033[31m"
	green  = "\033[32m"
	yellow = "\033[33m"
	mag    = "\033[35m"
	cyan   = "\033[36m"
	bgRed  = "\033[41;97m"
)

func (c Console) c(code, s string) string {
	if !c.Color {
		return s
	}
	return code + s + reset
}

func (c Console) sevColor(s core.Severity) string {
	switch s {
	case core.Critical:
		return bgRed
	case core.High:
		return red + bold
	case core.Medium:
		return yellow
	case core.Low:
		return cyan
	}
	return dim
}

func (c Console) Banner(meta Meta) {
	fmt.Fprintln(c.W, c.c(bold+mag, "\n  husmea")+c.c(dim, " ▸ escáner de amenazas "+meta.Version))
	fmt.Fprintf(c.W, "\n  Equipo: %s   Usuario: %s   SO: %s\n", meta.Host, meta.User, meta.OS)
	if meta.IsAdmin {
		fmt.Fprintln(c.W, "  Privilegios: "+c.c(green, adminWord()))
	} else {
		fmt.Fprintln(c.W, "  Privilegios: "+c.c(yellow, "usuario estándar")+c.c(dim, " (ejecute "+elevateHint()+" para un análisis completo)"))
	}
	fmt.Fprintln(c.W)
}

func (c Console) CheckDone(r core.CheckResult) {
	var st string
	switch r.Status {
	case core.StatusOK:
		st = c.c(green, "✔")
	case core.StatusSkipped:
		st = c.c(dim, "–")
	default:
		st = c.c(red, "✘")
	}
	line := fmt.Sprintf("  %s %-12s %s", st, r.Name, c.c(dim, r.Duration.Round(time.Millisecond).String()))
	if r.Status == core.StatusOK {
		line += fmt.Sprintf("  %d hallazgos", r.Findings)
	} else if r.Message != "" {
		msg := r.Message
		if i := strings.IndexByte(msg, '\n'); i > 0 {
			msg = msg[:i]
		}
		line += "  " + c.c(dim, msg)
	}
	fmt.Fprintln(c.W, line)
}

func (c Console) Log(format string, args ...any) {
	fmt.Fprintln(c.W, c.c(dim, "    · "+fmt.Sprintf(format, args...)))
}

func (c Console) Findings(r *Report) {
	shown := 0
	hidden := 0
	fmt.Fprintln(c.W)
	for _, f := range r.Findings {
		if f.Severity < c.MinLevel {
			hidden++
			continue
		}
		shown++
		fmt.Fprintf(c.W, "%s %s %s\n", c.c(c.sevColor(f.Severity), fmt.Sprintf(" %-8s", f.Severity.Label())), c.c(bold, f.Title), c.c(dim, "["+f.Check+"]"))
		if f.Path != "" {
			fmt.Fprintf(c.W, "           %s %s\n", c.c(dim, "ruta:"), f.Path)
		}
		if f.Signer != "" {
			fmt.Fprintf(c.W, "           %s %s\n", c.c(dim, "firmante:"), f.Signer)
		}
		if f.Description != "" {
			fmt.Fprintf(c.W, "           %s\n", f.Description)
		}
		for _, rs := range f.Reasons {
			fmt.Fprintf(c.W, "           • %s\n", rs)
		}
		if c.Verbose || f.Severity >= core.High {
			keys := make([]string, 0, len(f.Evidence))
			for k := range f.Evidence {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				v := f.Evidence[k]
				if v == "" {
					continue
				}
				v = strings.ReplaceAll(v, "\n", "\n             ")
				fmt.Fprintf(c.W, "           %s %s\n", c.c(dim, k+":"), v)
			}
		}
		if f.Recommendation != "" {
			fmt.Fprintf(c.W, "           %s %s\n", c.c(green, "→"), f.Recommendation)
		}
		if len(f.MITRE) > 0 {
			fmt.Fprintf(c.W, "           %s\n", c.c(dim, "MITRE ATT&CK: "+strings.Join(f.MITRE, ", ")))
		}
		fmt.Fprintln(c.W)
	}
	if shown == 0 {
		fmt.Fprintln(c.W, c.c(green, "  No se encontraron hallazgos con severidad ≥ "+c.MinLevel.Label()))
	}
	if hidden > 0 {
		fmt.Fprintln(c.W, c.c(dim, fmt.Sprintf("  (%d hallazgos de menor severidad ocultos; véalos en el informe HTML/JSON o use --min-severity info)", hidden)))
	}
}

func (c Console) Summary(r *Report) {
	s := r.Summary
	fmt.Fprintln(c.W, c.c(bold, "\nResumen"))
	fmt.Fprintf(c.W, "  %s %d   %s %d   %s %d   %s %d   %s %d\n",
		c.c(c.sevColor(core.Critical), " CRÍTICO "), s.Counts["critical"],
		c.c(c.sevColor(core.High), "ALTO"), s.Counts["high"],
		c.c(c.sevColor(core.Medium), "MEDIO"), s.Counts["medium"],
		c.c(c.sevColor(core.Low), "BAJO"), s.Counts["low"],
		c.c(dim, "INFO"), s.Counts["info"])
	lvl := s.RiskLevel
	switch {
	case s.Counts["critical"] > 0:
		lvl = c.c(bgRed, " "+lvl+" ")
	case s.Counts["high"] > 0:
		lvl = c.c(red+bold, lvl)
	case s.Counts["medium"] > 0:
		lvl = c.c(yellow, lvl)
	default:
		lvl = c.c(green, lvl)
	}
	fmt.Fprintf(c.W, "  Riesgo: %s (puntuación %d/100)   Duración: %s\n", lvl, s.RiskScore, r.Meta.Duration)
	if r.Suppressed > 0 {
		fmt.Fprintf(c.W, "  %d hallazgos suprimidos por la allowlist\n", r.Suppressed)
	}
	fmt.Fprintln(c.W, c.c(dim, "  husmea solo detecta: no modifica el sistema. Los hallazgos son indicios que deben verificarse antes de actuar."))
}

func adminWord() string {
	if runtime.GOOS == "windows" {
		return "administrador"
	}
	return "root"
}

func elevateHint() string {
	if runtime.GOOS == "windows" {
		return "como administrador"
	}
	return "con sudo"
}
