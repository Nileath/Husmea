// Command husmea scans the local machine for indicators of compromise.
// It is read-only: it never modifies the system, it only reports and recommends.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"husmea/internal/checks"
	"husmea/internal/core"
	"husmea/internal/report"
	"husmea/internal/winutil"
)

var version = "0.1.0"

type config struct {
	checks, skip            string
	list, showVersion       bool
	jsonPath, htmlPath      string
	outDir                  string
	noReport                bool
	minSeverity             string
	verbose, noColor, quiet bool
	ioc, yaraRules, yaraBin string
	vt                      bool
	vtMax, vtRate           int
	allowlist               string
	deep                    bool
	timeout                 time.Duration
	maxHashMB               int64
}

func parseFlags(args []string) (*config, error) {
	c := &config{}
	fs := flag.NewFlagSet("husmea", flag.ContinueOnError)
	fs.StringVar(&c.checks, "checks", "all", "módulos a ejecutar, separados por comas (ver --list)")
	fs.StringVar(&c.skip, "skip", "", "módulos a omitir, separados por comas")
	fs.BoolVar(&c.list, "list", false, "listar los módulos disponibles y salir")
	fs.BoolVar(&c.showVersion, "version", false, "mostrar la versión y salir")
	fs.StringVar(&c.outDir, "out-dir", "husmea-reports", "directorio donde guardar los informes JSON y HTML")
	fs.StringVar(&c.jsonPath, "json", "", "ruta del informe JSON (por defecto en --out-dir)")
	fs.StringVar(&c.htmlPath, "html", "", "ruta del informe HTML (por defecto en --out-dir)")
	fs.BoolVar(&c.noReport, "no-report", false, "no generar ficheros de informe, solo salida por consola")
	fs.StringVar(&c.minSeverity, "min-severity", "low", "severidad mínima mostrada en consola: info, low, medium, high, critical")
	fs.BoolVar(&c.verbose, "v", false, "mostrar toda la evidencia de cada hallazgo en consola")
	fs.BoolVar(&c.noColor, "no-color", false, "desactivar colores")
	fs.BoolVar(&c.quiet, "quiet", false, "no mostrar hallazgos en consola (solo resumen)")
	fs.StringVar(&c.ioc, "ioc", "", "fichero con hashes IOC (MD5/SHA1/SHA256, uno por línea)")
	fs.StringVar(&c.yaraRules, "yara-rules", "", "fichero o directorio de reglas YARA")
	fs.StringVar(&c.yaraBin, "yara-bin", "", "ruta a yara64.exe / yr.exe (por defecto se busca en el PATH)")
	fs.BoolVar(&c.vt, "vt", false, "consultar hashes en VirusTotal (requiere la variable VT_API_KEY; solo se envían hashes)")
	fs.IntVar(&c.vtMax, "vt-max", 20, "número máximo de hashes a consultar en VirusTotal")
	fs.IntVar(&c.vtRate, "vt-rate", 4, "consultas por minuto a VirusTotal (4 en la API gratuita)")
	fs.StringVar(&c.allowlist, "allowlist", "", "fichero JSON con rutas/hashes/firmantes/títulos a ignorar")
	fs.BoolVar(&c.deep, "deep", false, "análisis profundo de rutas (más lento)")
	fs.DurationVar(&c.timeout, "timeout", 10*time.Minute, "tiempo máximo por módulo")
	fs.Int64Var(&c.maxHashMB, "max-hash-mb", 100, "tamaño máximo (MB) de fichero para calcular hashes")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "husmea %s — escáner de amenazas (solo detección)\n\nUso: husmea [opciones]\n\nOpciones:\n", version)
		fs.PrintDefaults()
		fmt.Fprint(fs.Output(), "\nEjemplos:\n  husmea\n  husmea --checks services,autoruns,tasks\n  husmea --ioc iocs.txt --yara-rules reglas\\\n  set VT_API_KEY=... && husmea --vt\n\nCódigos de salida: 0 sin hallazgos altos/críticos, 1 hay hallazgos altos/críticos, 2 error de uso.\n")
	}
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	return c, nil
}

func selectChecks(all []core.Check, include, skip string) ([]core.Check, error) {
	byName := map[string]core.Check{}
	for _, c := range all {
		byName[c.Name()] = c
	}
	split := func(s string) []string {
		var out []string
		for _, p := range strings.Split(s, ",") {
			if p = strings.TrimSpace(strings.ToLower(p)); p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	want := map[string]bool{}
	if inc := split(include); len(inc) > 0 && !(len(inc) == 1 && inc[0] == "all") {
		for _, n := range inc {
			if _, ok := byName[n]; !ok {
				return nil, fmt.Errorf("módulo desconocido %q (use --list)", n)
			}
			want[n] = true
		}
	} else {
		for n := range byName {
			want[n] = true
		}
	}
	for _, n := range split(skip) {
		if _, ok := byName[n]; !ok {
			return nil, fmt.Errorf("módulo desconocido %q (use --list)", n)
		}
		delete(want, n)
	}
	var out []core.Check
	for _, c := range all {
		if want[c.Name()] {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no hay módulos seleccionados")
	}
	return out, nil
}

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	cfg, err := parseFlags(args)
	if err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if cfg.showVersion {
		fmt.Println("husmea", version)
		return 0
	}
	all := checks.All()
	if cfg.list {
		for _, c := range all {
			phase := ""
			if c.Phase() == core.PhaseAnalyze {
				phase = " (fase de análisis)"
			}
			fmt.Printf("  %-12s %s%s\n", c.Name(), c.Description(), phase)
		}
		return 0
	}
	selected, err := selectChecks(all, cfg.checks, cfg.skip)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	minSev, err := core.ParseSeverity(cfg.minSeverity)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	var allow *core.Allowlist
	if cfg.allowlist != "" {
		if allow, err = core.LoadAllowlist(cfg.allowlist); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 2
		}
	}

	color := !cfg.noColor && os.Getenv("NO_COLOR") == "" && winutil.EnableVirtualTerminal()
	var outMu sync.Mutex
	con := report.Console{W: os.Stdout, Color: color, MinLevel: minSev, Verbose: cfg.verbose}

	host, _ := os.Hostname()
	uname := ""
	if u, err := user.Current(); err == nil {
		uname = u.Username
	}
	meta := report.Meta{Tool: "husmea", Version: version, Host: host, OS: winutil.OSVersion(), User: uname,
		IsAdmin: winutil.IsAdmin(), Started: time.Now(), Online: cfg.vt}
	con.Banner(meta)
	if !checks.PlatformSupported {
		fmt.Println("  Aviso: en este sistema operativo solo están disponibles algunos módulos; el soporte completo es para Windows.")
		fmt.Println()
	}
	if cfg.vt {
		fmt.Println("  Aviso: --vt enviará los hashes SHA-256 de ficheros sospechosos a VirusTotal (nunca los ficheros).")
		fmt.Println()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	env := &core.Env{
		Ctx:       ctx,
		Artifacts: core.NewArtifacts(),
		Sig:       winutil.NewVerifier(),
		IsAdmin:   meta.IsAdmin,
		Opts: &core.Options{
			Deep:         cfg.deep,
			IOCFile:      cfg.ioc,
			YaraRules:    cfg.yaraRules,
			YaraBin:      cfg.yaraBin,
			VTEnabled:    cfg.vt,
			VTKey:        os.Getenv("VT_API_KEY"),
			VTMax:        cfg.vtMax,
			VTPerMinute:  cfg.vtRate,
			MaxHashSize:  cfg.maxHashMB << 20,
			CheckTimeout: cfg.timeout,
		},
		Log: func(f string, a ...any) {
			outMu.Lock()
			defer outMu.Unlock()
			con.Log(f, a...)
		},
	}
	names := make([]string, len(selected))
	for i, c := range selected {
		names[i] = c.Name()
	}
	fmt.Printf("  Ejecutando %d módulos: %s\n\n", len(selected), strings.Join(names, ", "))

	runner := &core.Runner{Checks: selected, Allowlist: allow, OnCheckDone: func(r core.CheckResult) {
		outMu.Lock()
		defer outMu.Unlock()
		con.CheckDone(r)
	}}
	out := runner.Run(env)
	meta.Duration = time.Since(meta.Started).Round(time.Second).String()
	rep := report.New(meta, out)

	if !cfg.quiet {
		con.Findings(rep)
	}
	con.Summary(rep)

	if !cfg.noReport {
		stamp := meta.Started.Format("20060102-150405")
		base := fmt.Sprintf("husmea-%s-%s", sanitize(host), stamp)
		jp, hp := cfg.jsonPath, cfg.htmlPath
		if jp == "" || hp == "" {
			if err := os.MkdirAll(cfg.outDir, 0o700); err != nil {
				fmt.Fprintln(os.Stderr, "error creando", cfg.outDir+":", err)
			}
		}
		if jp == "" {
			jp = filepath.Join(cfg.outDir, base+".json")
		}
		if hp == "" {
			hp = filepath.Join(cfg.outDir, base+".html")
		}
		var written []string
		if err := rep.WriteJSON(jp); err != nil {
			fmt.Fprintln(os.Stderr, "error escribiendo JSON:", err)
		} else {
			written = append(written, jp)
		}
		if err := rep.WriteHTML(hp); err != nil {
			fmt.Fprintln(os.Stderr, "error escribiendo HTML:", err)
		} else {
			written = append(written, hp)
		}
		sort.Strings(written)
		for _, w := range written {
			if abs, err := filepath.Abs(w); err == nil {
				w = abs
			}
			fmt.Println("  Informe:", w)
		}
	}
	if ctx.Err() != nil {
		fmt.Fprintln(os.Stderr, "\n  Análisis interrumpido: el informe puede estar incompleto.")
	}
	if rep.Summary.Counts["critical"]+rep.Summary.Counts["high"] > 0 {
		return 1
	}
	return 0
}

func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '-' || r == '_' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' {
			return r
		}
		return '_'
	}, s)
}
