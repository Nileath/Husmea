//go:build windows

package paths

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"husmea/internal/core"
	"husmea/internal/heuristics"
	"husmea/internal/winutil"
)

type check struct{}

func New() core.Check { return check{} }

func (check) Name() string { return Name }
func (check) Description() string {
	return "Ejecutables y scripts en rutas típicas de malware (Temp, AppData, ProgramData, Public...)"
}
func (check) Phase() int { return core.PhaseCollect }

func roots(deep bool) []root {
	d := func(n int) int {
		if deep {
			return 12
		}
		return n
	}
	sysRoot := winutil.SystemRoot()
	drive := filepath.VolumeName(sysRoot) + `\`
	rs := []root{
		{os.Getenv("TEMP"), d(3)},
		{filepath.Join(sysRoot, "Temp"), d(3)},
		{os.Getenv("APPDATA"), d(3)},
		{os.Getenv("LOCALAPPDATA"), d(2)},
		{os.Getenv("ProgramData"), d(2)},
		{filepath.Join(drive, `Users\Public`), d(4)},
		{filepath.Join(drive, `$Recycle.Bin`), d(3)},
		{filepath.Join(drive, "PerfLogs"), d(4)},
		{filepath.Join(sysRoot, "Tasks"), d(2)},
		{filepath.Join(sysRoot, "Debug"), d(2)},
		{filepath.Join(sysRoot, "Fonts"), d(1)},
		{filepath.Join(sysRoot, `System32\spool\drivers\color`), d(2)},
	}
	if p := os.Getenv("USERPROFILE"); p != "" {
		rs = append(rs, root{filepath.Join(p, "Downloads"), d(1)}, root{filepath.Join(p, "Desktop"), d(1)})
	}
	// Other user profiles (only readable as administrator).
	users := filepath.Join(drive, "Users")
	if ents, err := os.ReadDir(users); err == nil {
		for _, u := range ents {
			n := strings.ToLower(u.Name())
			if !u.IsDir() || n == "public" || n == "default" || n == "default user" || n == "all users" {
				continue
			}
			p := filepath.Join(users, u.Name())
			rs = append(rs,
				root{filepath.Join(p, `AppData\Local\Temp`), d(3)},
				root{filepath.Join(p, `AppData\Roaming`), d(3)},
				root{filepath.Join(p, `AppData\Local`), d(2)},
				root{filepath.Join(p, "Downloads"), d(1)},
			)
		}
	}
	// Deduplicate (env vars usually point to the same folders).
	seen := map[string]bool{}
	var out []root
	for _, r := range rs {
		if r.Dir == "" {
			continue
		}
		k := strings.ToLower(filepath.Clean(r.Dir))
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, r)
	}
	return out
}

func (check) Run(env *core.Env) ([]core.Finding, error) {
	maxFiles := 50000
	if env.Opts.Deep {
		maxFiles = 1000000
	}
	var files []fileEntry
	seen := map[string]bool{}
	for _, r := range roots(env.Opts.Deep) {
		truncated, err := walk(env.Ctx, r, maxFiles, func(fe fileEntry) {
			k := strings.ToLower(fe.Path)
			if seen[k] {
				return
			}
			seen[k] = true
			files = append(files, fe)
		})
		if err != nil && env.Ctx.Err() != nil {
			return nil, err
		}
		if truncated {
			env.Logf("paths: %s tiene demasiados ficheros, análisis truncado (use --deep para ampliarlo)", r.Dir)
		}
	}

	var pes []string
	for _, fe := range files {
		if heuristics.IsPE(fe.Path) {
			pes = append(pes, fe.Path)
		}
	}
	env.Logf("paths: %d ficheros candidatos, verificando %d firmas…", len(files), len(pes))
	env.Sig.Prefetch(env.Ctx, pes)

	now := time.Now()
	var out []core.Finding
	for _, fe := range files {
		env.Artifacts.Add(fe.Path, "ruta-sospechosa")
		var sig core.Signature
		if heuristics.IsPE(fe.Path) {
			sig = env.Sig.Lookup(env.Ctx, fe.Path)
		}
		if f := assess(fe, sig, now); f != nil {
			out = append(out, *f)
		}
	}
	return out, nil
}
