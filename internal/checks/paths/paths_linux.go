//go:build linux

package paths

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"husmea/internal/core"
	"husmea/internal/unixutil"
)

type check struct{}

func New() core.Check { return check{} }

func (check) Name() string { return Name }
func (check) Description() string {
	return "Ejecutables en /tmp, /var/tmp, /dev/shm, /dev y directorios ocultos; binarios SUID/SGID anómalos"
}
func (check) Phase() int { return core.PhaseCollect }

// Directories inside home folders that are large and rarely interesting.
var homeSkip = map[string]bool{
	"node_modules": true, ".git": true, "go-build": true, "pip": true, "mozilla": true, "google-chrome": true, "chromium": true,
	"Code": true, "JetBrains": true, ".npm": true, ".cargo": true, ".rustup": true, ".vscode": true, ".vscode-server": true,
	"snap": true, "Steam": true, "Trash": true, "site-packages": true, ".venv": true, "venv": true, ".gradle": true, ".m2": true,
	".nvm": true, ".pyenv": true, ".sdkman": true, ".conda": true, "anaconda3": true, "miniconda3": true, ".var": true,
	"thumbnails": true, "fontconfig": true, "yarn": true, "pnpm": true, ".cursor-server": true, "ms-playwright": true,
}

type walkSpec struct {
	dir      string
	maxDepth int
	home     bool // apply homeSkip and only open executable files
	statOnly bool // never open files (SUID scan of large system trees)
}

// FUSE mounts under /run/user (network shares, document portal) must not be walked.
var runSkip = map[string]bool{"gvfs": true, "doc": true}

// unixWalk visits regular files up to maxDepth, bounded by maxFiles.
func unixWalk(env *core.Env, s walkSpec, maxFiles int, fn func(unixFile, int)) bool {
	base := filepath.Clean(s.dir)
	baseDepth := strings.Count(base, "/")
	visited := 0
	truncated := false
	_ = filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
		if env.Ctx.Err() != nil {
			return env.Ctx.Err()
		}
		if err != nil {
			if d != nil && d.IsDir() && p != base {
				return fs.SkipDir
			}
			return nil
		}
		depth := strings.Count(p, "/") - baseDepth
		if d.IsDir() {
			if p != base && (depth >= s.maxDepth || (s.home && homeSkip[d.Name()]) || runSkip[d.Name()] || strings.HasPrefix(p, "/proc") || strings.HasPrefix(p, "/sys")) {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		visited++
		if visited > maxFiles {
			truncated = true
			return fs.SkipAll
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		f := unixFile{Path: p, Mode: info.Mode(), Size: info.Size(), ModTime: info.ModTime()}
		if !s.statOnly && (!s.home || f.executable()) || f.Mode&(os.ModeSetuid|os.ModeSetgid) != 0 {
			if info.Size() >= 4 {
				f.ELF = unixutil.IsELF(p)
				f.Shebang = !f.ELF && unixutil.HasShebang(p)
			}
		}
		fn(f, depth)
		return nil
	})
	return truncated
}

func (check) Run(env *core.Env) ([]core.Finding, error) {
	db := unixutil.Packages()
	now := time.Now()
	maxFiles, d := 100000, func(n int) int { return n }
	if env.Opts.Deep {
		maxFiles, d = 2000000, func(int) int { return 30 }
	}

	var out []core.Finding
	seenSUID := map[string]bool{}
	suid := func(f unixFile) {
		if f.Mode&(os.ModeSetuid|os.ModeSetgid) == 0 || seenSUID[f.Path] {
			return
		}
		seenSUID[f.Path] = true
		var packaged *bool
		owner := ""
		if db.Available() {
			owner = db.Owner(f.Path)
			b := owner != ""
			packaged = &b
		}
		if fd := assessSUIDFile(f, packaged, owner, now); fd != nil {
			env.Artifacts.Add(f.Path, "suid")
			out = append(out, *fd)
		}
	}
	threat := func(f unixFile, _ int) {
		suid(f)
		if fd := assessUnixFile(f, now); fd != nil {
			env.Artifacts.Add(f.Path, "ruta-sospechosa")
			out = append(out, *fd)
		}
	}

	specs := []walkSpec{
		{dir: "/tmp", maxDepth: d(6)}, {dir: "/var/tmp", maxDepth: d(6)}, {dir: "/dev/shm", maxDepth: d(6)}, {dir: "/dev", maxDepth: d(3)},
		{dir: "/run/user", maxDepth: d(4)}, {dir: "/var/www", maxDepth: d(5), home: true}, {dir: "/srv", maxDepth: d(4), home: true},
	}
	for _, h := range unixutil.HomeDirs() {
		specs = append(specs, walkSpec{dir: h, maxDepth: d(4), home: true})
	}
	for _, s := range specs {
		if s.dir == "/dev" {
			// Only regular files are interesting in /dev; /dev/shm is handled separately.
			if trunc := unixWalk(env, s, maxFiles, func(f unixFile, depth int) {
				if !strings.HasPrefix(f.Path, "/dev/shm/") {
					threat(f, depth)
				}
			}); trunc {
				env.Logf("paths: %s truncado", s.dir)
			}
			continue
		}
		if unixWalk(env, s, maxFiles, threat) {
			env.Logf("paths: %s tiene demasiados ficheros, análisis truncado (use --deep)", s.dir)
		}
	}

	for _, s := range []walkSpec{
		{dir: "/usr/bin", maxDepth: 1}, {dir: "/usr/sbin", maxDepth: 1}, {dir: "/bin", maxDepth: 1}, {dir: "/sbin", maxDepth: 1},
		{dir: "/usr/local", maxDepth: d(4)}, {dir: "/usr/lib", maxDepth: d(4)}, {dir: "/usr/libexec", maxDepth: d(3)}, {dir: "/opt", maxDepth: d(5)},
	} {
		if fi, err := os.Lstat(s.dir); err != nil || fi.Mode()&os.ModeSymlink != 0 {
			continue // /bin -> /usr/bin on merged-/usr systems
		}
		s.statOnly = true // only stat-based checks: do not open every library
		unixWalk(env, s, maxFiles, func(f unixFile, _ int) { suid(f) })
	}
	return out, env.Ctx.Err()
}
