// Package unixutil contains helpers for Linux/Unix checks: package ownership,
// users and file type detection. Parsers are pure and testable on any OS.
package unixutil

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// PackageDB answers "which package installed this file?" — the Linux analogue of a
// code signature: binaries in system directories should belong to a package.
type PackageDB struct {
	once    sync.Once
	Manager string
	files   map[string]string
}

var defaultDB PackageDB

// Packages returns the lazily loaded package database of the running system.
func Packages() *PackageDB {
	defaultDB.once.Do(func() { defaultDB.load("/") })
	return &defaultDB
}

func (db *PackageDB) Available() bool { return len(db.files) > 0 }

func (db *PackageDB) load(root string) {
	db.files = map[string]string{}
	switch {
	case dirExists(filepath.Join(root, "var/lib/dpkg/info")):
		db.Manager = "dpkg"
		db.loadDpkg(filepath.Join(root, "var/lib/dpkg/info"))
	case dirExists(filepath.Join(root, "var/lib/pacman/local")):
		db.Manager = "pacman"
		db.loadPacman(filepath.Join(root, "var/lib/pacman/local"))
	case fileExists(filepath.Join(root, "lib/apk/db/installed")):
		db.Manager = "apk"
		if f, err := os.Open(filepath.Join(root, "lib/apk/db/installed")); err == nil {
			db.parseApk(f)
			f.Close()
		}
	default:
		if p, err := exec.LookPath("rpm"); err == nil {
			db.Manager = "rpm"
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			out, err := exec.CommandContext(ctx, p, "-qa", "--qf", `[%{FILENAMES}\t%{NAME}\n]`).Output()
			if err == nil {
				db.parseRpm(bytes.NewReader(out))
			}
		}
	}
}

func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}

func (db *PackageDB) loadDpkg(dir string) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		n := e.Name()
		if !strings.HasSuffix(n, ".list") {
			continue
		}
		pkg := strings.TrimSuffix(n, ".list")
		if i := strings.IndexByte(pkg, ':'); i >= 0 {
			pkg = pkg[:i]
		}
		if f, err := os.Open(filepath.Join(dir, n)); err == nil {
			db.parseList(f, pkg)
			f.Close()
		}
	}
}

func (db *PackageDB) parseList(r io.Reader, pkg string) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); strings.HasPrefix(l, "/") {
			db.files[l] = pkg
		}
	}
}

func (db *PackageDB) loadPacman(dir string) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		f, err := os.Open(filepath.Join(dir, e.Name(), "files"))
		if err != nil {
			continue
		}
		pkg := e.Name()
		// Directory name is "<name>-<version>-<rel>"; drop the last two dash-separated fields.
		if parts := strings.Split(pkg, "-"); len(parts) > 2 {
			pkg = strings.Join(parts[:len(parts)-2], "-")
		}
		db.parsePacmanFiles(f, pkg)
		f.Close()
	}
}

func (db *PackageDB) parsePacmanFiles(r io.Reader, pkg string) {
	sc := bufio.NewScanner(r)
	in := false
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(l, "%"):
			in = l == "%FILES%"
		case in && l != "":
			db.files["/"+strings.TrimSuffix(l, "/")] = pkg
		}
	}
}

func (db *PackageDB) parseApk(r io.Reader) {
	sc := bufio.NewScanner(r)
	pkg, dir := "", ""
	for sc.Scan() {
		l := sc.Text()
		if len(l) < 2 || l[1] != ':' {
			continue
		}
		switch l[0] {
		case 'P':
			pkg = l[2:]
		case 'F':
			dir = "/" + l[2:]
		case 'R':
			db.files[path.Join(dir, l[2:])] = pkg
		}
	}
}

func (db *PackageDB) parseRpm(r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		if p, pkg, ok := strings.Cut(sc.Text(), "\t"); ok && strings.HasPrefix(p, "/") {
			db.files[p] = pkg
		}
	}
}

var usrMerge = [][2]string{{"/usr/bin/", "/bin/"}, {"/usr/sbin/", "/sbin/"}, {"/usr/lib/", "/lib/"}, {"/usr/lib64/", "/lib64/"}, {"/usr/lib32/", "/lib32/"}, {"/usr/sbin/", "/usr/bin/"}}

func candidates(p string) []string {
	out := []string{p}
	for _, m := range usrMerge {
		if strings.HasPrefix(p, m[0]) {
			out = append(out, m[1]+strings.TrimPrefix(p, m[0]))
		} else if strings.HasPrefix(p, m[1]) {
			out = append(out, m[0]+strings.TrimPrefix(p, m[1]))
		}
	}
	return out
}

// Owner returns the package owning p (following symlinks and /usr-merge aliases).
func (db *PackageDB) Owner(p string) string {
	if !db.Available() || p == "" {
		return ""
	}
	paths := []string{path.Clean(p)}
	if real, err := filepath.EvalSymlinks(p); err == nil && real != p {
		paths = append(paths, real)
	}
	for _, q := range paths {
		for _, c := range candidates(q) {
			if pkg, ok := db.files[c]; ok {
				return pkg
			}
		}
	}
	return ""
}

// NewPackageDBForTest builds a database from an explicit file→package map.
func NewPackageDBForTest(files map[string]string) *PackageDB {
	db := &PackageDB{Manager: "test", files: files}
	db.once.Do(func() {})
	return db
}
