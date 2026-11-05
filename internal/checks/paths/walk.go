package paths

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

type root struct {
	Dir      string
	MaxDepth int
}

var skipDirs = map[string]bool{
	"node_modules": true, ".git": true, "user data": true, "cache": true, "code cache": true,
	"gpucache": true, "webcache": true, "windowsapps": true, "assembly": true, "__pycache__": true,
	"site-packages": true, "packages": true, "inetcookies": true, "temporary internet files": true,
}

// walk enumerates interesting files under r up to MaxDepth, bounded by maxFiles visited entries.
func walk(ctx context.Context, r root, maxFiles int, fn func(fileEntry)) (truncated bool, err error) {
	base := filepath.Clean(r.Dir)
	baseDepth := strings.Count(base, string(os.PathSeparator))
	visited := 0
	err = filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			if d != nil && d.IsDir() && p != base {
				return fs.SkipDir
			}
			return nil
		}
		depth := strings.Count(p, string(os.PathSeparator)) - baseDepth
		if d.IsDir() {
			if p != base && (depth >= r.MaxDepth || skipDirs[strings.ToLower(d.Name())]) {
				return fs.SkipDir
			}
			return nil
		}
		visited++
		if visited > maxFiles {
			truncated = true
			return fs.SkipAll
		}
		if !d.Type().IsRegular() || !interesting(p, depth) {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		fn(fileEntry{Path: p, Depth: depth, Size: info.Size(), ModTime: info.ModTime()})
		return nil
	})
	if err == fs.SkipAll {
		err = nil
	}
	return truncated, err
}
