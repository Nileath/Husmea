//go:build windows

package tasks

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"husmea/internal/core"
	"husmea/internal/winutil"
)

type check struct{}

func New() core.Check { return check{} }

func (check) Name() string        { return Name }
func (check) Description() string { return "Tareas programadas con acciones sospechosas" }
func (check) Phase() int          { return core.PhaseCollect }

func (check) Run(env *core.Env) ([]core.Finding, error) {
	root := filepath.Join(winutil.SystemRoot(), `System32\Tasks`)
	type item struct {
		task *Task
		act  execAction
		ref  winutil.CommandRef
	}
	var items []item
	var files []string
	denied := 0
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if env.Ctx.Err() != nil {
			return env.Ctx.Err()
		}
		if err != nil {
			denied++
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			denied++
			return nil
		}
		rel := `\` + strings.TrimPrefix(strings.TrimPrefix(p, root), `\`)
		t, err := ParseTask(rel, b)
		if err != nil {
			return nil
		}
		t.Name = rel
		for _, a := range t.Actions {
			ref := winutil.ParseRegistryCommand(a.CommandLine())
			items = append(items, item{t, a, ref})
			for _, f := range ref.Files() {
				files = append(files, f)
				env.Artifacts.Add(f, "tarea:"+rel)
			}
		}
		return nil
	})
	if err != nil && env.Ctx.Err() != nil {
		return nil, err
	}
	if denied > 0 && !env.IsAdmin {
		env.Logf("tasks: %d elementos no accesibles sin privilegios de administrador", denied)
	}

	env.Sig.Prefetch(env.Ctx, files)
	var out []core.Finding
	for _, it := range items {
		if f := assess(it.task, it.act, it.ref.Launch(env.Ctx, env.Sig)); f != nil {
			out = append(out, *f)
		}
	}
	return out, nil
}
