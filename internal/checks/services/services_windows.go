//go:build windows

package services

import (
	"golang.org/x/sys/windows/registry"

	"husmea/internal/core"
	"husmea/internal/winutil"
)

type check struct{}

func New() core.Check { return check{} }

func (check) Name() string        { return Name }
func (check) Description() string { return "Servicios y controladores con binarios sospechosos" }
func (check) Phase() int          { return core.PhaseCollect }

const servicesKey = `SYSTEM\CurrentControlSet\Services`

func (check) Run(env *core.Env) ([]core.Finding, error) {
	root, err := registry.OpenKey(registry.LOCAL_MACHINE, servicesKey, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	names, err := root.ReadSubKeyNames(-1)
	if err != nil {
		return nil, err
	}

	type entry struct {
		info serviceInfo
		cmd  winutil.CommandRef
	}
	var entries []entry
	var files []string
	for _, n := range names {
		if env.Ctx.Err() != nil {
			return nil, env.Ctx.Err()
		}
		k, err := registry.OpenKey(root, n, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		info := serviceInfo{Name: n}
		img, _, err := k.GetStringValue("ImagePath")
		if err != nil || img == "" {
			k.Close()
			continue
		}
		info.ImagePath = img
		info.DisplayName, _ = winutil.RegValue(k, "DisplayName")
		info.Account, _, _ = k.GetStringValue("ObjectName")
		info.Type, _, _ = k.GetIntegerValue("Type")
		info.Start, _, _ = k.GetIntegerValue("Start")
		dll, _ := winutil.RegValue(k, "ServiceDll")
		k.Close()
		if pk, err := registry.OpenKey(root, n+`\Parameters`, registry.QUERY_VALUE); err == nil {
			if d, ok := winutil.RegValue(pk, "ServiceDll"); ok {
				dll = d
			}
			pk.Close()
		}

		ref := winutil.ParseRegistryCommand(img)
		if dll != "" {
			ref.Payload = winutil.NormalizeCommand(dll)
			ref.PayloadExists = winutil.FileExists(ref.Payload)
		}
		entries = append(entries, entry{info, ref})
		for _, f := range ref.Files() {
			files = append(files, f)
			env.Artifacts.Add(f, "servicio:"+n)
		}
	}

	env.Sig.Prefetch(env.Ctx, files)
	var out []core.Finding
	for _, e := range entries {
		if f := assess(e.info, e.cmd.Launch(env.Ctx, env.Sig)); f != nil {
			out = append(out, *f)
		}
	}
	return out, nil
}
