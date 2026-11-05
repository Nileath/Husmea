//go:build windows

package processes

import (
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/process"

	"husmea/internal/core"
	"husmea/internal/winutil"
)

type check struct{}

func New() core.Check { return check{} }

func (check) Name() string { return Name }
func (check) Description() string {
	return "Procesos en ejecución: ruta, firma, suplantación y árbol de procesos"
}
func (check) Phase() int { return core.PhaseCollect }

func (check) Run(env *core.Env) ([]core.Finding, error) {
	procs, err := process.ProcessesWithContext(env.Ctx)
	if err != nil {
		return nil, err
	}
	names := map[int32]string{}
	ctimes := map[int32]int64{}
	infos := make([]procInfo, 0, len(procs))
	denied := 0
	for _, p := range procs {
		if env.Ctx.Err() != nil {
			return nil, env.Ctx.Err()
		}
		pi := procInfo{PID: p.Pid}
		pi.Name, _ = p.NameWithContext(env.Ctx)
		names[p.Pid] = pi.Name
		if ct, err := p.CreateTimeWithContext(env.Ctx); err == nil {
			ctimes[p.Pid] = ct
		}
		if p.Pid <= 4 {
			continue // System Idle / System
		}
		pi.PPID, _ = p.PpidWithContext(env.Ctx)
		if pi.Exe, err = p.ExeWithContext(env.Ctx); err != nil {
			denied++
		}
		if !strings.Contains(pi.Exe, `\`) {
			pi.Exe = "" // pseudo-processes such as "Registry" or "MemCompression"
		}
		pi.Cmdline, _ = p.CmdlineWithContext(env.Ctx)
		pi.User, _ = p.UsernameWithContext(env.Ctx)
		if ct, err := p.CreateTimeWithContext(env.Ctx); err == nil {
			pi.Started = time.UnixMilli(ct).Format("2006-01-02 15:04:05")
		}
		infos = append(infos, pi)
	}
	if denied > 0 && !env.IsAdmin {
		env.Logf("processes: %d procesos sin acceso a su ruta (ejecute como administrador para verlos todos)", denied)
	}

	var exes []string
	for i := range infos {
		// Windows reuses PIDs: a "parent" created after the child is a different process.
		if pct, ok := ctimes[infos[i].PPID]; ok && pct <= ctimes[infos[i].PID] {
			infos[i].ParentName = names[infos[i].PPID]
		}
		if infos[i].Exe != "" {
			exes = append(exes, infos[i].Exe)
			env.Artifacts.Add(infos[i].Exe, "proceso:"+infos[i].Name)
		}
	}
	env.Sig.Prefetch(env.Ctx, exes)

	var out []core.Finding
	for _, pi := range infos {
		var sig core.Signature
		exists := true
		if pi.Exe != "" {
			exists = winutil.FileExists(pi.Exe)
			if exists {
				sig = env.Sig.Lookup(env.Ctx, pi.Exe)
			}
		}
		if f := assess(pi, exists, sig); f != nil {
			out = append(out, *f)
		}
	}
	return out, nil
}
