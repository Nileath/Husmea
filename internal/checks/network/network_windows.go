//go:build windows

package network

import (
	"strings"

	gnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"

	"husmea/internal/core"
	"husmea/internal/winutil"
)

type check struct{}

func New() core.Check { return check{} }

func (check) Name() string        { return Name }
func (check) Description() string { return "Puertos en escucha y conexiones activas por proceso" }
func (check) Phase() int          { return core.PhaseCollect }

func (check) Run(env *core.Env) ([]core.Finding, error) {
	stats, err := gnet.ConnectionsWithContext(env.Ctx, "inet")
	if err != nil {
		return nil, err
	}
	byPID := map[int32][]connInfo{}
	var all []connInfo
	for _, s := range stats {
		proto := "tcp"
		if s.Type == 2 { // SOCK_DGRAM
			proto = "udp"
		}
		c := connInfo{Proto: proto, LocalIP: s.Laddr.IP, LocalPort: s.Laddr.Port, RemoteIP: s.Raddr.IP, RemotePort: s.Raddr.Port, Status: strings.ToUpper(s.Status), PID: s.Pid}
		if c.Status == "" && proto == "udp" {
			c.Status = "UDP"
		}
		all = append(all, c)
		if s.Pid > 4 {
			byPID[s.Pid] = append(byPID[s.Pid], c)
		}
	}

	procs := map[int32]procMeta{}
	var exes []string
	for pid := range byPID {
		pm := procMeta{PID: pid}
		if p, err := process.NewProcessWithContext(env.Ctx, pid); err == nil {
			pm.Name, _ = p.NameWithContext(env.Ctx)
			if exe, err := p.ExeWithContext(env.Ctx); err == nil && strings.Contains(exe, `\`) {
				pm.Exe = exe
				exes = append(exes, exe)
				env.Artifacts.Add(exe, "red:"+pm.Name)
			}
		}
		procs[pid] = pm
	}
	procs[0] = procMeta{Name: "System Idle"}
	procs[4] = procMeta{PID: 4, Name: "System"}
	env.Sig.Prefetch(env.Ctx, exes)

	var out []core.Finding
	for pid, conns := range byPID {
		pm := procs[pid]
		var sig core.Signature
		if pm.Exe != "" && winutil.FileExists(pm.Exe) {
			sig = env.Sig.Lookup(env.Ctx, pm.Exe)
		}
		if f := assessProcess(pm, conns, sig); f != nil {
			out = append(out, *f)
		}
	}
	if f := listenersInventory(all, procs); f != nil {
		out = append(out, *f)
	}
	return out, nil
}
