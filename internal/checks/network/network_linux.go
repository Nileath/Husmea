//go:build linux

package network

import (
	"os"
	"strconv"
	"strings"

	gnet "github.com/shirou/gopsutil/v4/net"

	"husmea/internal/core"
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
	unknownPID := 0
	for _, s := range stats {
		proto := "tcp"
		if s.Type == 2 {
			proto = "udp"
		}
		c := connInfo{Proto: proto, LocalIP: s.Laddr.IP, LocalPort: s.Laddr.Port, RemoteIP: s.Raddr.IP, RemotePort: s.Raddr.Port, Status: strings.ToUpper(s.Status), PID: s.Pid}
		if proto == "udp" && (c.Status == "" || c.Status == "NONE") {
			c.Status = "UDP"
		}
		all = append(all, c)
		if s.Pid > 0 {
			byPID[s.Pid] = append(byPID[s.Pid], c)
		} else {
			unknownPID++
		}
	}
	if unknownPID > 0 && !env.IsAdmin {
		env.Logf("network: %d sockets de otros usuarios sin proceso asociado (ejecute con sudo para verlos)", unknownPID)
	}

	procs := map[int32]procMeta{0: {Name: "(desconocido: requiere root)"}}
	for pid := range byPID {
		base := "/proc/" + strconv.Itoa(int(pid))
		pm := procMeta{PID: pid}
		if b, err := os.ReadFile(base + "/comm"); err == nil {
			pm.Name = strings.TrimSpace(string(b))
		}
		if exe, err := os.Readlink(base + "/exe"); err == nil {
			pm.Exe = strings.TrimSuffix(exe, " (deleted)")
			env.Artifacts.Add(pm.Exe, "red:"+pm.Name)
		}
		procs[pid] = pm
	}

	var out []core.Finding
	for pid, conns := range byPID {
		if f := assessProcessWith(unixPolicy, procs[pid], conns, core.Signature{}); f != nil {
			out = append(out, *f)
		}
	}
	// Suspicious ports owned by processes we cannot attribute (non-root) are still worth reporting.
	var orphan []connInfo
	for _, c := range all {
		if c.PID == 0 {
			orphan = append(orphan, c)
		}
	}
	if len(orphan) > 0 {
		if f := assessProcessWith(unixPolicy, procMeta{Name: "proceso desconocido"}, orphan, core.Signature{}); f != nil {
			out = append(out, *f)
		}
	}
	if f := listenersInventory(all, procs); f != nil {
		out = append(out, *f)
	}
	return out, nil
}
