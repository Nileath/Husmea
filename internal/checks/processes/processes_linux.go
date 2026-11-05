//go:build linux

package processes

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"husmea/internal/core"
	"husmea/internal/unixutil"
)

type check struct{}

func New() core.Check { return check{} }

func (check) Name() string { return Name }
func (check) Description() string {
	return "Procesos en ejecución: binarios borrados o fuera de paquetes, suplantación, reverse shells, mineros, LD_PRELOAD"
}
func (check) Phase() int { return core.PhaseCollect }

func readProc(pid int, selfNS string) (lproc, bool) {
	base := "/proc/" + strconv.Itoa(pid)
	p := lproc{PID: pid}
	comm, err := os.ReadFile(base + "/comm")
	if err != nil {
		return p, false
	}
	p.Comm = strings.TrimSpace(string(comm))
	if b, err := os.ReadFile(base + "/cmdline"); err == nil {
		p.Argv0, _, _ = strings.Cut(string(b), "\x00")
		p.Cmdline = strings.TrimSpace(strings.ReplaceAll(string(b), "\x00", " "))
	}
	if p.Cmdline == "" {
		return p, false // kernel thread or zombie
	}
	if st, err := os.ReadFile(base + "/stat"); err == nil {
		// Fields after the last ')' : state ppid ...
		s := string(st)
		if i := strings.LastIndexByte(s, ')'); i >= 0 {
			if f := strings.Fields(s[i+1:]); len(f) >= 2 {
				p.PPID, _ = strconv.Atoi(f[1])
			}
		}
	}
	if status, err := os.ReadFile(base + "/status"); err == nil {
		for _, l := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(l, "Uid:") {
				if f := strings.Fields(l); len(f) >= 2 {
					p.UID, _ = strconv.Atoi(f[1])
				}
			}
		}
	}
	if exe, err := os.Readlink(base + "/exe"); err == nil {
		if strings.HasSuffix(exe, " (deleted)") {
			p.Deleted = true
			exe = strings.TrimSuffix(exe, " (deleted)")
			if _, err := os.Stat(exe); err == nil {
				p.Replaced = true
			}
		}
		p.Exe = exe
	}
	if ns, err := os.Readlink(base + "/ns/mnt"); err == nil && selfNS != "" && ns != selfNS {
		p.ForeignNS = true
	}
	for _, fd := range []string{"0", "1"} {
		if l, err := os.Readlink(base + "/fd/" + fd); err == nil && strings.HasPrefix(l, "socket:") && isNetSocket(l) {
			p.StdSocket = true
		}
	}
	if env, err := os.ReadFile(base + "/environ"); err == nil {
		for _, kv := range strings.Split(string(env), "\x00") {
			if strings.HasPrefix(kv, "LD_PRELOAD=") && len(kv) > len("LD_PRELOAD=") {
				p.LDPreload = strings.TrimPrefix(kv, "LD_PRELOAD=")
			}
		}
	}
	return p, true
}

// netInodes holds socket inodes of TCP/UDP sockets (unix sockets are excluded:
// shells talking over unix sockets are normal, e.g. terminals and IDEs).
var netInodes map[string]bool

func loadNetInodes() {
	netInodes = map[string]bool{}
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"} {
		lines, err := unixutil.ReadLines(f)
		if err != nil {
			continue
		}
		for _, l := range lines[1:] {
			if fs := strings.Fields(l); len(fs) >= 10 {
				netInodes[fs[9]] = true
			}
		}
	}
}

func isNetSocket(link string) bool {
	inode := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
	return netInodes[inode]
}

func (check) Run(env *core.Env) ([]core.Finding, error) {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	loadNetInodes()
	selfNS, _ := os.Readlink("/proc/self/ns/mnt")
	db := unixutil.Packages()

	var procs []lproc
	names := map[int]string{}
	unreadable := 0
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == os.Getpid() {
			continue
		}
		p, ok := readProc(pid, selfNS)
		if !ok {
			continue
		}
		names[pid] = p.Comm
		if p.Exe == "" {
			unreadable++
		}
		procs = append(procs, p)
	}
	if unreadable > 0 && !env.IsAdmin {
		env.Logf("processes: %d procesos de otros usuarios sin acceso a su ejecutable (ejecute con sudo para verlos todos)", unreadable)
	}

	var out []core.Finding
	for _, p := range procs {
		p.ParentComm = names[p.PPID]
		owner := ""
		if p.Exe != "" && !p.ForeignNS {
			if !p.Deleted {
				owner = db.Owner(p.Exe)
				env.Artifacts.Add(p.Exe, "proceso:"+p.Comm)
			} else if !p.Replaced {
				// The deleted image is still readable through /proc.
				env.Artifacts.Add(filepath.Join("/proc", strconv.Itoa(p.PID), "exe"), "proceso-borrado:"+p.Comm)
			}
		}
		if f := assessLinux(p, db.Available(), owner); f != nil {
			out = append(out, *f)
		}
	}
	return out, nil
}
