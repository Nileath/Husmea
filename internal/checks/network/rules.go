// Package network inspects listening ports and active connections and the processes owning them.
package network

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"husmea/internal/core"
	"husmea/internal/heuristics"
)

const Name = "network"

type connInfo struct {
	Proto      string
	LocalIP    string
	LocalPort  uint32
	RemoteIP   string
	RemotePort uint32
	Status     string
	PID        int32
}

func (c connInfo) String() string {
	s := fmt.Sprintf("%s %s → %s [%s]", c.Proto, hostPort(c.LocalIP, c.LocalPort), hostPort(c.RemoteIP, c.RemotePort), c.Status)
	if c.Status == "LISTEN" || c.RemoteIP == "" {
		s = fmt.Sprintf("%s %s [%s]", c.Proto, hostPort(c.LocalIP, c.LocalPort), c.Status)
	}
	return s
}

func hostPort(ip string, port uint32) string {
	if ip == "" {
		ip = "*"
	}
	return net.JoinHostPort(ip, strconv.Itoa(int(port)))
}

type procMeta struct {
	PID  int32
	Name string
	Exe  string
}

func isListen(c connInfo) bool { return c.Status == "LISTEN" }

func isWildcard(ip string) bool { return ip == "0.0.0.0" || ip == "::" || ip == "" }

func isPublic(ip string) bool {
	p := net.ParseIP(ip)
	return p != nil && !p.IsLoopback() && !p.IsPrivate() && !p.IsUnspecified() && !p.IsLinkLocalUnicast() && !p.IsMulticast()
}

// pathPolicy adapts path heuristics to the operating system.
type pathPolicy struct {
	classify   func(string) heuristics.Location
	trusted    func(string) bool
	masquerade func(string) *core.Reason
	advice     string
}

var windowsPolicy = pathPolicy{
	classify:   heuristics.ClassifyPath,
	trusted:    heuristics.IsTrustedLocation,
	masquerade: heuristics.Masquerade,
	advice:     "TCPView de Sysinternals ayuda",
}

var unixPolicy = pathPolicy{
	classify:   heuristics.ClassifyUnixPath,
	trusted:    func(p string) bool { return heuristics.ClassifyUnixPath(p).Severity < core.Low },
	masquerade: heuristics.UnixMasquerade,
	advice:     "use 'ss -tunap' y 'lsof -p PID'",
}

// assessProcess evaluates all connections owned by one process.
func assessProcess(pm procMeta, conns []connInfo, sig core.Signature) *core.Finding {
	return assessProcessWith(windowsPolicy, pm, conns, sig)
}

func assessProcessWith(pol pathPolicy, pm procMeta, conns []connInfo, sig core.Signature) *core.Finding {
	var reasons []core.Reason
	var lines []string
	seen := map[string]bool{}
	add := func(r core.Reason) {
		if !seen[r.Text] {
			seen[r.Text] = true
			reasons = append(reasons, r)
		}
	}
	external := false
	listensAll := false
	for _, c := range conns {
		lines = append(lines, c.String())
		if isListen(c) {
			if d, ok := heuristics.SuspiciousPorts[c.LocalPort]; ok {
				add(core.Reason{Severity: core.High, Text: fmt.Sprintf("escuchando en el puerto %d (%s)", c.LocalPort, d), MITRE: []string{"T1571"}})
			}
			if isWildcard(c.LocalIP) && c.Proto == "tcp" {
				listensAll = true
			}
			continue
		}
		if c.RemoteIP != "" && isPublic(c.RemoteIP) {
			external = true
			if d, ok := heuristics.SuspiciousPorts[c.RemotePort]; ok {
				add(core.Reason{Severity: core.High, Text: fmt.Sprintf("conectado a %s (puerto asociado a %s)", hostPort(c.RemoteIP, c.RemotePort), d), MITRE: []string{"T1571", "T1071"}})
			}
		}
	}
	untrusted := pm.Exe != "" && !sig.Valid() && !pol.trusted(pm.Exe)
	if pm.Exe != "" && (external || listensAll) {
		loc := pol.classify(pm.Exe)
		if loc.Severity >= core.Medium && !sig.Valid() {
			add(core.Reason{Severity: core.High, Text: "proceso con actividad de red ejecutándose desde " + loc.Label, MITRE: []string{"T1071"}})
		}
		if r := pol.masquerade(pm.Exe); r != nil {
			add(*r)
		}
	}
	if listensAll && untrusted && sig.Known() {
		add(core.Reason{Severity: core.Medium, Text: "binario sin firma válida aceptando conexiones en todas las interfaces", MITRE: []string{"T1205"}})
	}
	if len(reasons) == 0 {
		return nil
	}
	sev, texts, mitre := core.Combine(reasons)
	sort.Strings(lines)
	if len(lines) > 15 {
		lines = append(lines[:15], fmt.Sprintf("… y %d más", len(lines)-15))
	}
	f := &core.Finding{
		Severity: sev,
		Title:    fmt.Sprintf("Actividad de red sospechosa: %s (PID %d)", pm.Name, pm.PID),
		Path:     pm.Exe,
		Evidence: map[string]string{"pid": strconv.Itoa(int(pm.PID)), "proceso": pm.Name, "conexiones": strings.Join(lines, "\n")},
		Reasons:  texts,
		MITRE:    mitre,
		Recommendation: "Compruebe qué programa es y si debe comunicarse por red (" + pol.advice + "). Si no lo reconoce, " +
			"desconecte el equipo de la red, bloquee el binario/IP en el firewall y analice el fichero. Consulte la IP remota en servicios de reputación (p. ej. AbuseIPDB, VirusTotal).",
	}
	if sig.Known() {
		f.Evidence["firma"] = sig.Status
	}
	if sig.Valid() {
		f.Signer = sig.SignerName()
	}
	return f
}

// listenersInventory builds an informational finding listing all listening ports.
func listenersInventory(conns []connInfo, procs map[int32]procMeta) *core.Finding {
	var lines []string
	for _, c := range conns {
		if !isListen(c) && !(c.Proto == "udp" && c.RemoteIP == "") {
			continue
		}
		lines = append(lines, fmt.Sprintf("%-28s %s (PID %d)", c.String(), procs[c.PID].Name, c.PID))
	}
	if len(lines) == 0 {
		return nil
	}
	sort.Strings(lines)
	return &core.Finding{
		Severity:       core.Info,
		Title:          fmt.Sprintf("Inventario: %d puertos en escucha", len(lines)),
		Evidence:       map[string]string{"puertos": strings.Join(lines, "\n")},
		Recommendation: "Revise que solo estén abiertos los servicios que necesita y que el cortafuegos esté activo.",
	}
}
