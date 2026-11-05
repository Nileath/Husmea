// Package hosts inspects the hosts file and (on Windows) proxy and DNS settings.
package hosts

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"strings"

	"husmea/internal/core"
)

const Name = "hosts"

type hostEntry struct {
	Line  int
	IP    string
	Hosts []string
}

func parseHosts(b []byte) []hostEntry {
	var out []hostEntry
	sc := bufio.NewScanner(bytes.NewReader(b))
	n := 0
	for sc.Scan() {
		n++
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		out = append(out, hostEntry{Line: n, IP: fields[0], Hosts: fields[1:]})
	}
	return out
}

var securityDomains = []string{
	"windowsupdate.com", "update.microsoft.com", "download.microsoft.com", "wdcp.microsoft.com", "wd.microsoft.com", "smartscreen.microsoft.com",
	"virustotal.com", "kaspersky.com", "kaspersky-labs.com", "avast.com", "avg.com", "eset.com", "malwarebytes.com", "mcafee.com",
	"symantec.com", "norton.com", "bitdefender.com", "sophos.com", "trendmicro.com", "f-secure.com", "pandasecurity.com",
	"avira.com", "sysinternals.com", "hybrid-analysis.com", "any.run",
}

var sensitiveDomains = []string{
	"microsoft.com", "live.com", "office.com", "microsoftonline.com", "google.com", "gmail.com", "facebook.com", "instagram.com",
	"paypal.com", "apple.com", "icloud.com", "amazon.com", "github.com", "twitter.com", "x.com", "linkedin.com", "whatsapp.com",
	"outlook.com", "yahoo.com", "binance.com", "coinbase.com", "steamcommunity.com", "steampowered.com",
}

var telemetryHints = []string{"telemetry", "vortex", "watson", "settings-win", "ads", "adservice", "doubleclick", "analytics"}

func matchesDomain(host string, list []string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	for _, d := range list {
		if h == d || strings.HasSuffix(h, "."+d) {
			return true
		}
	}
	return false
}

func isBanking(host string) bool {
	h := strings.ToLower(host)
	return strings.Contains(h, "bank") || strings.Contains(h, "banco") || strings.Contains(h, "banca")
}

func isTelemetry(host string) bool {
	h := strings.ToLower(host)
	for _, t := range telemetryHints {
		if strings.Contains(h, t) {
			return true
		}
	}
	return false
}

func isBlockIP(ip string) bool {
	p := net.ParseIP(ip)
	return p != nil && (p.IsLoopback() || p.IsUnspecified())
}

// isPublicIP is true for routable unicast addresses (redirections outside the local network).
func isPublicIP(ip string) bool {
	p := net.ParseIP(ip)
	return p != nil && !p.IsLoopback() && !p.IsUnspecified() && !p.IsPrivate() && !p.IsMulticast() &&
		!p.IsLinkLocalUnicast() && !p.IsInterfaceLocalMulticast()
}

func assessHosts(path string, entries []hostEntry) []core.Finding {
	var out []core.Finding
	var custom []string
	for _, e := range entries {
		for _, h := range e.Hosts {
			lh := strings.ToLower(h)
			if lh == "localhost" || lh == "localhost.localdomain" || lh == "ip6-localhost" || lh == "ip6-loopback" || strings.HasSuffix(lh, ".localhost") || lh == "broadcasthost" {
				continue
			}
			line := fmt.Sprintf("línea %d: %s %s", e.Line, e.IP, h)
			sec := matchesDomain(h, securityDomains)
			sens := sec || matchesDomain(h, sensitiveDomains) || isBanking(h)
			switch {
			case sens && !isBlockIP(e.IP):
				out = append(out, core.Finding{
					Severity:    core.Critical,
					Title:       "Archivo hosts redirige un dominio sensible: " + h,
					Description: "El dominio " + h + " se resuelve a " + e.IP + " en lugar de su IP real. Es una técnica típica de phishing/pharming para robar credenciales.",
					Path:        path,
					Evidence:    map[string]string{"entrada": line},
					MITRE:       []string{"T1565.001"},
					Recommendation: "Elimine la línea del fichero hosts (" + editHint + path + "), " + flushHint + ", " +
						"analice el equipo con un antivirus y cambie las contraseñas de ese servicio desde otro dispositivo.",
				})
			case sec:
				out = append(out, core.Finding{
					Severity:       core.High,
					Title:          "Archivo hosts bloquea un dominio de seguridad/actualización: " + h,
					Description:    "El malware suele bloquear dominios de antivirus y de Windows Update para evitar ser detectado o eliminado.",
					Path:           path,
					Evidence:       map[string]string{"entrada": line},
					MITRE:          []string{"T1562.001"},
					Recommendation: "Si no lo añadió usted, elimine la línea del fichero hosts y " + flushHint + ". Luego actualice el sistema y analícelo.",
				})
			case sens && !isTelemetry(h):
				out = append(out, core.Finding{
					Severity:       core.Medium,
					Title:          "Archivo hosts bloquea un dominio conocido: " + h,
					Path:           path,
					Evidence:       map[string]string{"entrada": line},
					MITRE:          []string{"T1562"},
					Recommendation: "Verifique si añadió esta entrada intencionadamente; si no, elimínela.",
				})
			case isPublicIP(e.IP):
				custom = append(custom, line)
			}
		}
	}
	if len(custom) > 0 {
		out = append(out, core.Finding{
			Severity:       core.Low,
			Title:          fmt.Sprintf("Archivo hosts con %d redirecciones a IPs públicas", len(custom)),
			Path:           path,
			Evidence:       map[string]string{"entradas": strings.Join(custom, "\n")},
			MITRE:          []string{"T1565.001"},
			Recommendation: "Normalmente el fichero hosts no contiene redirecciones. Revise que reconoce todas estas entradas (entornos de desarrollo, VPN...).",
		})
	}
	return out
}

// OS-specific wording for recommendations (overridden on Linux).
var (
	editHint  = "como administrador: notepad "
	flushHint = "ejecute 'ipconfig /flushdns'"
	proxyHint = "desactívelo en Configuración > Red e Internet > Proxy"
	dnsHint   = "restablezca la configuración a automática (DHCP) en las propiedades del adaptador"
)

type check struct{}

func New() core.Check { return check{} }

func (check) Name() string        { return Name }
func (check) Description() string { return "Archivo hosts, proxy y servidores DNS" }
func (check) Phase() int          { return core.PhaseCollect }

func (check) Run(env *core.Env) ([]core.Finding, error) {
	path := hostsPath()
	var out []core.Finding
	b, err := os.ReadFile(path)
	if err != nil {
		env.Logf("hosts: no se pudo leer %s: %v", path, err)
	} else {
		out = append(out, assessHosts(path, parseHosts(b))...)
	}
	out = append(out, platformChecks(env)...)
	return out, nil
}
