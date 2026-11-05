package hosts

import (
	"net"
	"sort"
	"strings"

	"husmea/internal/core"
)

var knownResolvers = map[string]string{
	"8.8.8.8": "Google", "8.8.4.4": "Google", "2001:4860:4860::8888": "Google", "2001:4860:4860::8844": "Google",
	"1.1.1.1": "Cloudflare", "1.0.0.1": "Cloudflare", "1.1.1.2": "Cloudflare", "1.0.0.2": "Cloudflare", "1.1.1.3": "Cloudflare", "1.0.0.3": "Cloudflare",
	"2606:4700:4700::1111": "Cloudflare", "2606:4700:4700::1001": "Cloudflare",
	"9.9.9.9": "Quad9", "149.112.112.112": "Quad9", "9.9.9.11": "Quad9",
	"208.67.222.222": "OpenDNS", "208.67.220.220": "OpenDNS", "208.67.222.123": "OpenDNS", "208.67.220.123": "OpenDNS",
	"94.140.14.14": "AdGuard", "94.140.15.15": "AdGuard", "76.76.2.0": "Control D", "76.76.10.0": "Control D",
	"185.228.168.9": "CleanBrowsing", "185.228.169.9": "CleanBrowsing", "4.2.2.1": "Level3", "4.2.2.2": "Level3",
}

type dnsServer struct {
	Interface string
	Server    string
	Static    bool
}

// assessDNS flags statically configured public DNS servers that are not well-known resolvers
// (DNS hijacking by malware such as DNSChanger).
func assessDNS(servers []dnsServer) []core.Finding {
	var out []core.Finding
	var inv []string
	for _, s := range servers {
		kind := "DHCP"
		if s.Static {
			kind = "manual"
		}
		label := s.Server
		if n, ok := knownResolvers[s.Server]; ok {
			label += " (" + n + ")"
		}
		inv = append(inv, label+" ["+kind+"]")
		ip := net.ParseIP(s.Server)
		if !s.Static || ip == nil || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		if _, ok := knownResolvers[s.Server]; ok {
			continue
		}
		out = append(out, core.Finding{
			Severity:       core.Medium,
			Title:          "Servidor DNS manual desconocido: " + s.Server,
			Description:    "Un servidor DNS público no reconocido está configurado manualmente. Algunos malware (p. ej. DNSChanger) cambian el DNS para redirigir el tráfico.",
			Evidence:       map[string]string{"interfaz": s.Interface, "servidor": s.Server},
			MITRE:          []string{"T1565.001"},
			Recommendation: "Si no configuró este DNS (o su empresa/ISP), " + dnsHint + " y revise también la configuración DNS de su router.",
		})
	}
	if len(inv) > 0 {
		sort.Strings(inv)
		inv = dedupe(inv)
		out = append(out, core.Finding{
			Severity:       core.Info,
			Title:          "Inventario: servidores DNS configurados",
			Evidence:       map[string]string{"servidores": strings.Join(inv, "\n")},
			Recommendation: "Compruebe que reconoce estos servidores DNS.",
		})
	}
	return out
}

func dedupe(s []string) []string {
	out := s[:0]
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}

type proxyConfig struct {
	Enabled  bool
	Server   string
	PAC      string
	Override string
}

func assessProxy(p proxyConfig) []core.Finding {
	var out []core.Finding
	if p.Enabled && p.Server != "" {
		sev := core.Medium
		if strings.HasPrefix(p.Server, "127.") || strings.HasPrefix(strings.ToLower(p.Server), "localhost") {
			sev = core.Low // local proxies are common (debuggers, AV web shields) but also used by banking trojans
		}
		out = append(out, core.Finding{
			Severity:       sev,
			Title:          "Proxy del sistema configurado: " + p.Server,
			Description:    "Todo el tráfico web pasa por este proxy. El malware lo usa para interceptar o modificar el tráfico (robo de credenciales, inyección de anuncios).",
			Evidence:       map[string]string{"proxy": p.Server, "excepciones": p.Override},
			MITRE:          []string{"T1090", "T1557"},
			Recommendation: "Si no es el proxy de su empresa o de una herramienta que usa (Fiddler, Burp, antivirus), " + proxyHint + " y analice el equipo.",
		})
	}
	if p.PAC != "" {
		out = append(out, core.Finding{
			Severity:       core.Medium,
			Title:          "Script de configuración automática de proxy (PAC): " + p.PAC,
			Description:    "Un fichero PAC decide qué tráfico pasa por un proxy. Algunos troyanos bancarios lo usan para redirigir solo ciertos dominios.",
			Evidence:       map[string]string{"pac": p.PAC},
			MITRE:          []string{"T1090", "T1557"},
			Recommendation: "Si no corresponde a su organización, " + proxyHint + ".",
		})
	}
	return out
}
