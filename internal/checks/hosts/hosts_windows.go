//go:build windows

package hosts

import (
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"

	"husmea/internal/core"
	"husmea/internal/winutil"
)

func hostsPath() string {
	return filepath.Join(winutil.SystemRoot(), `System32\drivers\etc\hosts`)
}

func platformChecks(env *core.Env) []core.Finding {
	var out []core.Finding
	out = append(out, assessProxy(readProxy())...)
	out = append(out, assessDNS(readDNS())...)
	return out
}

func readProxy() proxyConfig {
	var p proxyConfig
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE)
	if err != nil {
		return p
	}
	defer k.Close()
	if v, _, err := k.GetIntegerValue("ProxyEnable"); err == nil {
		p.Enabled = v == 1
	}
	p.Server, _, _ = k.GetStringValue("ProxyServer")
	p.PAC, _, _ = k.GetStringValue("AutoConfigURL")
	p.Override, _, _ = k.GetStringValue("ProxyOverride")
	return p
}

func splitServers(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' })
}

func readDNS() []dnsServer {
	var out []dnsServer
	for _, base := range []string{
		`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`,
		`SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces`,
	} {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, base, registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			continue
		}
		ifaces, _ := k.ReadSubKeyNames(-1)
		k.Close()
		for _, iface := range ifaces {
			ik, err := registry.OpenKey(registry.LOCAL_MACHINE, base+`\`+iface, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			if v, _, err := ik.GetStringValue("NameServer"); err == nil {
				for _, s := range splitServers(v) {
					out = append(out, dnsServer{Interface: iface, Server: s, Static: true})
				}
			}
			if v, _, err := ik.GetStringValue("DhcpNameServer"); err == nil {
				for _, s := range splitServers(v) {
					out = append(out, dnsServer{Interface: iface, Server: s})
				}
			}
			ik.Close()
		}
	}
	// Global override (rare, set by some malware).
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`, registry.QUERY_VALUE); err == nil {
		if v, _, err := k.GetStringValue("NameServer"); err == nil {
			for _, s := range splitServers(v) {
				out = append(out, dnsServer{Interface: "global", Server: s, Static: true})
			}
		}
		k.Close()
	}
	return out
}
