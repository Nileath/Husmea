package hosts

import (
	"testing"

	"husmea/internal/core"
)

const sampleHosts = `# Copyright (c) Microsoft
127.0.0.1       localhost
::1             localhost
ff02::1 ip6-allnodes
0.0.0.0 vortex.data.microsoft.com
127.0.0.1 www.virustotal.com virustotal.com   # blocked
185.10.10.10 www.mibanco.es
192.168.1.20 nas.local
203.0.113.7 dev.example.org
`

func TestHosts(t *testing.T) {
	entries := parseHosts([]byte(sampleHosts))
	if len(entries) != 8 {
		t.Fatalf("entries = %d", len(entries))
	}
	fs := assessHosts("hosts", entries)
	bySev := map[core.Severity]int{}
	for _, f := range fs {
		bySev[f.Severity]++
	}
	// virustotal x2 -> high, mibanco -> critical, dev.example.org -> low aggregate; telemetry & LAN ignored.
	if bySev[core.Critical] != 1 || bySev[core.High] != 2 || bySev[core.Low] != 1 || bySev[core.Medium] != 0 || len(fs) != 4 {
		for _, f := range fs {
			t.Logf("%s %s", f.Severity, f.Title)
		}
		t.Errorf("unexpected severities: %v", bySev)
	}
}

func TestDNSAndProxy(t *testing.T) {
	fs := assessDNS([]dnsServer{
		{Interface: "a", Server: "192.168.1.1"},
		{Interface: "b", Server: "8.8.8.8", Static: true},
		{Interface: "c", Server: "93.184.216.34", Static: true},
	})
	if len(fs) != 2 || fs[0].Severity != core.Medium || fs[1].Severity != core.Info {
		t.Errorf("dns = %+v", fs)
	}
	if fs := assessProxy(proxyConfig{Enabled: false, Server: "1.2.3.4:8080"}); len(fs) != 0 {
		t.Errorf("disabled proxy reported: %+v", fs)
	}
	fs = assessProxy(proxyConfig{Enabled: true, Server: "1.2.3.4:8080", PAC: "http://x/p.pac"})
	if len(fs) != 2 || fs[0].Severity != core.Medium {
		t.Errorf("proxy = %+v", fs)
	}
}
