package network

import (
	"strings"
	"testing"

	"husmea/internal/core"
)

func TestAssessNetwork(t *testing.T) {
	signed := core.Signature{Status: "Valid", Signer: "CN=Google LLC"}
	pm := procMeta{PID: 100, Name: "chrome.exe", Exe: `C:\Program Files\Google\Chrome\Application\chrome.exe`}
	if f := assessProcess(pm, []connInfo{{Proto: "tcp", RemoteIP: "142.250.0.1", RemotePort: 443, Status: "ESTABLISHED"}}, signed); f != nil {
		t.Errorf("benign browser reported: %+v", f)
	}

	rat := procMeta{PID: 200, Name: "upd.exe", Exe: `C:\Users\a\AppData\Roaming\upd.exe`}
	f := assessProcess(rat, []connInfo{
		{Proto: "tcp", LocalIP: "0.0.0.0", LocalPort: 4444, Status: "LISTEN"},
		{Proto: "tcp", RemoteIP: "45.33.32.156", RemotePort: 5552, Status: "ESTABLISHED"},
	}, core.Signature{Status: "NotSigned"})
	if f == nil || f.Severity != core.Critical {
		t.Fatalf("rat = %+v", f)
	}
	if !strings.Contains(f.Evidence["conexiones"], "4444") {
		t.Errorf("evidence missing connections: %v", f.Evidence)
	}

	// Private remote addresses on suspicious ports do not count as external C2.
	if f := assessProcess(pm, []connInfo{{Proto: "tcp", RemoteIP: "192.168.1.10", RemotePort: 4444, Status: "ESTABLISHED"}}, signed); f != nil {
		t.Errorf("LAN connection reported: %+v", f)
	}
}

func TestListenersInventory(t *testing.T) {
	procs := map[int32]procMeta{4: {Name: "System"}, 900: {Name: "svchost.exe"}}
	f := listenersInventory([]connInfo{
		{Proto: "tcp", LocalIP: "0.0.0.0", LocalPort: 445, Status: "LISTEN", PID: 4},
		{Proto: "tcp", LocalIP: "0.0.0.0", LocalPort: 135, Status: "LISTEN", PID: 900},
		{Proto: "tcp", RemoteIP: "1.1.1.1", RemotePort: 443, Status: "ESTABLISHED", PID: 900},
	}, procs)
	if f == nil || f.Severity != core.Info || !strings.Contains(f.Title, "2 puertos") {
		t.Errorf("inventory = %+v", f)
	}
}

func TestUnixPolicy(t *testing.T) {
	pm := procMeta{PID: 300, Name: "kswapd", Exe: "/dev/shm/.k"}
	f := assessProcessWith(unixPolicy, pm, []connInfo{{Proto: "tcp", RemoteIP: "45.33.32.156", RemotePort: 443, Status: "ESTABLISHED"}}, core.Signature{})
	if f == nil || f.Severity < core.High {
		t.Errorf("shm process with C2 = %+v", f)
	}
	ok := procMeta{PID: 301, Name: "firefox", Exe: "/usr/lib/firefox/firefox"}
	if f := assessProcessWith(unixPolicy, ok, []connInfo{{Proto: "tcp", RemoteIP: "45.33.32.156", RemotePort: 443, Status: "ESTABLISHED"}}, core.Signature{}); f != nil {
		t.Errorf("browser reported: %+v", f)
	}
}
