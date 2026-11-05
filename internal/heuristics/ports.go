package heuristics

// SuspiciousPorts maps TCP ports frequently used by RATs, backdoors and
// offensive frameworks. A hit is a hint, not proof: legitimate software can use them.
var SuspiciousPorts = map[uint32]string{
	1337:  "puerto 'leet' usado por backdoors",
	31337: "Back Orifice / backdoors",
	4444:  "Metasploit (handler por defecto)",
	4445:  "Metasploit",
	5555:  "Android ADB / backdoors",
	6666:  "IRC / botnets",
	6667:  "IRC / botnets",
	6697:  "IRC sobre TLS / botnets",
	12345: "NetBus",
	12346: "NetBus",
	1604:  "DarkComet RAT",
	5552:  "njRAT",
	4782:  "Quasar RAT",
	2222:  "DarkComet / backdoors",
	3460:  "Poison Ivy",
	3333:  "minería de criptomonedas (stratum)",
	14444: "minería de criptomonedas (stratum)",
	45560: "minería de criptomonedas (stratum)",
	50050: "Cobalt Strike (team server)",
	9001:  "Tor (ORPort)",
	9050:  "Tor (SOCKS)",
	9150:  "Tor Browser (SOCKS)",
	8848:  "backdoors/RAT",
	20000: "backdoors/RAT",
}
