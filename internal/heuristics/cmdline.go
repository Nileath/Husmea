package heuristics

import (
	"regexp"
	"strings"

	"husmea/internal/core"
)

var launchExts = []string{".exe", ".com", ".bat", ".cmd", ".scr", ".pif", ".vbs", ".js", ".ps1", ".hta", ".msi", ".cpl", ".dll"}

// ParsedCommand is the result of splitting a Windows command line.
type ParsedCommand struct {
	Exe  string
	Args string
	// UnquotedSpaces is true when the executable path contains spaces but is
	// not quoted (potential "unquoted service path" privilege escalation).
	UnquotedSpaces bool
}

// ParseCommandLine extracts the executable and arguments from a Windows command line.
// exists (optional) is used to disambiguate unquoted paths with spaces.
func ParseCommandLine(cmd string, exists func(string) bool) ParsedCommand {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return ParsedCommand{}
	}
	if cmd[0] == '"' {
		if end := strings.IndexByte(cmd[1:], '"'); end >= 0 {
			return ParsedCommand{Exe: cmd[1 : end+1], Args: strings.TrimSpace(cmd[end+2:])}
		}
		return ParsedCommand{Exe: strings.Trim(cmd, `"`)}
	}
	tokens := strings.Split(cmd, " ")
	// Prefer the shortest prefix that exists on disk, then the shortest with an executable extension.
	if exists != nil {
		for i := 1; i <= len(tokens); i++ {
			cand := strings.Join(tokens[:i], " ")
			if contains(launchExts, Ext(cand)) && exists(cand) {
				return ParsedCommand{Exe: cand, Args: strings.TrimSpace(strings.Join(tokens[i:], " ")), UnquotedSpaces: i > 1}
			}
		}
	}
	for i := 1; i <= len(tokens); i++ {
		cand := strings.Join(tokens[:i], " ")
		if contains(launchExts, Ext(cand)) {
			return ParsedCommand{Exe: cand, Args: strings.TrimSpace(strings.Join(tokens[i:], " ")), UnquotedSpaces: i > 1}
		}
	}
	return ParsedCommand{Exe: tokens[0], Args: strings.TrimSpace(strings.Join(tokens[1:], " "))}
}

type cmdRule struct {
	re    *regexp.Regexp
	sev   core.Severity
	text  string
	mitre []string
}

func rule(expr string, sev core.Severity, text string, mitre ...string) cmdRule {
	return cmdRule{regexp.MustCompile(`(?i)` + expr), sev, text, mitre}
}

const ps = `(powershell|pwsh)(\.exe)?\b`

var cmdRules = []cmdRule{
	rule(ps+`.*\s-(e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\s+[a-z0-9+/=]{16,}`, core.High, "PowerShell con comando codificado en Base64 (-EncodedCommand)", "T1059.001", "T1027"),
	rule(ps+`.*(-w(indowstyle)?\s+h(idden)?\b)`, core.Medium, "PowerShell con ventana oculta", "T1564.003"),
	rule(ps+`.*(iex\b|invoke-expression|downloadstring|downloadfile|downloaddata|invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b|net\.webclient|start-bitstransfer)`, core.High, "PowerShell descargando y/o ejecutando código remoto", "T1059.001", "T1105"),
	rule(ps+`.*frombase64string`, core.High, "PowerShell decodificando Base64 en línea", "T1027", "T1140"),
	rule(ps+`.*-(ep|exec|executionpolicy)\s+(bypass|unrestricted)`, core.Low, "PowerShell omitiendo la política de ejecución", "T1059.001"),
	rule(`mshta(\.exe)?\b.*(https?:|javascript:|vbscript:|\\\\)`, core.High, "mshta ejecutando contenido remoto o script en línea", "T1218.005"),
	rule(`rundll32(\.exe)?\b.*javascript:`, core.Critical, "rundll32 ejecutando JavaScript (técnica fileless)", "T1218.011"),
	rule(`rundll32(\.exe)?\b.*\\(appdata|temp|users\\public|programdata|downloads)\\`, core.High, "rundll32 cargando una DLL desde una ruta escribible por el usuario", "T1218.011"),
	rule(`regsvr32(\.exe)?\b.*(/i:\s*https?:|scrobj\.dll)`, core.High, "regsvr32 ejecutando scriptlet (Squiblydoo)", "T1218.010"),
	rule(`certutil(\.exe)?\b.*(-urlcache|-verifyctl|-decode|-decodehex)`, core.High, "certutil usado para descargar o decodificar ficheros", "T1105", "T1140"),
	rule(`bitsadmin(\.exe)?\b.*(/transfer|/addfile|/setnotifycmdline)`, core.High, "bitsadmin descargando ficheros o ejecutando comandos", "T1197"),
	rule(`msiexec(\.exe)?\b.*(/i|/package)\s*https?:`, core.High, "msiexec instalando un paquete remoto", "T1218.007"),
	rule(`(wscript|cscript)(\.exe)?\b.*\\(appdata|temp|users\\public|programdata|downloads|startup)\\`, core.High, "Windows Script Host ejecutando un script desde ruta de usuario", "T1059.005"),
	rule(`(wscript|cscript)(\.exe)?\b.*//e:(jscript|vbscript)`, core.High, "Windows Script Host forzando motor de script", "T1059.005"),
	rule(`\b(curl|wget)(\.exe)?\b.*https?://.*(\||&&|-o\s)`, core.Medium, "descarga de fichero desde la línea de comandos", "T1105"),
	rule(`https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`, core.High, "URL apuntando directamente a una dirección IP", "T1105"),
	rule(`https?://`, core.Medium, "la línea de comandos contiene una URL", "T1105"),
	rule(`\bcmd(\.exe)?\s+/[ck]\b.*(powershell|mshta|wscript|cscript|certutil|bitsadmin|curl)`, core.Medium, "cmd encadenando herramientas de doble uso (LOLBins)", "T1059.003"),
	rule(`schtasks(\.exe)?\b.*/create`, core.Medium, "creación de tareas programadas desde la línea de comandos", "T1053.005"),
	rule(`vssadmin(\.exe)?\b.*delete\s+shadows|wmic(\.exe)?\b.*shadowcopy\s+delete|bcdedit(\.exe)?\b.*recoveryenabled\s+no`, core.Critical, "borrado de copias de seguridad / recuperación (típico de ransomware)", "T1490"),
	rule(`[a-z0-9+/]{200,}={0,2}`, core.Medium, "cadena larga tipo Base64 en la línea de comandos", "T1027"),
}

// AssessCommandLine applies LOLBin / living-off-the-land heuristics to a full command line.
func AssessCommandLine(cmd string) []core.Reason {
	var out []core.Reason
	seenURL := false
	for _, r := range cmdRules {
		if !r.re.MatchString(cmd) {
			continue
		}
		// Generic URL rule is redundant if a more specific one already matched.
		if r.text == "la línea de comandos contiene una URL" && seenURL {
			continue
		}
		if strings.Contains(r.re.String(), "https?:") {
			seenURL = true
		}
		out = append(out, core.Reason{Severity: r.sev, Text: r.text, MITRE: r.mitre})
	}
	return out
}

var officeApps = []string{"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "mspub.exe", "onenote.exe", "visio.exe", "acrord32.exe", "acrobat.exe", "foxitreader.exe", "hwp.exe"}
var shellChildren = []string{"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msbuild.exe", "installutil.exe", "schtasks.exe", "wmic.exe"}

// expectedParents lists the only legitimate parent names for critical system processes.
var expectedParents = map[string][]string{
	"svchost.exe":   {"services.exe", "msmpeng.exe"},
	"lsass.exe":     {"wininit.exe"},
	"services.exe":  {"wininit.exe"},
	"lsaiso.exe":    {"wininit.exe"},
	"wininit.exe":   {"smss.exe"},
	"winlogon.exe":  {"smss.exe"},
	"csrss.exe":     {"smss.exe"},
	"spoolsv.exe":   {"services.exe"},
	"taskhostw.exe": {"svchost.exe"},
}

// ParentChild flags anomalous process ancestry. parent may be "" when unknown
// (smss children exit, so orphans are expected for some system processes).
func ParentChild(parent, child string) *core.Reason {
	p, c := strings.ToLower(parent), strings.ToLower(child)
	if contains(officeApps, p) && contains(shellChildren, c) {
		return &core.Reason{Severity: core.High, Text: "aplicación ofimática/lector PDF lanzó " + c + " (" + p + " → " + c + ")", MITRE: []string{"T1204.002", "T1566.001"}}
	}
	if (p == "w3wp.exe" || p == "httpd.exe" || p == "nginx.exe" || p == "tomcat.exe" || p == "sqlservr.exe") && contains(shellChildren, c) {
		return &core.Reason{Severity: core.High, Text: "servidor web/BD lanzó un intérprete de comandos (posible webshell)", MITRE: []string{"T1505.003"}}
	}
	if exp, ok := expectedParents[c]; ok && p != "" && !contains(exp, p) {
		return &core.Reason{Severity: core.High, Text: "proceso del sistema " + c + " con padre inesperado " + p, MITRE: []string{"T1036", "T1055"}}
	}
	return nil
}

var payloadHosts = map[string]bool{"rundll32.exe": true, "regsvr32.exe": true, "wscript.exe": true, "cscript.exe": true, "mshta.exe": true, "powershell.exe": true, "pwsh.exe": true, "cmd.exe": true}

var fileArgRe = regexp.MustCompile(`(?i)("([a-z]:\\[^"]+|\\\\[^"]+)"|([a-z]:\\[^\s,"]+|\\\\[^\s,"]+))`)

// Payload returns the file actually executed when exe is a script host or
// proxy binary (e.g. the DLL passed to rundll32, the .vbs passed to wscript).
func Payload(exe, args string) string {
	if !payloadHosts[strings.ToLower(BaseName(exe))] {
		return ""
	}
	for _, m := range fileArgRe.FindAllStringSubmatch(args, -1) {
		cand := m[2]
		if cand == "" {
			cand = m[3]
		}
		if IsPE(cand) || IsScript(cand) {
			return cand
		}
	}
	return ""
}
