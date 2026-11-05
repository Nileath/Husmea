package paths

import (
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"husmea/internal/core"
	"husmea/internal/heuristics"
)

// unixFile is a file found while walking Linux locations.
type unixFile struct {
	Path    string
	Mode    os.FileMode
	Size    int64
	ModTime time.Time
	ELF     bool
	Shebang bool
}

func (f unixFile) executable() bool { return f.Mode&0o111 != 0 }

func evidenceFor(f unixFile, now time.Time) map[string]string {
	ev := map[string]string{
		"tamaño":     humanSize(f.Size),
		"permisos":   f.Mode.String(),
		"modificado": f.ModTime.Format("2006-01-02 15:04"),
	}
	if !f.ModTime.IsZero() && now.Sub(f.ModTime) < 7*24*time.Hour {
		ev["reciente"] = "modificado en los últimos 7 días"
	}
	return ev
}

var bunAddon = regexp.MustCompile(`^\.[0-9a-f]+-[0-9a-f]+\.(node|so)$|^\.bun-\d+-[0-9a-f]+\.(node|so)$`)

func isSharedLib(name string) bool {
	return strings.HasSuffix(name, ".so") || strings.Contains(name, ".so.") || strings.HasSuffix(name, ".node")
}

// assessUnixFile evaluates executables in temporary, device and hidden user locations.
func assessUnixFile(f unixFile, now time.Time) *core.Finding {
	loc := heuristics.ClassifyUnixPath(f.Path)
	name := path.Base(f.Path)
	var reasons []core.Reason
	hiddenLoc := loc.Category == "temphidden"
	switch loc.Category {
	case "temp", "temphidden", "shm", "dev", "run":
		switch {
		case f.ELF && bunAddon.MatchString(name):
			reasons = append(reasons, core.Reason{Severity: core.Low, Text: "módulo nativo extraído por el runtime Bun en " + loc.Label})
		case f.ELF && isSharedLib(name) && loc.Category != "shm" && loc.Category != "dev":
			// Runtimes (JNA, Netty, SQLite, Node addons) extract native libraries to /tmp.
			reasons = append(reasons, core.Reason{Severity: core.Medium, Text: "biblioteca ELF en " + loc.Label, MITRE: []string{"T1074.001"}})
		case f.ELF:
			sev := max(loc.Severity, core.High)
			if hiddenLoc || loc.Category == "dev" {
				sev = core.Critical
			}
			reasons = append(reasons, core.Reason{Severity: sev, Text: "binario ELF en " + loc.Label, MITRE: []string{"T1074.001", "T1105"}})
		case f.executable() && f.Shebang:
			reasons = append(reasons, core.Reason{Severity: lower(loc.Severity), Text: "script ejecutable en " + loc.Label, MITRE: []string{"T1059.004"}})
		case f.executable() && loc.Category != "run":
			reasons = append(reasons, core.Reason{Severity: core.Low, Text: "fichero con permiso de ejecución en " + loc.Label})
		}
	case "homehidden":
		if f.ELF && f.executable() {
			reasons = append(reasons, core.Reason{Severity: loc.Severity, Text: "binario ELF en " + loc.Label, MITRE: []string{"T1564.001"}})
		}
	case "syshidden", "web":
		if f.ELF {
			reasons = append(reasons, core.Reason{Severity: loc.Severity, Text: "binario ELF en " + loc.Label, MITRE: []string{"T1564.001"}})
		}
	}
	if len(reasons) == 0 {
		return nil
	}
	if strings.HasPrefix(name, ".") && !hiddenLoc && reasons[0].Severity > core.Low {
		reasons = append(reasons, core.Reason{Severity: core.Medium, Text: "nombre de fichero oculto", MITRE: []string{"T1564.001"}})
	}
	if r := heuristics.UnixMasquerade(f.Path); r != nil {
		reasons = append(reasons, *r)
	}
	sev, texts, mitre := core.Combine(reasons)
	return &core.Finding{
		Severity: sev,
		Title:    "Fichero sospechoso: " + name,
		Path:     f.Path,
		Evidence: evidenceFor(f, now),
		Reasons:  texts,
		MITRE:    mitre,
		Recommendation: "Compruebe qué proceso lo creó (fecha, propietario 'ls -la', 'lsof " + f.Path + "') y consulte su hash ('sha256sum') en VirusTotal. " +
			"Si es malicioso, finalice los procesos que lo usen, consérvelo para análisis fuera del equipo y elimínelo; revise también la persistencia.",
	}
}

// assessSUIDFile wraps heuristics.AssessSUID into a finding. packaged is nil if unknown.
func assessSUIDFile(f unixFile, packaged *bool, owner string, now time.Time) *core.Finding {
	setuid := f.Mode&os.ModeSetuid != 0
	if !setuid && f.Mode&os.ModeSetgid == 0 {
		return nil
	}
	v := heuristics.AssessSUID(f.Path, setuid, packaged)
	if v == nil {
		return nil
	}
	ev := evidenceFor(f, now)
	if owner != "" {
		ev["paquete"] = owner
	} else if packaged != nil {
		ev["paquete"] = "(ninguno)"
	}
	return &core.Finding{
		Severity: v.Severity,
		Title:    "Binario SUID/SGID anómalo: " + f.Path,
		Path:     f.Path,
		Evidence: ev,
		Reasons:  []string{"[" + v.Severity.Label() + "] " + v.Text},
		MITRE:    []string{"T1548.001"},
		Recommendation: "Un binario con bit SUID se ejecuta con los privilegios de su propietario (normalmente root). Si no es necesario, " +
			"quite el bit con 'chmod u-s,g-s " + f.Path + "' tras verificar su origen; si apareció sin motivo, investigue una posible escalada de privilegios.",
	}
}
