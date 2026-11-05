// Package tasks inspects Windows scheduled tasks.
package tasks

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"io"
	"strings"
	"unicode/utf16"

	"husmea/internal/checks/checkutil"
	"husmea/internal/core"
	"husmea/internal/heuristics"
)

const Name = "tasks"

type execAction struct {
	Command   string `xml:"Command"`
	Arguments string `xml:"Arguments"`
	WorkDir   string `xml:"WorkingDirectory"`
}

type triggers struct {
	Inner []struct {
		XMLName xml.Name
	} `xml:",any"`
}

type taskXML struct {
	Author      string       `xml:"RegistrationInfo>Author"`
	Description string       `xml:"RegistrationInfo>Description"`
	URI         string       `xml:"RegistrationInfo>URI"`
	Hidden      string       `xml:"Settings>Hidden"`
	Enabled     string       `xml:"Settings>Enabled"`
	UserID      string       `xml:"Principals>Principal>UserId"`
	RunLevel    string       `xml:"Principals>Principal>RunLevel"`
	Exec        []execAction `xml:"Actions>Exec"`
	ComClassIDs []string     `xml:"Actions>ComHandler>ClassId"`
	Triggers    triggers     `xml:"Triggers"`
}

// Task is a parsed scheduled task definition.
type Task struct {
	Name     string
	Author   string
	Hidden   bool
	Enabled  bool
	UserID   string
	RunLevel string
	Actions  []execAction
	ComIDs   []string
	Triggers []string
}

// decodeXML converts UTF-16 (with BOM) task files to UTF-8.
func decodeXML(b []byte) []byte {
	if len(b) >= 2 && ((b[0] == 0xFF && b[1] == 0xFE) || (b[0] == 0xFE && b[1] == 0xFF)) {
		var order binary.ByteOrder = binary.LittleEndian
		if b[0] == 0xFE {
			order = binary.BigEndian
		}
		b = b[2:]
		u := make([]uint16, len(b)/2)
		for i := range u {
			u[i] = order.Uint16(b[i*2:])
		}
		return []byte(string(utf16.Decode(u)))
	}
	return bytes.TrimPrefix(b, []byte("\xEF\xBB\xBF"))
}

func ParseTask(name string, raw []byte) (*Task, error) {
	dec := xml.NewDecoder(bytes.NewReader(decodeXML(raw)))
	// Content is already UTF-8; ignore the declared encoding (usually UTF-16).
	dec.CharsetReader = func(_ string, r io.Reader) (io.Reader, error) { return r, nil }
	var t taskXML
	if err := dec.Decode(&t); err != nil {
		return nil, err
	}
	task := &Task{
		Name:     name,
		Author:   t.Author,
		Hidden:   strings.EqualFold(strings.TrimSpace(t.Hidden), "true"),
		Enabled:  !strings.EqualFold(strings.TrimSpace(t.Enabled), "false"),
		UserID:   t.UserID,
		RunLevel: t.RunLevel,
		Actions:  t.Exec,
		ComIDs:   t.ComClassIDs,
	}
	if task.Name == "" {
		task.Name = t.URI
	}
	for _, tr := range t.Triggers.Inner {
		task.Triggers = append(task.Triggers, tr.XMLName.Local)
	}
	return task, nil
}

// CommandLine returns the full command executed by an action.
func (a execAction) CommandLine() string {
	c := strings.TrimSpace(a.Command)
	if c != "" && !strings.HasPrefix(c, `"`) && strings.Contains(c, " ") {
		c = `"` + c + `"`
	}
	return strings.TrimSpace(c + " " + a.Arguments)
}

func isMicrosoftTask(t *Task) bool {
	return strings.HasPrefix(strings.ToLower(t.Name), `\microsoft\`)
}

// assess evaluates one exec action of a task.
func assess(t *Task, a execAction, l heuristics.Launch) *core.Finding {
	var extra []core.Reason
	ms := isMicrosoftTask(t)
	l.Vendor = ms
	if t.Hidden && !ms {
		extra = append(extra, core.Reason{Severity: core.Medium, Text: "tarea marcada como oculta", MITRE: []string{"T1053.005", "T1564"}})
	}
	if ms && l.Exe.Path != "" && !heuristics.IsTrustedLocation(l.Exe.Path) {
		extra = append(extra, core.Reason{Severity: core.High, Text: "tarea en la carpeta \\Microsoft\\ que ejecuta un binario fuera de Windows/Program Files", MITRE: []string{"T1053.005", "T1036.004"}})
	}
	if strings.EqualFold(t.RunLevel, "HighestAvailable") && !ms && l.Exe.Path != "" && !heuristics.IsTrustedLocation(l.Exe.Path) {
		extra = append(extra, core.Reason{Severity: core.Low, Text: "se ejecuta con privilegios elevados", MITRE: []string{"T1053.005"}})
	}
	ev := map[string]string{
		"tarea":        t.Name,
		"comando":      a.CommandLine(),
		"autor":        t.Author,
		"usuario":      t.UserID,
		"disparadores": strings.Join(t.Triggers, ", "),
	}
	if !t.Enabled {
		ev["estado"] = "deshabilitada"
	}
	rec := "Revise la tarea en el Programador de tareas (taskschd.msc) o con 'schtasks /query /tn \"" + t.Name + "\" /v /fo list'. " +
		"Si no la reconoce, deshabilítela ('schtasks /change /tn \"" + t.Name + "\" /disable') y analice el ejecutable antes de borrarla."
	f := checkutil.LaunchFinding("Tarea programada sospechosa: "+t.Name, l, extra, ev, core.Low, rec)
	if f != nil {
		if !t.Enabled && f.Severity > core.Low {
			f.Severity--
			f.Reasons = append(f.Reasons, "(severidad reducida: la tarea está deshabilitada)")
		}
		return f
	}
	if ms {
		return nil
	}
	inv := &core.Finding{
		Severity:       core.Info,
		Title:          "Tarea programada de terceros: " + t.Name,
		Path:           l.Exe.Path,
		Evidence:       ev,
		MITRE:          []string{"T1053.005"},
		Recommendation: "Sin indicadores sospechosos. Verifique que corresponde a software instalado por usted.",
	}
	if l.Exe.Sig.Valid() {
		inv.Signer = l.Exe.Sig.SignerName()
	}
	return inv
}
