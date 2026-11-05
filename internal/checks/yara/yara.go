// Package yara scans collected artifacts with YARA rules using an external yara / yara-x binary.
package yara

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"husmea/internal/core"
)

const Name = "yara"

type check struct{}

func New() core.Check { return check{} }

func (check) Name() string { return Name }
func (check) Description() string {
	return "Escaneo de ficheros recopilados con reglas YARA (binario yara/yr externo)"
}
func (check) Phase() int { return core.PhaseAnalyze }

func findBinary(explicit string) (string, error) {
	if explicit != "" {
		if _, err := os.Stat(explicit); err != nil {
			return "", err
		}
		return explicit, nil
	}
	names := []string{"yr", "yara64", "yara"}
	for _, n := range names {
		if p, err := exec.LookPath(n); err == nil {
			return p, nil
		}
	}
	// Also look next to our own executable.
	if self, err := os.Executable(); err == nil {
		dir := filepath.Dir(self)
		for _, n := range names {
			p := filepath.Join(dir, n)
			if runtime.GOOS == "windows" {
				p += ".exe"
			}
			if _, err := os.Stat(p); err == nil {
				return p, nil
			}
		}
	}
	return "", errors.New("no se encontró yara ni yara-x (yr) en el PATH; indíquelo con --yara-bin")
}

func isYaraX(bin string) bool {
	b := strings.ToLower(filepath.Base(bin))
	return strings.HasPrefix(b, "yr")
}

// ruleFiles returns the rule files for classic yara (a file, or every .yar/.yara in a directory).
func ruleFiles(path string) ([]string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return []string{path}, nil
	}
	var out []string
	err = filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if e := strings.ToLower(filepath.Ext(p)); e == ".yar" || e == ".yara" {
				out = append(out, p)
			}
		}
		return nil
	})
	if len(out) == 0 {
		return nil, fmt.Errorf("no hay ficheros .yar/.yara en %s", path)
	}
	return out, err
}

// parseOutput parses "RuleName target" lines produced by yara and yara-x.
func parseOutput(b []byte) map[string][]string {
	out := map[string][]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		i := strings.IndexByte(line, ' ')
		if i <= 0 || strings.HasPrefix(line, "error") || strings.HasPrefix(line, "warning") {
			continue
		}
		rule, target := line[:i], strings.TrimSpace(line[i+1:])
		// Classic yara with -g/-m adds "[tags] [meta]" before the path; strip bracket groups.
		for strings.HasPrefix(target, "[") {
			if j := strings.Index(target, "] "); j >= 0 {
				target = target[j+2:]
			} else {
				break
			}
		}
		out[target] = append(out[target], rule)
	}
	return out
}

func (check) Run(env *core.Env) ([]core.Finding, error) {
	if env.Opts.YaraRules == "" {
		return nil, core.ErrSkipped{Reason: "sin reglas YARA (use --yara-rules fichero_o_directorio)"}
	}
	bin, err := findBinary(env.Opts.YaraBin)
	if err != nil {
		return nil, core.ErrSkipped{Reason: err.Error()}
	}
	var targets []string
	for _, a := range env.Artifacts.List() {
		if st, err := os.Stat(a.Path); err == nil && st.Mode().IsRegular() {
			targets = append(targets, a.Path)
		}
	}
	if len(targets) == 0 {
		return nil, nil
	}
	env.Logf("yara: analizando %d ficheros con %s…", len(targets), filepath.Base(bin))

	matches, err := scan(env.Ctx, bin, env.Opts.YaraRules, targets)
	if err != nil {
		return nil, err
	}
	sources := map[string][]string{}
	for _, a := range env.Artifacts.List() {
		sources[strings.ToLower(a.Path)] = a.Sources
	}
	var out []core.Finding
	for path, rules := range matches {
		sort.Strings(rules)
		out = append(out, core.Finding{
			Severity:    core.High,
			Title:       "Coincidencia YARA en " + filepath.Base(path) + ": " + strings.Join(rules, ", "),
			Description: "El fichero coincide con reglas YARA. Revise la descripción de las reglas: algunas son informativas y otras indican malware concreto.",
			Path:        path,
			Evidence:    map[string]string{"reglas": strings.Join(rules, "\n"), "origen": strings.Join(sources[strings.ToLower(path)], ", ")},
			Recommendation: "Consulte el hash del fichero en VirusTotal y analícelo con su antivirus. Si la regla identifica una familia de malware, " +
				"ponga el fichero en cuarentena y elimine su persistencia.",
		})
	}
	return out, nil
}

func scan(ctx context.Context, bin, rules string, targets []string) (map[string][]string, error) {
	list, err := os.CreateTemp("", "husmea-yara-*.txt")
	if err != nil {
		return nil, err
	}
	defer os.Remove(list.Name())
	_, _ = list.WriteString(strings.Join(targets, "\n") + "\n")
	list.Close()

	var args []string
	if isYaraX(bin) {
		// yr accepts a directory of rules directly.
		args = []string{"scan", "--disable-console-logs", "--scan-list", rules, list.Name()}
	} else {
		rf, err := ruleFiles(rules)
		if err != nil {
			return nil, err
		}
		args = append([]string{"-w", "--scan-list"}, rf...)
		args = append(args, list.Name())
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	// Unreadable files make the scanner exit non-zero; only fail when nothing was produced.
	if err := cmd.Run(); err != nil && stdout.Len() == 0 {
		return nil, fmt.Errorf("%s: %v: %s", filepath.Base(bin), err, strings.TrimSpace(stderr.String()))
	}
	return parseOutput(stdout.Bytes()), nil
}
