// Package hashes matches collected artifacts against a local list of IOC hashes.
package hashes

import (
	"bufio"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"

	"husmea/internal/core"
)

const Name = "hashes"

var hexRe = regexp.MustCompile(`^[0-9a-fA-F]+$`)

// ParseIOC reads hashes (MD5, SHA1 or SHA256) and optional names. Accepted line formats:
//
//	<hash>
//	<hash>,<name>      <hash>;<name>      <hash> <name>      <name>,<hash>
//
// Lines starting with '#' are comments.
func ParseIOC(r io.Reader) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.FieldsFunc(line, func(r rune) bool { return r == ',' || r == ';' || r == '\t' || r == ' ' || r == '"' })
		hash, name := "", []string{}
		for _, f := range fields {
			if hash == "" && hexRe.MatchString(f) && (len(f) == 32 || len(f) == 40 || len(f) == 64) {
				hash = strings.ToLower(f)
				continue
			}
			name = append(name, f)
		}
		if hash != "" {
			out[hash] = strings.Join(name, " ")
		}
	}
	return out
}

type check struct{}

func New() core.Check { return check{} }

func (check) Name() string { return Name }
func (check) Description() string {
	return "Hashes de los ficheros recopilados contra una lista local de IOCs"
}
func (check) Phase() int { return core.PhaseAnalyze }

func (check) Run(env *core.Env) ([]core.Finding, error) {
	if env.Opts.IOCFile == "" {
		return nil, core.ErrSkipped{Reason: "sin lista de IOCs (use --ioc fichero.txt)"}
	}
	f, err := os.Open(env.Opts.IOCFile)
	if err != nil {
		return nil, err
	}
	iocs := ParseIOC(f)
	f.Close()
	if len(iocs) == 0 {
		return nil, core.ErrSkipped{Reason: "la lista de IOCs no contiene hashes válidos"}
	}
	env.Logf("hashes: %d IOCs cargados, calculando hashes de %d ficheros…", len(iocs), len(env.Artifacts.List()))

	var (
		mu  sync.Mutex
		out []core.Finding
	)
	ForEachHash(env, func(a core.Artifact, h *core.Hashes) {
		for _, v := range []string{h.SHA256, h.SHA1, h.MD5} {
			name, ok := iocs[v]
			if !ok {
				continue
			}
			title := "Fichero coincide con un IOC"
			if name != "" {
				title += ": " + name
			}
			mu.Lock()
			out = append(out, core.Finding{
				Severity:    core.Critical,
				Title:       title,
				Description: "El hash del fichero aparece en la lista de indicadores de compromiso proporcionada.",
				Path:        a.Path,
				SHA256:      h.SHA256,
				Evidence:    map[string]string{"hash_coincidente": v, "origen": strings.Join(a.Sources, ", "), "md5": h.MD5, "sha1": h.SHA1},
				Recommendation: "Trate el equipo como comprometido: desconéctelo de la red, ponga el fichero en cuarentena con su antivirus, " +
					"elimine su persistencia (ver otros hallazgos) y cambie las contraseñas desde un equipo limpio.",
			})
			mu.Unlock()
			return
		}
	})
	return out, env.Ctx.Err()
}

// ForEachHash hashes all existing artifacts concurrently and calls fn for each.
func ForEachHash(env *core.Env, fn func(core.Artifact, *core.Hashes)) {
	arts := env.Artifacts.List()
	ch := make(chan core.Artifact)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for a := range ch {
				h, err := env.Artifacts.Hash(a.Path, env.Opts.MaxHashSize)
				if err == nil {
					fn(a, h)
				}
			}
		}()
	}
	for _, a := range arts {
		if env.Ctx.Err() != nil {
			break
		}
		ch <- a
	}
	close(ch)
	wg.Wait()
}
