package winutil

import (
	"context"
	"encoding/json"
	"strings"
	"sync"

	"husmea/internal/core"
)

const sigScript = `
$paths = Get-Content -Raw -Encoding UTF8 -LiteralPath $InputFile | ConvertFrom-Json
$out = foreach ($p in $paths) {
  try {
    $s = Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop
    $n = ''
    if ($s.SignerCertificate) { $n = $s.SignerCertificate.Subject }
    [pscustomobject]@{ p = $p; s = [string]$s.Status; n = $n }
  } catch {
    [pscustomobject]@{ p = $p; s = 'Unknown'; n = '' }
  }
}
ConvertTo-Json -Compress -InputObject @($out)
`

type sigRow struct {
	P string `json:"p"`
	S string `json:"s"`
	N string `json:"n"`
}

// PSVerifier verifies Authenticode signatures (embedded and catalog) in batches
// through Get-AuthenticodeSignature and caches the results.
type PSVerifier struct {
	mu    sync.Mutex
	cache map[string]core.Signature
	run   func(ctx context.Context, script string, input []byte) ([]byte, error)
	// batchMu serializes PowerShell invocations to avoid spawning many at once.
	batchMu sync.Mutex
}

func newPSVerifier(run func(ctx context.Context, script string, input []byte) ([]byte, error)) *PSVerifier {
	return &PSVerifier{cache: map[string]core.Signature{}, run: run}
}

func sigKey(p string) string { return strings.ToLower(p) }

func (v *PSVerifier) Prefetch(ctx context.Context, paths []string) {
	var todo []string
	seen := map[string]bool{}
	v.mu.Lock()
	for _, p := range paths {
		k := sigKey(p)
		if _, ok := v.cache[k]; ok || seen[k] || p == "" {
			continue
		}
		seen[k] = true
		todo = append(todo, p)
	}
	v.mu.Unlock()
	if len(todo) == 0 {
		return
	}
	v.batchMu.Lock()
	defer v.batchMu.Unlock()
	const chunk = 300
	for i := 0; i < len(todo); i += chunk {
		end := min(i+chunk, len(todo))
		v.verifyBatch(ctx, todo[i:end])
	}
}

func (v *PSVerifier) verifyBatch(ctx context.Context, paths []string) {
	results := map[string]core.Signature{}
	in, _ := json.Marshal(paths)
	out, err := v.run(ctx, sigScript, in)
	if err == nil {
		var rows []sigRow
		if json.Unmarshal(out, &rows) == nil {
			for _, r := range rows {
				results[sigKey(r.P)] = core.Signature{Status: r.S, Signer: r.N}
			}
		}
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	for _, p := range paths {
		k := sigKey(p)
		if s, ok := results[k]; ok {
			v.cache[k] = s
		} else if ctx.Err() == nil {
			v.cache[k] = core.Signature{Status: "Unknown"}
		}
	}
}

func (v *PSVerifier) Lookup(ctx context.Context, path string) core.Signature {
	if path == "" {
		return core.Signature{Status: "Unknown"}
	}
	k := sigKey(path)
	v.mu.Lock()
	s, ok := v.cache[k]
	v.mu.Unlock()
	if ok {
		return s
	}
	v.Prefetch(ctx, []string{path})
	v.mu.Lock()
	defer v.mu.Unlock()
	if s, ok := v.cache[k]; ok {
		return s
	}
	return core.Signature{Status: "Unknown"}
}

// NopVerifier is used on platforms without Authenticode support.
type NopVerifier struct{}

func (NopVerifier) Prefetch(context.Context, []string) {}
func (NopVerifier) Lookup(context.Context, string) core.Signature {
	return core.Signature{Status: "Unknown"}
}
