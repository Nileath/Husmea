package core

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Phase 1 checks collect evidence from the system; phase 2 checks
// (hashes, YARA, VirusTotal) analyze the artifacts gathered in phase 1.
const (
	PhaseCollect = 1
	PhaseAnalyze = 2
)

type Check interface {
	Name() string
	Description() string
	Phase() int
	Run(env *Env) ([]Finding, error)
}

// ErrSkipped signals that a check intentionally did not run (missing input, unsupported...).
type ErrSkipped struct{ Reason string }

func (e ErrSkipped) Error() string { return e.Reason }

type Options struct {
	Deep         bool
	IOCFile      string
	YaraRules    string
	YaraBin      string
	VTEnabled    bool
	VTKey        string
	VTMax        int
	VTPerMinute  int
	MaxHashSize  int64
	CheckTimeout time.Duration
}

type SignatureVerifier interface {
	// Prefetch verifies many files at once (verification can be expensive per call).
	Prefetch(ctx context.Context, paths []string)
	Lookup(ctx context.Context, path string) Signature
}

type Logger func(format string, args ...any)

type Env struct {
	Ctx       context.Context
	Opts      *Options
	Artifacts *Artifacts
	Sig       SignatureVerifier
	IsAdmin   bool
	Log       Logger

	mu    sync.RWMutex
	prior []Finding
}

// PriorFindings returns findings produced by phase-1 checks (available in phase 2).
func (e *Env) PriorFindings() []Finding {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return append([]Finding(nil), e.prior...)
}

func (e *Env) Logf(format string, args ...any) {
	if e.Log != nil {
		e.Log(format, args...)
	}
}

type Hashes struct {
	MD5    string `json:"md5"`
	SHA1   string `json:"sha1"`
	SHA256 string `json:"sha256"`
}

type Artifact struct {
	Path    string
	Sources []string
	hashes  *Hashes
	hashErr error
	hashed  bool
}

// Artifacts is a thread-safe registry of files referenced by checks
// (service binaries, autorun targets, process images...).
type Artifacts struct {
	mu    sync.Mutex
	items map[string]*Artifact
}

func NewArtifacts() *Artifacts { return &Artifacts{items: map[string]*Artifact{}} }

func artifactKey(p string) string { return strings.ToLower(p) }

func (a *Artifacts) Add(path, source string) {
	if path == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	k := artifactKey(path)
	it, ok := a.items[k]
	if !ok {
		it = &Artifact{Path: path}
		a.items[k] = it
	}
	for _, s := range it.Sources {
		if s == source {
			return
		}
	}
	it.Sources = append(it.Sources, source)
}

func (a *Artifacts) List() []Artifact {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]Artifact, 0, len(a.items))
	for _, it := range a.items {
		out = append(out, Artifact{Path: it.Path, Sources: append([]string(nil), it.Sources...)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

var ErrTooLarge = errors.New("archivo demasiado grande para calcular hash")

// Hash computes (and memoizes) MD5/SHA1/SHA256 of a file. maxSize <= 0 means unlimited.
func (a *Artifacts) Hash(path string, maxSize int64) (*Hashes, error) {
	k := artifactKey(path)
	a.mu.Lock()
	it, ok := a.items[k]
	if !ok {
		it = &Artifact{Path: path}
		a.items[k] = it
	}
	if it.hashed {
		h, err := it.hashes, it.hashErr
		a.mu.Unlock()
		return h, err
	}
	a.mu.Unlock()

	h, err := HashFile(path, maxSize)

	a.mu.Lock()
	it.hashes, it.hashErr, it.hashed = h, err, true
	a.mu.Unlock()
	return h, err
}

func HashFile(path string, maxSize int64) (*Hashes, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.IsDir() {
		return nil, errors.New("es un directorio")
	}
	if maxSize > 0 && st.Size() > maxSize {
		return nil, ErrTooLarge
	}
	m, s1, s256 := md5.New(), sha1.New(), sha256.New()
	if _, err := io.Copy(io.MultiWriter(m, s1, s256), f); err != nil {
		return nil, err
	}
	return &Hashes{
		MD5:    hex.EncodeToString(m.Sum(nil)),
		SHA1:   hex.EncodeToString(s1.Sum(nil)),
		SHA256: hex.EncodeToString(s256.Sum(nil)),
	}, nil
}
