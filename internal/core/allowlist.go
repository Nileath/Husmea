package core

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Allowlist suppresses known-good findings. Patterns are case-insensitive and
// support "*" (any sequence of characters, including path separators).
type Allowlist struct {
	Paths   []string `json:"paths"`
	Hashes  []string `json:"hashes"`
	Signers []string `json:"signers"`
	Titles  []string `json:"titles"`

	pathRe  []*regexp.Regexp
	titleRe []*regexp.Regexp
}

func LoadAllowlist(path string) (*Allowlist, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var a Allowlist
	if err := json.Unmarshal(b, &a); err != nil {
		return nil, fmt.Errorf("allowlist %s: %w", path, err)
	}
	a.compile()
	return &a, nil
}

func NewAllowlist(paths, hashes, signers, titles []string) *Allowlist {
	a := &Allowlist{Paths: paths, Hashes: hashes, Signers: signers, Titles: titles}
	a.compile()
	return a
}

func globToRegexp(g string) *regexp.Regexp {
	parts := strings.Split(g, "*")
	for i, p := range parts {
		parts[i] = regexp.QuoteMeta(p)
	}
	return regexp.MustCompile("(?i)^" + strings.Join(parts, ".*") + "$")
}

func (a *Allowlist) compile() {
	a.pathRe, a.titleRe = nil, nil
	for _, p := range a.Paths {
		a.pathRe = append(a.pathRe, globToRegexp(p))
	}
	for _, t := range a.Titles {
		a.titleRe = append(a.titleRe, globToRegexp(t))
	}
}

func (a *Allowlist) Match(f Finding) bool {
	if f.Path != "" {
		for _, re := range a.pathRe {
			if re.MatchString(f.Path) {
				return true
			}
		}
	}
	if f.SHA256 != "" {
		for _, h := range a.Hashes {
			if strings.EqualFold(h, f.SHA256) {
				return true
			}
		}
	}
	if f.Signer != "" {
		for _, s := range a.Signers {
			if s != "" && strings.Contains(strings.ToLower(f.Signer), strings.ToLower(s)) {
				return true
			}
		}
	}
	for _, re := range a.titleRe {
		if re.MatchString(f.Title) {
			return true
		}
	}
	return false
}

func (a *Allowlist) Filter(fs []Finding) ([]Finding, int) {
	out := fs[:0:0]
	n := 0
	for _, f := range fs {
		if a.Match(f) {
			n++
			continue
		}
		out = append(out, f)
	}
	return out, n
}
