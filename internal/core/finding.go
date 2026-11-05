package core

import (
	"encoding/json"
	"fmt"
	"strings"
)

type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var severityNames = []string{"info", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if s < Info || s > Critical {
		return "unknown"
	}
	return severityNames[s]
}

// Label returns the Spanish, user-facing name of the severity.
func (s Severity) Label() string {
	switch s {
	case Critical:
		return "CRÍTICO"
	case High:
		return "ALTO"
	case Medium:
		return "MEDIO"
	case Low:
		return "BAJO"
	default:
		return "INFO"
	}
}

func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

func (s *Severity) UnmarshalJSON(b []byte) error {
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return err
	}
	v, err := ParseSeverity(str)
	if err != nil {
		return err
	}
	*s = v
	return nil
}

func ParseSeverity(s string) (Severity, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	for i, n := range severityNames {
		if n == s {
			return Severity(i), nil
		}
	}
	return Info, fmt.Errorf("severidad desconocida %q (use: %s)", s, strings.Join(severityNames, ", "))
}

// Bump raises the severity by n levels, capped at Critical.
func (s Severity) Bump(n int) Severity {
	r := s + Severity(n)
	if r > Critical {
		return Critical
	}
	return r
}

type Finding struct {
	Check          string            `json:"check"`
	Severity       Severity          `json:"severity"`
	Title          string            `json:"title"`
	Description    string            `json:"description,omitempty"`
	Path           string            `json:"path,omitempty"`
	SHA256         string            `json:"sha256,omitempty"`
	Signer         string            `json:"signer,omitempty"`
	Evidence       map[string]string `json:"evidence,omitempty"`
	Reasons        []string          `json:"reasons,omitempty"`
	Recommendation string            `json:"recommendation,omitempty"`
	MITRE          []string          `json:"mitre,omitempty"`
}

// Reason is a single heuristic hit contributing to a finding.
type Reason struct {
	Severity Severity
	Text     string
	MITRE    []string
}

// Combine merges reasons into an overall severity: the maximum severity,
// escalated one level when two or more independent reasons are at least Medium.
func Combine(reasons []Reason) (Severity, []string, []string) {
	var max Severity
	strong := 0
	var texts, mitre []string
	seen := map[string]bool{}
	for _, r := range reasons {
		if r.Severity > max {
			max = r.Severity
		}
		if r.Severity >= Medium {
			strong++
		}
		texts = append(texts, fmt.Sprintf("[%s] %s", r.Severity.Label(), r.Text))
		for _, m := range r.MITRE {
			if !seen[m] {
				seen[m] = true
				mitre = append(mitre, m)
			}
		}
	}
	if strong >= 2 {
		max = max.Bump(1)
	}
	return max, texts, mitre
}

// Signature describes the Authenticode status of a file.
type Signature struct {
	Status string `json:"status"` // Valid, NotSigned, HashMismatch, NotTrusted, UnknownError, Unknown...
	Signer string `json:"signer,omitempty"`
}

func (s Signature) Known() bool { return s.Status != "" && s.Status != "Unknown" }
func (s Signature) Valid() bool { return s.Status == "Valid" }
func (s Signature) IsMicrosoft() bool {
	return s.Valid() && strings.Contains(s.Signer, "O=Microsoft Corporation")
}

// SignerName extracts the CN from a certificate subject.
func (s Signature) SignerName() string {
	for _, part := range strings.Split(s.Signer, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "CN=") {
			return strings.Trim(strings.TrimPrefix(part, "CN="), `"`)
		}
	}
	return s.Signer
}
