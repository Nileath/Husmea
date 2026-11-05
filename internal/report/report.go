// Package report renders scan results as console text, JSON and HTML.
package report

import (
	"encoding/json"
	"os"
	"time"

	"husmea/internal/core"
)

type Meta struct {
	Tool     string    `json:"tool"`
	Version  string    `json:"version"`
	Host     string    `json:"host"`
	OS       string    `json:"os"`
	User     string    `json:"user"`
	IsAdmin  bool      `json:"is_admin"`
	Started  time.Time `json:"started"`
	Duration string    `json:"duration"`
	Online   bool      `json:"online"`
}

type Report struct {
	Meta       Meta               `json:"meta"`
	Summary    core.Summary       `json:"summary"`
	Checks     []core.CheckResult `json:"checks"`
	Findings   []core.Finding     `json:"findings"`
	Suppressed int                `json:"suppressed_by_allowlist"`
}

func New(meta Meta, out core.RunOutput) *Report {
	fs := out.Findings
	if fs == nil {
		fs = []core.Finding{}
	}
	return &Report{Meta: meta, Summary: core.Summarize(fs), Checks: out.Results, Findings: fs, Suppressed: out.Suppressed}
}

func (r *Report) WriteJSON(path string) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}
