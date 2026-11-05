package core

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"sort"
	"sync"
	"time"
)

type CheckStatus string

const (
	StatusOK      CheckStatus = "ok"
	StatusError   CheckStatus = "error"
	StatusSkipped CheckStatus = "skipped"
	StatusTimeout CheckStatus = "timeout"
)

type CheckResult struct {
	Name     string        `json:"name"`
	Status   CheckStatus   `json:"status"`
	Message  string        `json:"message,omitempty"`
	Duration time.Duration `json:"duration_ns"`
	Findings int           `json:"findings"`
}

type Runner struct {
	Checks    []Check
	Allowlist *Allowlist
	// OnCheckDone is called (possibly concurrently) after each check finishes.
	OnCheckDone func(CheckResult)
}

type RunOutput struct {
	Results    []CheckResult
	Findings   []Finding
	Suppressed int
}

func (r *Runner) Run(env *Env) RunOutput {
	var out RunOutput
	for _, phase := range []int{PhaseCollect, PhaseAnalyze} {
		var batch []Check
		for _, c := range r.Checks {
			if c.Phase() == phase {
				batch = append(batch, c)
			}
		}
		results, findings := r.runPhase(env, batch)
		out.Results = append(out.Results, results...)
		env.mu.Lock()
		env.prior = append(env.prior, findings...)
		env.mu.Unlock()
		out.Findings = append(out.Findings, findings...)
	}
	if r.Allowlist != nil {
		out.Findings, out.Suppressed = r.Allowlist.Filter(out.Findings)
	}
	SortFindings(out.Findings)
	order := map[string]int{}
	for i, c := range r.Checks {
		order[c.Name()] = i
	}
	sort.SliceStable(out.Results, func(i, j int) bool { return order[out.Results[i].Name] < order[out.Results[j].Name] })
	return out
}

func (r *Runner) runPhase(env *Env, checks []Check) ([]CheckResult, []Finding) {
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		results  []CheckResult
		findings []Finding
	)
	for _, c := range checks {
		wg.Add(1)
		go func(c Check) {
			defer wg.Done()
			res, fs := r.runOne(env, c)
			mu.Lock()
			results = append(results, res)
			findings = append(findings, fs...)
			mu.Unlock()
			if r.OnCheckDone != nil {
				r.OnCheckDone(res)
			}
		}(c)
	}
	wg.Wait()
	return results, findings
}

type checkReturn struct {
	findings []Finding
	err      error
}

func (r *Runner) runOne(parent *Env, c Check) (CheckResult, []Finding) {
	start := time.Now()
	timeout := parent.Opts.CheckTimeout
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(parent.Ctx, timeout)
	defer cancel()

	env := &Env{Ctx: ctx, Opts: parent.Opts, Artifacts: parent.Artifacts, Sig: parent.Sig, IsAdmin: parent.IsAdmin, Log: parent.Log}
	parent.mu.RLock()
	env.prior = parent.prior
	parent.mu.RUnlock()

	done := make(chan checkReturn, 1)
	go func() {
		defer func() {
			if p := recover(); p != nil {
				done <- checkReturn{err: fmt.Errorf("panic: %v\n%s", p, debug.Stack())}
			}
		}()
		fs, err := c.Run(env)
		done <- checkReturn{fs, err}
	}()

	res := CheckResult{Name: c.Name(), Status: StatusOK}
	var fs []Finding
	select {
	case ret := <-done:
		fs = ret.findings
		var skip ErrSkipped
		switch {
		case ret.err == nil:
		case errors.As(ret.err, &skip):
			res.Status, res.Message = StatusSkipped, skip.Reason
		case errors.Is(ret.err, context.DeadlineExceeded):
			res.Status, res.Message = StatusTimeout, "tiempo de ejecución agotado"
		default:
			res.Status, res.Message = StatusError, ret.err.Error()
		}
	case <-ctx.Done():
		res.Status, res.Message = StatusTimeout, "tiempo de ejecución agotado"
		if errors.Is(ctx.Err(), context.Canceled) {
			res.Status, res.Message = StatusError, "cancelado"
		}
	}
	for i := range fs {
		if fs[i].Check == "" {
			fs[i].Check = c.Name()
		}
	}
	res.Duration = time.Since(start)
	res.Findings = len(fs)
	return res, fs
}

func SortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Severity != fs[j].Severity {
			return fs[i].Severity > fs[j].Severity
		}
		if fs[i].Check != fs[j].Check {
			return fs[i].Check < fs[j].Check
		}
		return fs[i].Title < fs[j].Title
	})
}

type Summary struct {
	Counts    map[string]int `json:"counts"`
	Total     int            `json:"total"`
	RiskScore int            `json:"risk_score"`
	RiskLevel string         `json:"risk_level"`
}

func Summarize(fs []Finding) Summary {
	s := Summary{Counts: map[string]int{}}
	for _, n := range severityNames {
		s.Counts[n] = 0
	}
	weights := map[Severity]int{Critical: 40, High: 15, Medium: 5, Low: 1}
	for _, f := range fs {
		s.Counts[f.Severity.String()]++
		s.Total++
		s.RiskScore += weights[f.Severity]
	}
	if s.RiskScore > 100 {
		s.RiskScore = 100
	}
	switch {
	case s.Counts["critical"] > 0:
		s.RiskLevel = "Crítico"
	case s.Counts["high"] > 0:
		s.RiskLevel = "Alto"
	case s.Counts["medium"] > 0:
		s.RiskLevel = "Moderado"
	case s.Counts["low"] > 0:
		s.RiskLevel = "Bajo"
	default:
		s.RiskLevel = "Sin hallazgos relevantes"
	}
	return s
}
