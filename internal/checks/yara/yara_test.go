package yara

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"husmea/internal/core"
)

func TestParseOutput(t *testing.T) {
	out := parseOutput([]byte("Rule_A C:\\x\\a b.exe\nRule_B C:\\x\\a b.exe\nwarning: slow rule\nRule_C [tag1] /tmp/z\n\n"))
	if len(out[`C:\x\a b.exe`]) != 2 || len(out["/tmp/z"]) != 1 {
		t.Errorf("parseOutput = %v", out)
	}
}

func TestRunWithFakeYara(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a shell script as fake yara")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "sample.bin")
	_ = os.WriteFile(target, []byte("MZ..."), 0o600)
	rules := filepath.Join(dir, "rules")
	_ = os.MkdirAll(rules, 0o700)
	_ = os.WriteFile(filepath.Join(rules, "r.yar"), []byte("rule X { condition: true }"), 0o600)

	// Fake classic yara: prints "Evil_Rule <path>" for every path in the scan list (last argument).
	fake := filepath.Join(dir, "yara")
	script := "#!/bin/sh\nfor last; do :; done\nwhile read -r p; do echo \"Evil_Rule $p\"; done < \"$last\"\n"
	if err := os.WriteFile(fake, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}

	env := &core.Env{Ctx: context.Background(), Opts: &core.Options{YaraRules: rules, YaraBin: fake}, Artifacts: core.NewArtifacts()}
	env.Artifacts.Add(target, "test")
	env.Artifacts.Add(filepath.Join(dir, "missing.exe"), "test")
	fs, err := New().Run(env)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].Path != target || fs[0].Severity != core.High {
		t.Errorf("findings = %+v", fs)
	}
}

func TestSkipWithoutRules(t *testing.T) {
	env := &core.Env{Ctx: context.Background(), Opts: &core.Options{}, Artifacts: core.NewArtifacts()}
	_, err := New().Run(env)
	var skip core.ErrSkipped
	if !errors.As(err, &skip) {
		t.Errorf("err = %v", err)
	}
}
