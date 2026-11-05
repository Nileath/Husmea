//go:build windows

package winutil

import (
	"context"

	"husmea/internal/core"
	"husmea/internal/heuristics"
)

// CommandRef is a command line found in a persistence location, resolved to files on disk.
type CommandRef struct {
	Raw        string
	Normalized string
	Parsed     heuristics.ParsedCommand
	Exe        string
	Exists     bool
	// Payload is the script/DLL executed through a host binary (rundll32, wscript...).
	Payload       string
	PayloadExists bool
}

func ParseRegistryCommand(raw string) CommandRef {
	n := NormalizeCommand(raw)
	p := heuristics.ParseCommandLine(n, FileExists)
	exe := ResolveExecutable(ExpandEnv(p.Exe, nil))
	ref := CommandRef{Raw: raw, Normalized: n, Parsed: p, Exe: exe, Exists: FileExists(exe)}
	if pl := heuristics.Payload(exe, ExpandEnv(p.Args, nil)); pl != "" {
		ref.Payload = pl
		ref.PayloadExists = FileExists(pl)
	}
	return ref
}

// Files returns the on-disk files referenced by the command (for signature prefetch / hashing).
func (c CommandRef) Files() []string {
	var out []string
	if c.Exe != "" {
		out = append(out, c.Exe)
	}
	if c.Payload != "" {
		out = append(out, c.Payload)
	}
	return out
}

// Launch builds the heuristics input, looking up signatures with v.
func (c CommandRef) Launch(ctx context.Context, v core.SignatureVerifier) heuristics.Launch {
	l := heuristics.Launch{Exe: heuristics.ExeRef{Path: c.Exe, Exists: c.Exists, CommandLine: c.Normalized}}
	if c.Exists {
		l.Exe.Sig = v.Lookup(ctx, c.Exe)
	}
	if c.Payload != "" {
		p := &heuristics.ExeRef{Path: c.Payload, Exists: c.PayloadExists}
		if c.PayloadExists {
			p.Sig = v.Lookup(ctx, c.Payload)
		}
		l.Payload = p
	}
	return l
}
