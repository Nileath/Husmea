//go:build !windows && !linux

package hosts

import "husmea/internal/core"

func hostsPath() string { return "/etc/hosts" }

func platformChecks(*core.Env) []core.Finding { return nil }
