//go:build windows

package checks

import (
	"husmea/internal/checks/autoruns"
	"husmea/internal/checks/defender"
	"husmea/internal/checks/hashes"
	"husmea/internal/checks/hosts"
	"husmea/internal/checks/network"
	"husmea/internal/checks/paths"
	"husmea/internal/checks/processes"
	"husmea/internal/checks/services"
	"husmea/internal/checks/tasks"
	"husmea/internal/checks/vt"
	"husmea/internal/checks/yara"
	"husmea/internal/core"
)

// All returns every check available on this platform, in display order.
func All() []core.Check {
	return []core.Check{
		services.New(),
		autoruns.New(),
		tasks.New(),
		processes.New(),
		network.New(),
		paths.New(),
		hosts.New(),
		defender.New(),
		hashes.New(),
		yara.New(),
		vt.New(),
	}
}

const PlatformSupported = true
