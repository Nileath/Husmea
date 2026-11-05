//go:build !windows && !linux

package checks

import (
	"husmea/internal/checks/hashes"
	"husmea/internal/checks/hosts"
	"husmea/internal/checks/vt"
	"husmea/internal/checks/yara"
	"husmea/internal/core"
)

// All returns the checks available on this platform. Linux/macOS support is
// limited for now: only platform-independent checks are included.
func All() []core.Check {
	return []core.Check{
		hosts.New(),
		hashes.New(),
		yara.New(),
		vt.New(),
	}
}

const PlatformSupported = false
