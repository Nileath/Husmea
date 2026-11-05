//go:build !windows

package winutil

import (
	"os"
	"os/exec"

	"husmea/internal/core"
)

func hideWindow(*exec.Cmd) {}

func NewVerifier() core.SignatureVerifier { return NopVerifier{} }

func IsAdmin() bool { return os.Geteuid() == 0 }

func EnableVirtualTerminal() bool { return true }
