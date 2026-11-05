//go:build linux

package winutil

import (
	"os"
	"strings"
)

// OSVersion returns the distribution name and kernel release.
func OSVersion() string {
	name := "Linux"
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(l, "PRETTY_NAME="); ok {
				name = strings.Trim(v, `"`)
			}
		}
	}
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		name += " (kernel " + strings.TrimSpace(string(b)) + ")"
	}
	return name
}
