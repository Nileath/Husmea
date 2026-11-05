//go:build windows

package winutil

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"husmea/internal/core"
)

func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
}

func NewVerifier() core.SignatureVerifier { return newPSVerifier(RunPowerShell) }

func IsAdmin() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

func SystemRoot() string {
	if r := os.Getenv("SystemRoot"); r != "" {
		return r
	}
	return `C:\Windows`
}

// SearchDirs returns the directories Windows searches for bare executable names.
func SearchDirs() []string {
	root := SystemRoot()
	dirs := []string{
		filepath.Join(root, "System32"),
		root,
		filepath.Join(root, `System32\Wbem`),
		filepath.Join(root, `System32\WindowsPowerShell\v1.0`),
	}
	return append(dirs, filepath.SplitList(os.Getenv("PATH"))...)
}

// ResolveExecutable turns a bare name into a full path when possible.
func ResolveExecutable(exe string) string {
	return Resolve(exe, SearchDirs(), FileExists)
}

// NormalizeCommand expands variables and fixes registry path prefixes.
func NormalizeCommand(raw string) string {
	return NormalizeImagePath(raw, SystemRoot(), nil)
}

// EnableVirtualTerminal enables ANSI escape sequences in the console; returns false if unsupported.
func EnableVirtualTerminal() bool {
	h := windows.Handle(os.Stdout.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return false
	}
	return windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING) == nil
}

// RegValue reads a registry value of any common type as a string.
func RegValue(k registry.Key, name string) (string, bool) {
	s, typ, err := k.GetStringValue(name)
	if err == nil {
		if typ == registry.EXPAND_SZ {
			s = ExpandEnv(s, nil)
		}
		return s, true
	}
	if ss, _, err := k.GetStringsValue(name); err == nil {
		return strings.Join(ss, " "), true
	}
	if n, _, err := k.GetIntegerValue(name); err == nil {
		return strconv.FormatUint(n, 10), true
	}
	return "", false
}

// RegHiveName returns a printable name for a predefined key.
func RegHiveName(k registry.Key) string {
	switch k {
	case registry.LOCAL_MACHINE:
		return "HKLM"
	case registry.CURRENT_USER:
		return "HKCU"
	case registry.USERS:
		return "HKU"
	case registry.CLASSES_ROOT:
		return "HKCR"
	}
	return "HK?"
}

// OSVersion returns a human-readable Windows version.
func OSVersion() string {
	v := windows.RtlGetVersion()
	name := "Windows"
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE); err == nil {
		if p, _, err := k.GetStringValue("ProductName"); err == nil {
			name = p
		}
		k.Close()
	}
	// ProductName still says "Windows 10" on Windows 11; the build number tells them apart.
	if v.BuildNumber >= 22000 {
		name = strings.Replace(name, "Windows 10", "Windows 11", 1)
	}
	return name + " (build " + strconv.FormatUint(uint64(v.BuildNumber), 10) + ")"
}
