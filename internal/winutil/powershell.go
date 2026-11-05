package winutil

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unicode/utf16"
)

// PowerShellPath returns the absolute path of Windows PowerShell (avoids PATH hijacking).
func PowerShellPath() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, `System32\WindowsPowerShell\v1.0\powershell.exe`)
}

func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func encodePS(script string) string {
	u := utf16.Encode([]rune(script))
	b := make([]byte, len(u)*2)
	for i, v := range u {
		b[i*2] = byte(v)
		b[i*2+1] = byte(v >> 8)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// RunPowerShell executes script and returns the string it produces, transported
// through a UTF-8 temp file so non-ASCII paths survive console code pages.
// If input is non-nil it is written to a UTF-8 file available as $InputFile.
func RunPowerShell(ctx context.Context, script string, input []byte) ([]byte, error) {
	dir, err := os.MkdirTemp("", "husmea-ps-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	outFile := filepath.Join(dir, "out.txt")
	inFile := filepath.Join(dir, "in.txt")
	if input != nil {
		if err := os.WriteFile(inFile, input, 0o600); err != nil {
			return nil, err
		}
	}
	full := fmt.Sprintf(`$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$InputFile = %s
$__r = & {
%s
}
[System.IO.File]::WriteAllText(%s, [string]$__r, (New-Object System.Text.UTF8Encoding $false))
`, psQuote(inFile), script, psQuote(outFile))

	cmd := exec.CommandContext(ctx, PowerShellPath(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encodePS(full))
	hideWindow(cmd)
	stderr, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(stderr))
		if len(msg) > 500 {
			msg = msg[:500] + "…"
		}
		return nil, fmt.Errorf("powershell: %w: %s", err, msg)
	}
	b, err := os.ReadFile(outFile)
	if err != nil {
		return nil, fmt.Errorf("powershell no produjo salida: %w", err)
	}
	return []byte(strings.TrimPrefix(string(b), "\ufeff")), nil
}
