//go:build !windows && !linux

package winutil

import "runtime"

func OSVersion() string { return runtime.GOOS + "/" + runtime.GOARCH }
