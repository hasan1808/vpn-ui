//go:build windows
// +build windows

package sys

import (
	"fmt"
	"syscall"
)

var SIGUSR1 = syscall.Signal(0) // No SIGUSR1 on Windows; use a no-op signal

func GetTCPCount() (int, error) {
	// Windows does not expose /proc/net/tcp; fall back to gopsutil
	return 0, fmt.Errorf("GetTCPCount not implemented on Windows")
}

func GetUDPCount() (int, error) {
	return 0, fmt.Errorf("GetUDPCount not implemented on Windows")
}

// CPUTimesRaw is not implemented on Windows.
func CPUTimesRaw() (idleAll, total uint64, err error) {
	return 0, 0, fmt.Errorf("CPUTimesRaw not implemented on Windows")
}
