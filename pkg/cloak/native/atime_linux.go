//go:build linux
// +build linux

package native

import (
	"syscall"
	"time"
)

func getAtime(stat *syscall.Stat_t) time.Time {
	return time.Unix(int64(stat.Atim.Sec), int64(stat.Atim.Nsec))
}
