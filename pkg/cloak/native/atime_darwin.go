//go:build darwin
// +build darwin

package native

import (
	"syscall"
	"time"
)

func getAtime(stat *syscall.Stat_t) time.Time {
	return time.Unix(int64(stat.Atimespec.Sec), int64(stat.Atimespec.Nsec))
}
