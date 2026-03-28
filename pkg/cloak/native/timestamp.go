//go:build darwin || linux
// +build darwin linux

package native

import (
	"os"
	"syscall"
	"time"
)

// FileTimes holds the access and modification times of a file.
type FileTimes struct {
	AccessTime time.Time
	ModTime    time.Time
}

// GetFileTimes captures the current atime and mtime of a file.
// Supports high-precision timestamps on Linux and Darwin.
func GetFileTimes(path string) (FileTimes, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return FileTimes{}, err
	}

	stat := fi.Sys().(*syscall.Stat_t)
	
	// Platform specific atime extraction
	atime := getAtime(stat)
	
	return FileTimes{
		AccessTime: atime,
		ModTime:    fi.ModTime(),
	}, nil
}

// RestoreFileTimes applies the given times to a file, effectively "time-stomping" it.
func RestoreFileTimes(path string, times FileTimes) error {
	return os.Chtimes(path, times.AccessTime, times.ModTime)
}
