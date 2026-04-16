//go:build windows
// +build windows

package native

import (
	"os"
	"time"
)

// FileTimes holds the access and modification times of a file.
type FileTimes struct {
	AccessTime time.Time
	ModTime    time.Time
}

/* GetFileTimes captures the mtime of path. Windows does not expose atime
without CGO, so AccessTime falls back to ModTime. */
func GetFileTimes(path string) (FileTimes, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return FileTimes{}, err
	}
	return FileTimes{AccessTime: fi.ModTime(), ModTime: fi.ModTime()}, nil
}

// RestoreFileTimes applies times to path using os.Chtimes.
func RestoreFileTimes(path string, times FileTimes) error {
	return os.Chtimes(path, times.AccessTime, times.ModTime)
}
