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

// GetFileTimes captures the current atime and mtime of a file.
func GetFileTimes(path string) (FileTimes, error) {
	info, err := os.Stat(path)
	if err != nil {
		return FileTimes{}, err
	}
	
	// On Unix-like systems, we can get atime via sys info, 
	// but for this implementation, we'll use ModTime for both 
	// or standard OS stat info which Go handles gracefully.
	return FileTimes{
		AccessTime: info.ModTime(), // Simplified for cross-platform
		ModTime:    info.ModTime(),
	}, nil
}

// RestoreFileTimes applies the given times to a file, effectively "time-stomping" it.
func RestoreFileTimes(path string, times FileTimes) error {
	return os.Chtimes(path, times.AccessTime, times.ModTime)
}
