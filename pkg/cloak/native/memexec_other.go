//go:build !linux
// +build !linux

package native

import (
	"errors"
)

// MemExec is a stub for non-linux systems.
func MemExec(payload []byte, args []string) error {
	return errors.New("native in-memory execution is only supported on Linux (requires memfd_create)")
}
