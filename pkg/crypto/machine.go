package crypto

import (
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

/*
machineID returns a stable identifier for the current machine.
Tries /etc/machine-id (Linux), hw.uuid via sysctl (macOS), then the
first non-loopback hardware MAC address. Returns "" if all methods fail.
*/
func machineID() string {
	if id := readMachineIDFile(); id != "" {
		return id
	}
	if id := readSysctlUUID(); id != "" {
		return id
	}
	return readFirstMAC()
}

func readMachineIDFile() string {
	if runtime.GOOS != "linux" {
		return ""
	}
	data, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func readSysctlUUID() string {
	if runtime.GOOS != "darwin" {
		return ""
	}
	out, err := exec.Command("sysctl", "-n", "hw.uuid").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func readFirstMAC() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if len(iface.HardwareAddr) > 0 {
			return iface.HardwareAddr.String()
		}
	}
	return ""
}
