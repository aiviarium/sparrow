//go:build unix

package hub

import (
	"os/exec"
	"syscall"
)

// ownProcessGroup starts a spawned node in its own process group, so
// stopping it also stops what it started.
func ownProcessGroup(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }

func killProcessGroup(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
