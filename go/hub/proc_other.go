//go:build !unix

package hub

import "os/exec"

func ownProcessGroup(cmd *exec.Cmd) {}

func killProcessGroup(cmd *exec.Cmd) {}
