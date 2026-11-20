//go:build unix

package main

import (
	"os/exec"
	"syscall"
)

// Run each stdio upstream in its own process group so `npx`/`uvx` wrappers and the real server
// they spawn are all stopped together.
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func killProcessGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
}
