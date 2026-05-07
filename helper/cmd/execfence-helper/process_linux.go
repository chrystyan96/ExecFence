//go:build linux

package main

import (
	"os/exec"
	"syscall"
)

func applyPlatformAttrs(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

type platformSupervisor struct{}

func newPlatformSupervisor() (*platformSupervisor, error) {
	return &platformSupervisor{}, nil
}

func (s *platformSupervisor) Attach(_ int) error {
	return nil
}

func (s *platformSupervisor) Close() {}

func platformChildProcessCapability() capability {
	return capability{Available: true, Enforced: true, Proof: "linux process-group supervision"}
}
