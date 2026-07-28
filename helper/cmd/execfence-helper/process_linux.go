//go:build linux

package main

import (
	"os/exec"
	"syscall"
)

func applyPlatformAttrs(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

type platformSupervisor struct {
	pgid int
}

func newPlatformSupervisor() (*platformSupervisor, error) {
	return &platformSupervisor{}, nil
}

func (s *platformSupervisor) Attach(pid int) error {
	s.pgid = pid
	return nil
}

func (s *platformSupervisor) Close() {
	if s == nil || s.pgid == 0 {
		return
	}
	_ = syscall.Kill(-s.pgid, syscall.SIGKILL)
	s.pgid = 0
}

func platformChildProcessCapability() capability {
	return capability{
		Available:  true,
		Enforced:   false,
		Proof:      "Linux process group is terminated after the root command exits",
		Limitation: "process groups are best-effort cleanup; descendants can create a new session or process group, so complete child-process containment is not claimed",
	}
}
