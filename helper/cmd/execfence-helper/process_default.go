//go:build !linux && !windows

package main

import "os/exec"

func applyPlatformAttrs(_ *exec.Cmd) {}

type platformSupervisor struct{}

func newPlatformSupervisor() (*platformSupervisor, error) {
	return &platformSupervisor{}, nil
}

func (s *platformSupervisor) Attach(_ int) error {
	return nil
}

func (s *platformSupervisor) Close() {}

func platformChildProcessCapability() capability {
	return capability{Available: false, Enforced: false, Limitation: "unsupported platform"}
}
