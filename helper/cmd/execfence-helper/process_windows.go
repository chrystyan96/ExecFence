//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"syscall"
	"unsafe"
)

const (
	jobObjectExtendedLimitInformationClass = 9
	jobObjectLimitKillOnJobClose           = 0x00002000
	processSetQuota                        = 0x0100
	processTerminate                       = 0x0001
)

var (
	kernel32                     = syscall.NewLazyDLL("kernel32.dll")
	procCreateJobObjectW         = kernel32.NewProc("CreateJobObjectW")
	procSetInformationJobObject  = kernel32.NewProc("SetInformationJobObject")
	procAssignProcessToJobObject = kernel32.NewProc("AssignProcessToJobObject")
	procOpenProcess              = kernel32.NewProc("OpenProcess")
	procCloseHandle              = kernel32.NewProc("CloseHandle")
)

type ioCounters struct {
	ReadOperationCount  uint64
	WriteOperationCount uint64
	OtherOperationCount uint64
	ReadTransferCount   uint64
	WriteTransferCount  uint64
	OtherTransferCount  uint64
}

type jobObjectBasicLimitInformation struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

type jobObjectExtendedLimitInformation struct {
	BasicLimitInformation jobObjectBasicLimitInformation
	IoInfo                ioCounters
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

type platformSupervisor struct {
	job syscall.Handle
}

func applyPlatformAttrs(_ *exec.Cmd) {}

func newPlatformSupervisor() (*platformSupervisor, error) {
	job, err := createKillOnCloseJob()
	if err != nil {
		return nil, err
	}
	return &platformSupervisor{job: job}, nil
}

func (s *platformSupervisor) Attach(pid int) error {
	if s == nil || s.job == 0 {
		return nil
	}
	process, _, err := procOpenProcess.Call(processSetQuota|processTerminate, 0, uintptr(uint32(pid)))
	if process == 0 {
		return fmt.Errorf("OpenProcess failed for sandbox child: %v", err)
	}
	defer procCloseHandle.Call(process)
	ok, _, assignErr := procAssignProcessToJobObject.Call(uintptr(s.job), process)
	if ok == 0 {
		return fmt.Errorf("AssignProcessToJobObject failed: %v", assignErr)
	}
	return nil
}

func (s *platformSupervisor) Close() {
	if s != nil && s.job != 0 {
		procCloseHandle.Call(uintptr(s.job))
		s.job = 0
	}
}

func platformChildProcessCapability() capability {
	job, err := createKillOnCloseJob()
	if err != nil {
		return capability{Available: true, Enforced: false, Limitation: "Windows Job Object self-test failed: " + err.Error()}
	}
	procCloseHandle.Call(uintptr(job))
	return capability{Available: true, Enforced: true, Proof: "Windows Job Object with kill-on-close limit"}
}

func createKillOnCloseJob() (syscall.Handle, error) {
	handle, _, err := procCreateJobObjectW.Call(0, 0)
	if handle == 0 {
		return 0, fmt.Errorf("CreateJobObjectW failed: %v", err)
	}
	info := jobObjectExtendedLimitInformation{}
	info.BasicLimitInformation.LimitFlags = jobObjectLimitKillOnJobClose
	ok, _, setErr := procSetInformationJobObject.Call(
		handle,
		jobObjectExtendedLimitInformationClass,
		uintptr(unsafe.Pointer(&info)),
		unsafe.Sizeof(info),
	)
	if ok == 0 {
		procCloseHandle.Call(handle)
		return 0, fmt.Errorf("SetInformationJobObject failed: %v", setErr)
	}
	return syscall.Handle(handle), nil
}
