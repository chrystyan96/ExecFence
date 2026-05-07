package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	protocolVersion = 1
	helperVersion   = "5.0.0"
)

type capability struct {
	Available         bool   `json:"available"`
	Enforced          bool   `json:"enforced"`
	Proof             string `json:"proof,omitempty"`
	RequiresElevation bool   `json:"requiresElevation,omitempty"`
	Limitation        string `json:"limitation,omitempty"`
}

type selfTestResult struct {
	OK              bool                  `json:"ok"`
	ProtocolVersion int                   `json:"protocolVersion"`
	SelfTestID      string                `json:"selfTestId"`
	Name            string                `json:"name"`
	Version         string                `json:"version"`
	Platform        string                `json:"platform"`
	Arch            string                `json:"arch"`
	SHA256          string                `json:"sha256"`
	Capabilities    map[string]capability `json:"capabilities"`
	Limitations     []string              `json:"limitations"`
	GeneratedAt     string                `json:"generatedAt"`
}

type policy struct {
	SchemaVersion        int      `json:"schemaVersion"`
	ProtocolVersion      int      `json:"protocolVersion"`
	Mode                 string   `json:"mode"`
	Profile              string   `json:"profile"`
	CWD                  string   `json:"cwd"`
	RequiredCapabilities []string `json:"requiredCapabilities"`
	Command              struct {
		Argv    []string `json:"argv"`
		Display string   `json:"display"`
	} `json:"command"`
	FS struct {
		Deny              []string `json:"deny"`
		DenyNewExecutable bool     `json:"denyNewExecutable"`
	} `json:"fs"`
	Process struct {
		Deny []string `json:"deny"`
	} `json:"process"`
	Network struct {
		Default string   `json:"default"`
		Allow   []string `json:"allow"`
	} `json:"network"`
}

type event struct {
	Type      string `json:"type"`
	Time      string `json:"time"`
	Surface   string `json:"surface,omitempty"`
	Operation string `json:"operation,omitempty"`
	File      string `json:"file,omitempty"`
	Reason    string `json:"reason,omitempty"`
	PID       int    `json:"pid,omitempty"`
	ExitCode  int    `json:"exitCode,omitempty"`
}

type fileInfo struct {
	Mode int64
	Size int64
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(2)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: execfence-helper self-test|run")
	}
	switch args[0] {
	case "self-test":
		return writeJSON(os.Stdout, selfTest())
	case "run":
		return runCommand(args[1:])
	default:
		return fmt.Errorf("unknown command: %s", args[0])
	}
}

func selfTest() selfTestResult {
	sum, _ := ownSHA256()
	caps := map[string]capability{
		"filesystem": {
			Available:  false,
			Enforced:   false,
			Limitation: "pre-execution filesystem deny requires a platform broker or kernel sandbox; this helper does not claim it",
		},
		"sensitiveReads": {
			Available:  false,
			Enforced:   false,
			Limitation: "sensitive read denial is not claimed without a platform broker",
		},
		"process": {
			Available: true,
			Enforced:  true,
			Proof:     "supervisor launches and waits for the root command",
		},
		"childProcesses": platformChildProcessCapability(),
		"network": {
			Available:         false,
			Enforced:          false,
			RequiresElevation: true,
			Limitation:        "outbound network blocking requires elevated platform controls and is not claimed by this unprivileged helper",
		},
		"newExecutables": {
			Available: true,
			Enforced:  true,
			Proof:     "helper snapshots workspace executable artifacts before and after execution and fails on new artifacts",
		},
	}
	limitations := []string{}
	for name, cap := range caps {
		if !cap.Enforced {
			limitations = append(limitations, name+": "+cap.Limitation)
		}
	}
	return selfTestResult{
		OK:              true,
		ProtocolVersion: protocolVersion,
		SelfTestID:      fmt.Sprintf("%x", sha256.Sum256([]byte(runtime.GOOS+"/"+runtime.GOARCH+"/"+sum))),
		Name:            "execfence-helper",
		Version:         helperVersion,
		Platform:        nodePlatform(runtime.GOOS),
		Arch:            nodeArch(runtime.GOARCH),
		SHA256:          sum,
		Capabilities:    caps,
		Limitations:     limitations,
		GeneratedAt:     time.Now().UTC().Format(time.RFC3339),
	}
}

func runCommand(args []string) error {
	var policyPath, eventsPath string
	var command []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--policy":
			i++
			if i >= len(args) {
				return errors.New("--policy requires a file")
			}
			policyPath = args[i]
		case "--events":
			i++
			if i >= len(args) {
				return errors.New("--events requires a file")
			}
			eventsPath = args[i]
		case "--":
			command = args[i+1:]
			i = len(args)
		default:
			return fmt.Errorf("unknown run argument: %s", args[i])
		}
	}
	if policyPath == "" || len(command) == 0 {
		return errors.New("usage: execfence-helper run --policy <file> [--events <file>] -- <command>")
	}
	p, err := readPolicy(policyPath)
	if err != nil {
		return err
	}
	events, closeEvents, err := eventWriter(eventsPath)
	if err != nil {
		return err
	}
	defer closeEvents()
	caps := selfTest().Capabilities
	for _, required := range p.RequiredCapabilities {
		if cap, ok := caps[required]; !ok || !cap.Enforced {
			events(event{Type: "deny", Surface: "sandbox", Operation: "start command", Reason: "required helper capability is not enforced: " + required})
			os.Exit(126)
		}
	}
	display := strings.Join(command, " ")
	for _, denied := range p.Process.Deny {
		if denied != "" && strings.Contains(strings.ToLower(display), strings.ToLower(denied)) {
			events(event{Type: "deny", Surface: "process", Operation: display, Reason: "command matches sandbox process deny rule: " + denied})
			os.Exit(126)
		}
	}
	before := snapshotExecutables(p.CWD)
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Dir = p.CWD
	cmd.Env = os.Environ()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	supervisor, err := newPlatformSupervisor()
	if err != nil {
		events(event{Type: "deny", Surface: "process", Operation: display, Reason: err.Error()})
		os.Exit(126)
	}
	defer supervisor.Close()
	applyPlatformAttrs(cmd)
	if err := cmd.Start(); err != nil {
		events(event{Type: "deny", Surface: "process", Operation: display, Reason: err.Error()})
		os.Exit(127)
	}
	if err := supervisor.Attach(cmd.Process.Pid); err != nil {
		events(event{Type: "deny", Surface: "process", Operation: display, Reason: err.Error()})
		_ = cmd.Process.Kill()
		os.Exit(126)
	}
	events(event{Type: "spawn", Surface: "process", Operation: display, PID: cmd.Process.Pid})
	err = cmd.Wait()
	after := snapshotExecutables(p.CWD)
	newExecs := diffExecutableSnapshots(before, after)
	if p.FS.DenyNewExecutable && len(newExecs) > 0 {
		for _, file := range newExecs {
			events(event{Type: "deny", Surface: "filesystem", Operation: "new executable artifact", File: file, Reason: "sandbox policy denies new executable/archive artifacts"})
		}
		os.Exit(126)
	}
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			events(event{Type: "deny", Surface: "process", Operation: display, Reason: err.Error()})
			os.Exit(127)
		}
	}
	events(event{Type: "exit", Surface: "process", Operation: display, ExitCode: exitCode})
	os.Exit(exitCode)
	return nil
}

func readPolicy(file string) (policy, error) {
	var p policy
	data, err := os.ReadFile(file)
	if err != nil {
		return p, err
	}
	err = json.Unmarshal(data, &p)
	return p, err
}

func eventWriter(file string) (func(event), func(), error) {
	if file == "" {
		return func(e event) {
			e.Time = time.Now().UTC().Format(time.RFC3339)
			_ = json.NewEncoder(os.Stderr).Encode(e)
		}, func() {}, nil
	}
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		return nil, nil, err
	}
	handle, err := os.Create(file)
	if err != nil {
		return nil, nil, err
	}
	return func(e event) {
		e.Time = time.Now().UTC().Format(time.RFC3339)
		_ = json.NewEncoder(handle).Encode(e)
	}, func() { _ = handle.Close() }, nil
}

func snapshotExecutables(root string) map[string]fileInfo {
	out := map[string]fileInfo{}
	_ = filepath.WalkDir(root, func(file string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			if entry != nil && entry.IsDir() && ignoredDir(entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !isExecutableArtifact(file) {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, file)
		out[filepath.ToSlash(rel)] = fileInfo{Mode: int64(info.Mode()), Size: info.Size()}
		return nil
	})
	return out
}

func diffExecutableSnapshots(before, after map[string]fileInfo) []string {
	var created []string
	for file, current := range after {
		previous, ok := before[file]
		if !ok || previous != current {
			created = append(created, file)
		}
	}
	return created
}

func ignoredDir(name string) bool {
	switch name {
	case ".git", ".execfence", "node_modules", "dist", "build", "coverage", "target", ".next", ".nuxt", ".turbo", ".pytest_cache":
		return true
	default:
		return false
	}
}

func isExecutableArtifact(file string) bool {
	lower := strings.ToLower(file)
	for _, ext := range []string{".asar", ".bat", ".cmd", ".com", ".dll", ".dylib", ".exe", ".jar", ".node", ".scr", ".sh", ".so", ".tar", ".tgz", ".vbs", ".wsf", ".zip"} {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

func ownSHA256() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	handle, err := os.Open(exe)
	if err != nil {
		return "", err
	}
	defer handle.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, handle); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func writeJSON(w io.Writer, value any) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func nodePlatform(goos string) string {
	if goos == "windows" {
		return "win32"
	}
	return goos
}

func nodeArch(goarch string) string {
	switch goarch {
	case "amd64":
		return "x64"
	case "386":
		return "ia32"
	default:
		return goarch
	}
}
