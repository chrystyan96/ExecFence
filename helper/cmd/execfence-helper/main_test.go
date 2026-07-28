package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSelfTestDoesNotClaimUnavailableContainment(t *testing.T) {
	result := selfTest()
	if !result.OK || result.ProtocolVersion != protocolVersion {
		t.Fatalf("unexpected self-test result: %#v", result)
	}
	for _, name := range []string{"filesystem", "sensitiveReads", "network"} {
		if result.Capabilities[name].Enforced {
			t.Fatalf("%s must not be claimed as enforced", name)
		}
	}
	if !result.Capabilities["process"].Enforced || !result.Capabilities["newExecutables"].Enforced {
		t.Fatal("root process supervision and executable artifact checks must be reported")
	}
}

func TestExecutableSnapshotDetectsBuildOutputs(t *testing.T) {
	root := t.TempDir()
	before := snapshotExecutables(root)
	output := filepath.Join(root, "dist", "tool.exe")
	if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, []byte("fixture"), 0o644); err != nil {
		t.Fatal(err)
	}
	after := snapshotExecutables(root)
	changed := diffExecutableSnapshots(before, after)
	if len(changed) != 1 || changed[0] != "dist/tool.exe" {
		t.Fatalf("expected build output executable, got %#v", changed)
	}
}

func TestReadPolicyAndEventWriter(t *testing.T) {
	root := t.TempDir()
	policyPath := filepath.Join(root, "policy.json")
	eventsPath := filepath.Join(root, "events.jsonl")
	input := policy{SchemaVersion: 1, ProtocolVersion: protocolVersion, Mode: "enforce", CWD: root}
	input.Command.Argv = []string{"go", "test", "./..."}
	bytes, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyPath, bytes, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := readPolicy(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Command.Argv[0] != "go" || loaded.ProtocolVersion != protocolVersion {
		t.Fatalf("policy did not round trip: %#v", loaded)
	}
	writeEvent, closeEvents, err := eventWriter(eventsPath)
	if err != nil {
		t.Fatal(err)
	}
	writeEvent(event{Type: "spawn", PID: 42})
	closeEvents()
	var recorded event
	eventBytes, err := os.ReadFile(eventsPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(eventBytes, &recorded); err != nil {
		t.Fatal(err)
	}
	if recorded.Type != "spawn" || recorded.PID != 42 || recorded.Time == "" {
		t.Fatalf("unexpected event: %#v", recorded)
	}
}

func TestPlatformMappings(t *testing.T) {
	if nodePlatform("windows") != "win32" || nodeArch("amd64") != "x64" || nodeArch("386") != "ia32" {
		t.Fatal("Node platform mappings changed")
	}
}
