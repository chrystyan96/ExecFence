# ExecFence

Guard package-manager installs, dependency changes, CI, and agent-run commands before suspicious project code executes.

ExecFence is a local execution and supply-chain guardrail for JavaScript, Python, Rust, Go, JVM, .NET, PHP, Ruby, CI pipelines, package releases, and coding agents. It puts a reviewable fence in front of risky commands such as dependency installs, tests, builds, package scripts, publish steps, and agent-driven tool execution.

## Quick Start

Run a scan without installing globally:

```sh
npx --yes execfence scan
```

Guard a command before it runs:

```sh
npx --yes execfence run -- npm test
```

Enable project-local guardrails:

```sh
npx --yes execfence guard enable
npx --yes execfence guard enable --apply
```

Enable global package-manager interception for terminal and agent-run commands:

```sh
npx --yes execfence guard global-enable
```

## What Version 6 Adds

ExecFence v6 turns the existing execution and supply-chain checks into a more explicit trust and enforcement system:

- one decision model with independent severity, confidence, decision, enforcement status, policy reason, and exact evidence
- a documented threat model and capability matrix that separate prevention, partial enforcement, detection, and unsupported controls
- fail-closed sandbox enforcement, CI rejection of degraded execution, and mandatory local justification for an explicit downgrade
- helper runtime monitoring that terminates its supervised process tree when a denied executable or archive appears
- granular, expiring approvals with branch, commit, command, environment, package, manifest-entry, and policy scope
- separately trusted Ed25519, Ed448, RSA, or ECDSA approver keys with cryptographic signatures and distinct-reviewer quorum
- exact-finding explanations, SARIF output, GitHub annotations, Markdown summaries, and GitHub/GitLab/Azure integration examples
- CycloneDX 1.6 and SPDX 2.3 SBOM generation
- dependency-version comparison for lifecycle scripts, bin entries, provenance, integrity, and package archive changes
- recursive package-content auditing, archive expansion limits, executable magic-byte detection, and stricter registry/artifact validation
- a versioned public Node API and contracts shared by the CLI, CI adapters, approvals, and future IDE integrations
- content-addressed scan caching, bounded workers, timeout/cancellation controls, memory limits, and performance metrics
- release bootstrap checks that reject appended-loader patterns before the project CLI is loaded, followed by source scanning and `npm ci --ignore-scripts`

The project remains dependency-free at runtime and continues to cover npm/pnpm/Yarn/Bun, Python, Rust, Go, JVM, .NET, PHP, and Ruby execution surfaces.

Install-like commands such as `npm install`, `pnpm add`, `pip install`, `uv add`, `cargo add`, `go get`, `go install pkg@version`, `composer require`, and `bundle add` run through ExecFence first. When an ecosystem has a reliable lifecycle suppression flag, ExecFence delegates with scripts disabled. Ecosystems such as Go do not have a universal equivalent, so ExecFence uses preflight scan, dependency review, runtime behavior audit, and strict-mode containment checks instead of pretending scripts were disabled.

## Common Commands

| Command | What it does |
| --- | --- |
| `npx --yes execfence --help` | Prints the grouped command reference and examples. Use this to confirm the installed CLI supports the sandbox/helper commands you expect. |
| `npx --yes execfence scan` | Scans the current project before code runs. It blocks high-risk execution surfaces such as suspicious scripts, loaders, workflows, package hooks, and unexpected executable/archive artifacts. |
| `npx --yes execfence run -- npm test` | Runs a command behind ExecFence. It scans first, executes only if clean, records runtime evidence, snapshots file changes, rescans changed files, and writes a report. |
| `npx --yes execfence ci` | Runs the release/CI bundle: scan, manifest diff, dependency diff/review, coverage, config validation, package audit, and trust audit. |
| `npx --yes execfence deps review` | Reviews changed dependencies across npm/Bun/Yarn/pnpm, Python, Cargo, Go, JVM, NuGet, Composer, and Bundler manifests/lockfiles with metadata, reputation, integrity, source, and runtime-surface findings. |
| `npx --yes execfence deps compare foo@1.0.0 foo@1.1.0` | Compares lifecycle scripts, bin entries, provenance, integrity, and archive delta between two package versions. |
| `npx --yes execfence sbom --format cyclonedx` | Generates a monorepo-aware CycloneDX 1.6 SBOM. Use `--format spdx` for SPDX 2.3 and `--output <file>` to write it. |
| `npx --yes execfence policy diff --base-ref HEAD` | Compares effective policy with a Git base and blocks security-sensitive policy drift. |
| `npx --yes execfence approval audit` | Verifies approval expiry, scope, trusted signing keys, cryptographic signatures, and distinct-reviewer quorum. |
| `npx --yes execfence explain <finding-id> --report <file>` | Explains exact evidence, severity, confidence, decision, policy reason, and remediation. |
| `npx --yes execfence coverage` | Shows whether sensitive entrypoints are covered by direct `execfence run`, package prehooks, workflow-level gates, or active global shims. |
| `npx --yes execfence config validate` | Validates `.execfence/config/*`, baselines, signatures, sandbox policy, and policy packs. It reports invalid regexes, expired baselines, unsafe allowlists, and strict-mode coverage gaps. |
| `npx --yes execfence pack-audit` | Audits files that would be shipped in the package handoff/release, catching dangerous scripts, unexpected binaries, archives, and suspicious publish inputs. |
| `npx --yes execfence agent-report` | Reviews agent, MCP, tool, and instruction-file surfaces for shell/filesystem/network/browser/credential access and attempts to disable security checks. |
| `npx --yes execfence run --sandbox-mode audit -- npm test` | Runs the command normally but records sandbox policy, capability gaps, runtime trace, file snapshot, post-run scan, and report evidence. Audit mode is evidence, not containment. |
| `npx --yes execfence run --sandbox -- npm test` | Enforce mode. It only runs if a verified Windows/Linux helper proves every required capability; otherwise it blocks before the command starts. |
| `npx --yes execfence run --timeout-ms 120000 -- npm test` | Applies a bounded runtime timeout while preserving preflight, postflight, and trace evidence. |
| `npx --yes execfence sandbox doctor` | Prints local sandbox capability status: helper install state, `helperVerified`, capability proof, unsupported capabilities, and missing requirements for enforce mode. |
| `npx --yes execfence sandbox plan -- npm test` | Explains the sandbox policy that would apply to a command: filesystem, process, network, helper proof, missing enforcement, and block reasons. |
| `npx --yes execfence sandbox install-helper --binary ./path/to/execfence-helper` | Registers a reviewed helper binary, computes SHA-256, stores helper metadata, runs helper audit, and reports which capabilities are actually proven. |
| `npx --yes execfence helper audit` | Rechecks the installed helper metadata, binary hash, platform/arch, provenance, self-test output, capability proof, and unsupported capabilities. |

## Sandbox Helper

Sandbox audit mode records the policy, local capability matrix, runtime trace, file snapshot, post-run scan, and report evidence. It is evidence, not containment:

```sh
npx --yes execfence run --sandbox-mode audit -- npm test
```

The npm package includes the helper source under `helper/` so it can be reviewed and built, but it does not install a prebuilt trusted helper binary. Enforce mode stays disabled until you build or otherwise obtain a reviewed Windows/Linux helper binary and register that exact file.

Sandbox enforce mode only runs through a verified Windows/Linux helper:

```sh
npx --yes execfence sandbox doctor
npx --yes execfence sandbox plan -- npm test
npx --yes execfence sandbox install-helper --binary ./path/to/execfence-helper
npx --yes execfence run --sandbox -- npm test
```

Enforce mode validates the helper binary SHA-256, platform, arch, provenance, and `execfence-helper self-test` output. If every required capability is proven, ExecFence writes a policy JSON and launches `execfence-helper run --policy <policy.json> -- <command>`. The helper emits JSONL events such as `spawn`, `deny`, and `exit`; deny events become blocking findings.

ExecFence does not count metadata-only helpers as enforcement. Unsupported capabilities are reported as `unsupportedCapabilities` and strict/enforce blocks instead of silently downgrading. The current helper proves root-process supervision and new-executable artifact detection. Windows can additionally prove Job Object child containment; Linux process-group cleanup is best-effort and is not claimed as complete child-process containment. Filesystem pre-read denial, sensitive-read denial, and network blocking require a real platform broker/elevated capability before they can be claimed.

## Strict Supply-Chain Mode

For security-sensitive CI, release, or package-publishing workflows:

```json
{
  "supplyChain": {
    "mode": "strict"
  }
}
```

`strict` blocks unavailable metadata/reputation/tarball signals, missing integrity/provenance signals, release cooldowns, new package age windows, uncovered package-manager surfaces, invalid ExecFence config, and dependency runtime audits that lack helper-backed containment.

## When ExecFence Blocks

Do not rerun the command outside ExecFence just to bypass the block. Start with the report:

```sh
npx --yes execfence reports latest
npx --yes execfence incident bundle --from-report .execfence/reports/<report>.json
```

`reports latest` prints the blocking summary first: why it blocked, how the suspicious code can execute, affected ecosystem, and the next action.

If the finding is legitimate and must be allowed, create a narrow reviewed baseline with owner, reason, expiry, and hash.

## Documentation

The npm README is intentionally short. Full documentation lives here:

- [Full documentation](https://chrystyan96.github.io/ExecFence/)
- [Source docs](docs/README.md)
- [Architecture and security invariants](docs/architecture.md)
- [Threat model and guarantee contract](docs/threat-model.md)
- [Additional functionality implementation plan](docs/additional-features-plan.md)
- [Detection model](docs/detection.md)
- [Release cadence](docs/release-cadence.md)
- [OpenAI Skills catalog PR](https://github.com/openai/skills/pull/385)

## Non-Claims

ExecFence does not replace antivirus, EDR, secret scanning, dependency vulnerability management, or human review. It does not prove that arbitrary library code is benign. It blocks and records the execution paths and supply-chain signals it can observe: scripts, lockfiles, package metadata, reputation feeds, tarballs, runtime evidence, workflows, binaries, archives, and agent/tool configuration.

## License

Apache-2.0
