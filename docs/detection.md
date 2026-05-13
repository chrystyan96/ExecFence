# ExecFence Detection Model

This page is the technical companion to the [ExecFence launch article](./article). It explains what the scanner inspects, how detection layers work, and how to handle reviewed exceptions without weakening the guardrail.

ExecFence is built around execution surfaces. It prioritizes files and metadata that can cause code to run during:

- dependency install
- build
- test
- local dev
- IDE task execution
- CI
- packaging and publishing
- agent/MCP tool use

It is not a general-purpose code linter. The scanner is tuned for suspicious execution paths.

## What The Scanner Inspects

ExecFence inspects:

- JavaScript/TypeScript executable configs
- package scripts and lifecycle hooks
- npm/pnpm/yarn/bun lockfiles and manifests
- Python requirements, pyproject, Poetry, and uv lockfiles
- Cargo, Go, Maven/Gradle, NuGet, Composer, and Bundler manifests/lockfiles
- GitHub Actions workflows
- `.vscode/tasks.json`
- Makefiles
- Tauri/Electron/VS Code extension surfaces
- committed executable and archive artifacts
- MCP and agent instruction/config files
- project-specific signatures in `.execfence/config/signatures.json`
- reviewed baseline exceptions in `.execfence/config/baseline.json`

It skips normal generated or dependency directories such as `.git`, `node_modules`, `dist`, `build`, `coverage`, `target`, caches, and test output by default.

## Rule Layers

### Exact IoC Matching

Known suspicious markers are detected as literal indicators. This is intentionally simple: exact matching is fast, deterministic, and explainable.

Use this layer for stable indicators such as known loader markers, suspicious endpoint strings, or campaign-specific strings that should never appear in normal project code.

### Regex Signatures

Regex rules catch families of suspicious code that do not have a single stable string.

Teams can add project-owned signatures in:

```text
.execfence/config/signatures.json
```

This keeps project-specific IoCs out of scanner source code and makes them reviewable with the rest of the project policy.

### Suspicious Loader Heuristics

ExecFence looks for JavaScript patterns that are unusual in normal config files but common in loader-style malware:

- global object assignment to dynamic Node module loading
- dynamic `Function` or constructor loaders
- `eval` combined with encoded or generated strings
- `fromCharCode` or base64-like decode paths used with dynamic execution
- `child_process` usage in executable project config
- very long obfuscated lines combined with loader markers

The scanner does not flag every minified file. It focuses on executable project surfaces where obfuscated loader behavior is higher risk.

### Lifecycle Script Audit

Package scripts are treated differently depending on whether they execute automatically. Install-time hooks such as `preinstall`, `install`, `postinstall`, and `prepare` are high-value attacker surfaces because package managers can run them during dependency installation or publication workflows.

When global package-manager guard is enabled, terminal and agent-run package-manager commands pass through ExecFence before the real tool starts. This includes npm/pnpm/yarn/Bun, Python package managers, Cargo, Go, Maven/Gradle, dotnet/NuGet, Composer, and Bundler. Install-like commands are delegated with lifecycle scripts disabled only where the package manager exposes a reliable suppression flag: npm and Bun use `--ignore-scripts=true`, pnpm uses `--ignore-scripts`, Yarn 1 uses `--ignore-scripts=true`, and Yarn 2+ receives `YARN_ENABLE_SCRIPTS=0`. Other ecosystems are protected by preflight scan, dependency review, runtime behavior audit, sandbox evidence, and strict-mode blocking when containment is missing.

ExecFence looks for risky behavior such as:

- shell downloads
- pipe-to-shell
- hidden PowerShell
- `curl` or `wget` execution chains
- eval-style execution
- Windows LOLBins and script hosts such as `bitsadmin`, `Start-BitsTransfer`, `mshta`, `rundll32`, and `regsvr32`
- suspicious binary launch paths
- install hooks in local packages/workspaces
- Python `setup.py`/build-backend execution
- Rust `build.rs` execution
- Go `go generate` directives
- Composer and Bundler script execution

### Lockfile Source Audit

Lockfiles are inspected for suspicious sources:

- raw GitHub URLs
- gist URLs
- paste hosts
- non-HTTPS package sources
- registry drift
- unexpected package source changes
- lifecycle/bin entries in newly introduced packages

The goal is not to replace dependency vulnerability scanning. It is to catch dependency source changes that may cause code execution during install/build/test.

### Guarded Dependency Metadata Review

`execfence deps review` adds supply-chain metadata, reputation, and tarball checks to changed dependencies across supported ecosystems. It aggregates npm/pnpm/yarn/Bun, Python, Cargo, Go, Maven/Gradle, NuGet, Composer, and Bundler manifests/lockfiles, then reports package manager, lockfile, package name/version, change type, registry/source, integrity/checksum hints, lifecycle/build/runtime hints, metadata status, reputation status, tarball status, tarball delta status, privacy status, findings, and recommended actions.

The metadata/reputation layer is intentionally scoped to supply-chain flows, not every static scan. It runs from `deps review`, the CLI `deps diff` path, `ci`, and global guard install-like commands. It only checks new or changed packages or explicit package specs, skips scoped packages unless allowlisted, skips non-allowlisted registries, never reads npm auth tokens, caches under `.execfence/cache/`, applies short timeouts and package-count limits, and fails open on network errors by default.

Strong signals can block in guarded mode:

- version published inside the configured release cooldown
- security-relevant deprecation text
- missing version metadata for the requested package
- package age, recent package metadata modification, missing maintainers, missing integrity, or missing provenance/signature hints according to policy
- OSV advisory matches or other no-token reputation-feed hits
- tarball integrity mismatch, executable artifacts, obfuscated code, or process/network/credential-sensitive code inside reviewed package tarballs
- tarball delta that adds or changes executable artifacts, obfuscation, process/network APIs, or credential-sensitive references
- metadata lookup failure only when `supplyChain.metadata.networkFailure` is set to `block`
- unavailable metadata/reputation/tarball signals, cooldowns, new package age windows, missing integrity/provenance, uncovered package-manager surfaces, and missing helper-backed runtime containment when `supplyChain.mode` is `strict`

This still does not prove that ordinary library code is safe. Runtime-only malicious behavior that appears only after an application imports, builds, generates, or bundles a compromised dependency remains a limitation unless surrounding metadata, scripts, artifacts, lockfile drift, tarball content/delta, reputation feeds, helper-backed runtime enforcement, or runtime evidence expose it. For Go specifically, direct `go.mod`/`go.sum` edits and `go get`/`go install pkg@version` are reviewed, while `go run`, `go build`, `go install`, `go test`, and high-risk `go generate` enter dependency behavior audit when changed modules are present.

Use `execfence run --dependency-behavior-audit --sandbox-mode audit -- <command>` when a test/build/start command may import changed dependencies. The runtime report records the changed-dependency review, sandbox containment status, degraded network/process/filesystem enforcement, generated executable artifacts, and post-run scan evidence. In enforce mode, v5 requires a verified Windows/Linux helper self-test and executes through `execfence-helper run`; unsupported capabilities remain blocking instead of being treated as protection.

### Executable And Archive Artifacts

ExecFence flags unexpected binaries and archives in source/build-input folders:

- `.exe`
- `.dll`
- `.bat`
- `.cmd`
- `.scr`
- `.vbs`
- `.wsf`
- `.zip`
- `.tar`
- `.tgz`
- `.asar`
- platform shared libraries and other executable-like artifacts

Reviewed artifacts should be pinned by SHA-256 through config or trust stores, with a reason and owner.

### Multi-Ecosystem Execution Fixtures

ExecFence treats dependency managers and build systems as activation surfaces, not only as parsers. The scanner blocks high-confidence install/build/generate/run signals across supported ecosystems:

- npm/pnpm/yarn/Bun lifecycle scripts with download cradles, encoded PowerShell, pipe-to-shell, native artifact drops, or credential access combined with process/network behavior
- Python `setup.py` and build metadata that invoke shell, subprocess, dynamic code, or download behavior
- Rust `build.rs` with process execution, shell/download behavior, embedded artifacts, or generated-output paths
- Go `go generate` directives that invoke shell, downloaders, package managers, or interpreters
- Maven/Gradle repository or plugin drift plus build logic that launches processes or downloaders
- NuGet restore/build sources over HTTP, local paths, raw/paste hosts, or other suspicious sources
- Composer scripts with shell/PHP dynamic execution
- Bundler git/path gems or suspicious non-registry sources

Credential-only references are warnings by default. They become blocking when combined with network, shell, process, or download behavior because that is the point where token exposure becomes credible exfiltration risk.

### Workflow Hardening

GitHub Actions workflows are audited for patterns that can turn untrusted repository code into credentialed execution:

- broad write permissions
- risky triggers
- unpinned actions
- pipe-to-shell
- publish workflows without provenance
- secrets exposed to untrusted PR contexts

### Agent And MCP Surface Audit

ExecFence treats agents as execution surfaces. MCP/tool manifests and agent instructions can expose powerful capabilities that are equivalent to local code execution.

The scanner and `agent-report` watch for:

- broad shell/process access
- broad filesystem access
- browser/network/credential access
- MCP configs added or changed in a diff
- agent instructions that tell tools to skip, disable, ignore, or bypass ExecFence/security checks

`execfence scan` audits committed MCP/tool configs directly. For agent instruction files such as `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, Copilot instructions, and `.clinerules`, scan blocks explicit attempts to skip, disable, ignore, or bypass ExecFence/security checks while avoiding noisy blocks for ordinary operational wording. `execfence agent-report` keeps the broader changed-file review for shell, filesystem, network, browser, and credential-capable agent surfaces.

This is useful because agents can execute commands faster than a human can review each one.

## Baselines And Exceptions

Reviewed exceptions live in:

```text
.execfence/config/baseline.json
```

A good exception includes:

- `findingId`
- `file`
- `sha256`
- `reason`
- `owner`
- `expiresAt`

Use baselines for reviewed legacy findings. Do not baseline new `critical` or `high` findings only to make a build pass.

Example `baseline.json` entry:

```json
{
  "$schema": "https://raw.githubusercontent.com/chrystyan96/execfence/master/schema/execfence-baseline.schema.json",
  "findings": [
    {
      "findingId": "executable-artifact-in-source-tree",
      "file": "tools/reviewed-helper.exe",
      "sha256": "9d377c49b1f5f3c61acd9dd3f4a8f0e8749f23d3c8d2d9080f24e7a0b2c2d4ef",
      "reason": "Reviewed internal build helper required by legacy packaging workflow.",
      "owner": "security-team",
      "expiresAt": "2026-12-31"
    }
  ]
}
```

Operational rules for baselines:

- Use a baseline only after reviewing the exact file and current hash.
- Prefer `sha256` for any file-backed finding.
- Require a human owner and a concrete reason.
- Use short expiry dates for temporary exceptions.
- Re-review the finding when the file hash changes.
- Do not baseline fresh `critical` or `high` findings just to pass a build.
- Do not use broad ignores when a narrow file/hash exception is possible.

## Reports

Findings are written to timestamped JSON reports under `.execfence/reports/`. For report contents and incident flow, see [Evidence Reports in the main article](./article#evidence-reports).

## Design Boundary

ExecFence is intentionally conservative about what it claims:

- It can block known suspicious patterns before execution.
- It can detect risky execution surfaces.
- It can preserve evidence when a command blocks.
- It can make agents prefer safer command execution.

It cannot prove arbitrary code is safe or replace EDR/AV. Hard sandbox isolation requires a verified platform helper with self-tested capabilities; metadata-only helper declarations do not count.
