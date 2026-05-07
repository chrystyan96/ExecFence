# ExecFence Documentation

ExecFence is a local execution guardrail for projects that run code during development, build, test, CI, packaging, or agent workflows. It was created to stop the specific class of incident where a developer clones or opens a repository, runs a normal project command, and unintentionally executes attacker-controlled code.

The project intentionally sits close to the developer workflow:

- before `npm test`, `go test`, `cargo test`, `python -m pytest`, `npm run build`, `make`, packaging, or publishing
- around project commands through `execfence run -- <command>`
- inside CI through `execfence ci`
- in agent workflows through the `execfence` skill and portable agent rules
- in investigation workflows through automatic JSON reports, evidence bundles, baselines, trust stores, and incident helpers

ExecFence is not an antivirus, EDR, SCA platform, or remote sandbox service. It is a lightweight, dependency-free CLI and agent skill that focuses on one narrow but high-impact problem: suspicious code becoming active during normal development.

## What Version 5 Adds

Version 5 is the major release that moves ExecFence from npm-centric guardrails to multi-ecosystem supply-chain coverage and helper-backed sandbox evidence.

The multi-ecosystem layer covers:

- npm, pnpm, Yarn, and Bun manifests, lockfiles, install-like commands, lifecycle scripts, and runtime-like commands
- Python `pip`, `pipx`, `uv`, Poetry, `requirements*.txt`, `pyproject.toml`, `poetry.lock`, and `uv.lock`
- Rust/Cargo `Cargo.toml`, `Cargo.lock`, `cargo add/install/update/fetch/build/test/run/check`, `build.rs`, proc-macro and native-artifact surfaces
- Go `go.mod`, `go.sum`, `go.work`, `go get`, `go install pkg@version`, `go mod download/tidy`, `go work sync`, `go run`, `go build`, `go test`, `go generate`, and `go vet`
- JVM Maven/Gradle files and repositories/plugins
- .NET/NuGet project files, lockfiles, restore/build/test/run surfaces, and package sources
- Composer/PHP and Bundler/Ruby manifests, lockfiles, scripts, git/path package sources, and runtime-like commands

The sandbox layer adds:

- Windows and Linux helper support through a Go supervisor binary
- `execfence-helper self-test` as required capability proof before enforce mode
- `execfence-helper run --policy <policy.json> -- <command>` as the only enforce-mode execution path
- helper manifests pinned by platform, arch, SHA-256, provenance, version, and self-test evidence
- report fields such as `helperVerified`, `capabilityProof`, and `unsupportedCapabilities`
- strict/enforce blocking when required containment cannot be proven

This is not a blanket claim that every dependency is safe or every platform sandbox primitive exists. Version 5 is explicit about what is covered, what is only audited, and what remains unsupported until a helper proves it on the current host.

## Why ExecFence Exists

Modern software projects execute code in many places that do not look like application code:

- package manager lifecycle hooks
- build tool configs
- local task runners
- IDE task files
- generated package archives
- CI workflows
- language-specific build scripts
- agent and MCP tool manifests

Recent threat reporting shows why this matters. The practical risk is not only "malware exists"; it is that malware can be hidden in exactly the files developers are trained to trust during ordinary work.

Trend Micro described Void Dokkaebi activity where fake job interview lures pushed developers toward malicious code repositories, turning repository execution into a malware delivery path: [Void Dokkaebi Uses Fake Job Interview Lure to Spread Malware via Code Repositories](https://www.trendmicro.com/en_us/research/26/d/void-dokkaebi-uses-fake-job-interview-lure-to-spread-malware-via-code-repositories.html).

Microsoft described the Contagious Interview campaign as a long-running social engineering operation against software developers. Its analysis highlights developer trust in recruitment workflows, malicious packages, and Visual Studio Code task execution after repository trust is granted: [Contagious Interview: Malware delivered through fake developer job interviews](https://www.microsoft.com/en-us/security/blog/2026/03/11/contagious-interview-malware-delivered-through-fake-developer-job-interviews/).

Datadog documented the 2026 axios npm compromise, where malicious releases introduced a dependency with a `postinstall` script that downloaded and ran a cross-platform RAT during install, then removed traces of the hook from disk: [Compromised axios npm package delivers cross-platform RAT](https://securitylabs.datadoghq.com/articles/axios-npm-supply-chain-compromise/).

Those incidents share the same operational lesson: the point of execution is often mundane. A developer runs a test, opens a folder, installs dependencies, accepts an interview task, or lets CI run a script. ExecFence exists to put a reviewable fence around those moments.

## Origin Story: From Suspicious Build Output To A Product

ExecFence started from a concrete workflow problem: a project test/build step produced a temporary Go test binary that was flagged by local security tooling as `PasswordStealer.Spyware.Stealer.DDS`. The important question was not only whether that specific binary was malicious. The bigger question was:

> What guardrail should exist so a developer does not have to manually notice every injected payload before running build, dev, or test?

That question maps directly to the attack pattern described by Trend Micro in its Void Dokkaebi research. In that campaign, the attacker does not need the victim to double-click an obvious malware attachment. The attacker can rely on developer habits:

- clone or open a repository
- trust a coding exercise, interview task, dependency, or workspace
- run a build/test/dev command
- let IDE tasks, package hooks, or scripts execute
- expose local files, tokens, browser data, wallets, SSH keys, cloud credentials, or source code

ExecFence was created to make that path less automatic. It turns "run the project" into a guarded workflow:

```sh
npx --yes execfence scan
npx --yes execfence run -- npm test
npx --yes execfence run --sandbox-mode audit -- npm run build
```

The design goal is deliberately narrow: block or document suspicious execution before it reaches the user's machine, CI credentials, package publishing credentials, or agent tool access.

## How ExecFence Maps To The Void Dokkaebi Pattern

Trend Micro's Void Dokkaebi article is important because it focuses on malware delivered through code repositories and social engineering against developers. ExecFence responds to that class of risk with specific controls:

| Attack pressure | ExecFence response |
| --- | --- |
| Developer is told to clone/open a repository | `execfence scan`, `doctor`, and known IoC checks inspect the repo before execution. |
| Interview/task project hides suspicious JavaScript | Scanner rules look for injected loader markers, dynamic loaders, obfuscation, shell execution, and known IoCs. |
| Repository uses IDE/task automation | `.vscode/tasks.json` and folder-open execution are treated as execution surfaces. |
| Package install/build runs attacker code | npm/pnpm/yarn/bun, Python, Cargo, Go, JVM, .NET, Composer, and Bundler manifests, lockfiles, install commands, and runtime-like commands are audited. |
| Malware drops or modifies binaries | Runtime trace can detect created/modified executable artifacts, and `--deny-on-new-executable` can block after execution. |
| CI or agent runs changed scripts | `manifest diff`, `coverage`, `ci`, and `agent-report` identify new or unguarded execution entrypoints. |
| Agent tool config exposes shell/filesystem/network | MCP/tool/agent configs are audited for broad shell, filesystem, browser, credential, or network access. |
| User needs evidence after a block | Every blocking-capable command writes a timestamped JSON report under `.execfence/reports/`. |

ExecFence does not claim to detect every Void Dokkaebi sample or every future campaign. Its value is operational: it places a default review and evidence layer at the point where repository code would execute.

## Functional Overview

ExecFence is made of six cooperating surfaces:

1. **Static scanner**: looks for known IoCs, suspicious loaders, risky scripts, workflow hardening issues, lockfile problems, and unexpected binaries/archives.
2. **Runtime gate**: wraps commands with `execfence run -- <command>`, performs preflight scanning, executes only when allowed, records runtime evidence, and rescans changed files.
3. **Sandbox readiness and enforcement switch**: records sandbox policy in audit mode and blocks enforce mode when real filesystem/process/network enforcement is unavailable.
4. **Execution manifest**: inventories package scripts, workflows, Makefiles, language build files, tasks, hooks, and agent rules.
5. **Supply-chain checks**: compares dependency and lockfile changes, audits package contents, and manages trust stores.
6. **Agent skill and rules**: teaches coding agents to use the guardrail before running project commands or changing execution surfaces.

The result is not one big scanner command. It is a workflow:

```text
detect stack -> initialize policy -> scan -> wrap execution -> record evidence -> compare changes -> investigate blocks
```

## Threat Model

ExecFence is designed for:

- injected JavaScript loaders in project files
- suspicious build or config files that execute during dev/build/test
- `.vscode/tasks.json` folder-open autostart behavior
- npm/pnpm/yarn/bun lifecycle scripts, Python build scripts, Rust `build.rs`, Go `go generate`, Composer/Bundler scripts, and shell/download/eval behavior or Windows LOLBins such as `bitsadmin`, `mshta`, `rundll32`, and `regsvr32`
- suspicious package manager lockfile sources
- unexpected executables and archives in source or build-input folders
- new or modified execution entrypoints
- risky GitHub Actions patterns
- MCP/tool/agent configs that expose broad shell, filesystem, browser, network, or credential access
- attempts to instruct agents to skip or disable ExecFence/security checks

ExecFence is not designed to:

- replace endpoint security
- guarantee malware-free dependencies
- prove that arbitrary code is safe
- provide complete sandbox isolation without a verified helper
- remove suspicious files automatically
- send private code or local paths to external services by default

## Core Workflow

The recommended sequence for an existing project is:

```sh
npx --yes execfence init --preset auto
npx --yes execfence scan
npx --yes execfence coverage
npx --yes execfence wire --dry-run
npx --yes execfence run -- npm test
```

The higher-level automatic setup is:

```sh
npx --yes execfence guard enable
npx --yes execfence guard enable --apply
npx --yes execfence guard status
```

`guard enable` is a dry-run by default. It plans project config, script/workflow/task wrappers, CI wiring, local agent rules, and coverage status. `guard enable --apply` writes those changes. `guard disable` removes generated wrappers and marked agent rules while preserving reports, config, baselines, signatures, trust stores, and quarantine metadata.

For first adoption in a noisy repository:

```sh
npx --yes execfence adopt
npx --yes execfence adopt --write-baseline
```

For CI:

```sh
npx --yes execfence ci
```

For a higher-risk local command:

```sh
npx --yes execfence sandbox doctor
npx --yes execfence sandbox plan -- npm test
npx --yes execfence run --sandbox-mode audit -- npm test
```

Use hard sandbox enforcement only when a verified Windows or Linux helper can actually enforce the requested controls:

```sh
npx --yes execfence run --sandbox -- npm test
```

If hard enforcement is requested and filesystem/process/network/process-tree enforcement is unavailable, ExecFence blocks before running the command. It never silently downgrades `--sandbox` to audit mode. Helper metadata alone is not enough; ExecFence validates the binary SHA-256 and runs `execfence-helper self-test` before enforce mode can start.

## Project Layout

ExecFence owns a single operational directory in the project root:

```text
.execfence/
  config/
    execfence.json
    signatures.json
    baseline.json
    sandbox.json
    policies/
  reports/
  cache/
  trust/
  quarantine/
  helper/
  manifest.json
```

### `.execfence/config/execfence.json`

Main project policy. Common fields:

- `policyPack`: baseline policy preset
- `mode`: `block` or `audit`
- `blockSeverities`: severities that fail in block mode
- `warnSeverities`: severities reported without blocking
- `roots`: default scan roots
- `ignoreDirs`: extra directories to skip
- `allowExecutables`: reviewed executable allowlist with SHA-256
- `signaturesFile`: path to project IoCs
- `baselineFile`: path to reviewed exceptions
- `sandboxFile`: path to sandbox policy
- `reportsDir`: automatic JSON report directory
- `reportsGitignore`: whether reports stay out of git
- `runtimeTrace`: runtime gate evidence options
- `analysis.webEnrichment`: optional enrichment settings
- `manifest`: execution surface policy
- `trustStore`: reviewed trust stores
- `reportRetention`: local retention hints

### `.execfence/config/signatures.json`

Team-owned IoCs and regex signatures. Use this for project-specific indicators instead of editing scanner code.

### `.execfence/config/baseline.json`

Reviewed exceptions for existing findings. A good baseline entry includes:

- `findingId`
- `file`
- `sha256`
- `reason`
- `owner`
- `expiresAt`

Baseline entries should be narrow and time-bound. Do not baseline new `critical` or `high` findings just to unblock a build.

### `.execfence/config/sandbox.json`

Sandbox policy for `execfence run --sandbox` and `execfence run --sandbox-mode audit`.

Important fields:

- `mode`: `audit` or `enforce`
- `profile`: `test`, `build`, `dev`, `pack`, `publish`, or `strict`
- `allowDegraded`: explicit degraded-mode allowance
- `fs.readAllow`, `fs.writeAllow`, `fs.deny`
- `process.allow`, `process.deny`, `process.superviseChildren`
- `network.default`, `network.allow`, `network.auditOnly`
- `helper.path`, `helper.requiredForEnforce`, `helper.requiredCapabilities`, `helper.minExecFenceVersion`

## Commands By Job

### Common Command Reference

These are the commands most users see first in the README, with the operational meaning spelled out.

| Command | When to use it | What it does | What to look for |
| --- | --- | --- | --- |
| `npx --yes execfence --help` | When checking an installed version or onboarding a new project. | Prints grouped commands, options, and examples from the local CLI. | Confirm `run --sandbox`, `sandbox install-helper --binary`, and `helper audit` are present for v5 sandbox support. |
| `npx --yes execfence scan` | Before running code from a repo, before review, or as a fast local check. | Scans source, package scripts, lockfiles, workflows, task files, agent/MCP configs, executables, archives, and configured signatures. | `OK` means no blocking finding was detected. A block includes finding id, file, severity, activation surface, and report path. |
| `npx --yes execfence run -- npm test` | When you want to run a project command but keep preflight and post-run evidence. | Runs preflight scan, executes only if clean, records command/env/runtime trace, snapshots files, rescans changed files, and writes a JSON report. | Use the report to see what ran, what changed, whether postflight passed, and whether new executable artifacts appeared. |
| `npx --yes execfence ci` | In CI/release review or before publishing. | Aggregates scan, manifest diff, dependency diff/review, coverage, config validation, pack audit, and trust audit. | `ok:false` means at least one release gate failed. Check `ci.configValidation`, `manifest.summary`, dependency findings, and `blockingSummary`. |
| `npx --yes execfence deps review` | After dependency, manifest, lockfile, or package-manager command changes. | Reviews changed dependencies across npm/Bun/Yarn/pnpm, Python, Cargo, Go, JVM, NuGet, Composer, and Bundler. Adds metadata, reputation, integrity, source drift, lifecycle/build/runtime, and advisory findings. | Look for source/registry drift, git/path deps, recent packages, yanked/deprecated versions, missing integrity, OSV advisories, and runtime-audit requirements. |
| `npx --yes execfence coverage` | When deciding whether project entrypoints are protected. | Inventories sensitive scripts/workflows/tasks/package-manager surfaces and checks whether each is directly guarded or otherwise covered. | `directGuarded` means the command itself invokes ExecFence. `covered` also counts package prehooks, workflow gates, and active global shims. |
| `npx --yes execfence config validate` | Before CI/release, after config edits, or when adoption fails. | Validates `.execfence/config/execfence.json`, `baseline.json`, `signatures.json`, `sandbox.json`, and local policy packs. | Fix JSON parse errors, invalid regexes, expired baselines, allowlisted executables without hashes, suspicious registries, and strict-mode coverage gaps. |
| `npx --yes execfence pack-audit` | Before `npm pack`, publish, handoff, or release artifact review. | Audits files that would be included in package output. | Watch for unexpected binaries, archives, executable configs, lifecycle hooks, or files that should not ship. |
| `npx --yes execfence agent-report` | When agent/MCP/tooling config changes or before enabling coding agents. | Reviews agent instructions, MCP servers, tool manifests, and local automation surfaces. | Look for broad shell/filesystem/network/browser/credential access and instructions that try to bypass ExecFence/security checks. |
| `npx --yes execfence run --sandbox-mode audit -- npm test` | When a command is risky but helper enforcement is unavailable or intentionally not required. | Runs the command normally while recording sandbox plan, helper/capability gaps, runtime trace, file changes, post-run scan, and report evidence. | Treat it as evidence only. It does not block network, filesystem reads, or child behavior at runtime. |
| `npx --yes execfence run --sandbox -- npm test` | When hard enforcement is required. | Uses enforce mode. ExecFence validates the helper and, only if required capabilities are proven, delegates execution to `execfence-helper run --policy <policy.json> -- <command>`. | If helper proof is incomplete, the command blocks before execution. If the helper emits a `deny` event, the runtime report contains a blocking finding. |
| `npx --yes execfence sandbox doctor` | Before using enforce mode or debugging why `--sandbox` blocked. | Reports platform, arch, helper install state, helper self-test, `helperVerified`, capability proof, unsupported capabilities, and missing enforce requirements. | `helperVerified:false` or non-empty `missingForEnforce` means enforce mode will block unless degraded mode is explicitly allowed. |
| `npx --yes execfence sandbox plan -- npm test` | Before running a command under audit/enforce to understand policy impact. | Shows filesystem allow/deny, process allow/deny, network policy, helper proof, missing enforcement, decisions, and blocked operations for that command. | Use it to see whether a command will be audited, enforced, or blocked before running it. |
| `npx --yes execfence sandbox install-helper --binary ./path/to/execfence-helper` | After building or downloading a reviewed helper binary. | Copies/registers the helper, computes SHA-256, writes helper metadata, runs self-test through `helper audit`, and returns proven/unsupported capabilities. | Install success does not mean every capability is enforced. Review `capabilityProof` and `unsupportedCapabilities`. |
| `npx --yes execfence helper audit` | After helper install, after binary updates, or during CI/release checks. | Revalidates helper metadata, binary hash, platform/arch, provenance, self-test output, required capabilities, and limitations. | Metadata-only helpers fail. Hash mismatch, wrong platform, failed self-test, or missing capabilities prevent enforce mode. |

### Initialize

```sh
npx --yes execfence init --preset auto
```

Creates `.execfence/config/*`, `.execfence/reports/`, a sandbox policy, and common project hooks/wrappers when safe.

Dry-run:

```sh
npx --yes execfence init --dry-run
```

### Scan

```sh
npx --yes execfence scan
npx --yes execfence scan --mode audit
npx --yes execfence scan --changed-only --ci --format json
npx --yes execfence scan --ci --format sarif
```

Use `scan` before running project code, in CI, and when reviewing suspicious diffs.

### Runtime Gate

```sh
npx --yes execfence run -- npm test
npx --yes execfence run -- npm run build
npx --yes execfence run --record-artifacts --deny-on-new-executable -- npm test
```

`run` does a preflight scan, executes the command if allowed, snapshots evidence, rescans changed files, and writes a JSON report.

### Sandbox

```sh
npx --yes execfence sandbox init
npx --yes execfence sandbox doctor
npx --yes execfence sandbox plan -- npm test
npx --yes execfence sandbox explain
npx --yes execfence sandbox install-helper --binary ./path/to/execfence-helper
npx --yes execfence sandbox install-helper --metadata ./execfence-helper.json
npx --yes execfence sandbox helper-audit
npx --yes execfence helper audit
npx --yes execfence run --sandbox-mode audit -- npm test
npx --yes execfence run --sandbox -- npm test
```

Audit mode records the plan, local capability matrix, runtime trace, file snapshot, post-run scan, and report evidence. It does not contain the process.

The npm package ships helper source under `helper/` for review and local builds, not a prebuilt trusted helper binary. A global or `npx` install does not automatically enable sandbox enforce mode. Build or obtain a reviewed Windows/Linux helper binary first, then register that exact file with `sandbox install-helper --binary`.

Enforce mode delegates execution to `execfence-helper run --policy <policy.json> -- <command>`. ExecFence first validates the helper metadata, binary SHA-256, platform, arch, provenance, and `execfence-helper self-test` result. Without a verified helper binary, matching SHA-256, successful self-test, and enforced required capabilities, enforce mode blocks before execution.

The helper emits JSONL events for `spawn`, `deny`, `allow`, `network`, `filesystem`, `process`, `child`, `newExecutable`, and `exit`. Deny events become blocking findings in the runtime report. Windows and Linux are the v5 helper targets; other platforms remain explicit unsupported for enforce.

Current unprivileged helper proof is intentionally narrow: root process supervision, Windows Job Object or Linux process-group child handling, and new executable artifact detection. Filesystem pre-read denial, sensitive-read denial, and outbound network blocking are reported as unsupported unless a real platform broker/elevated capability proves them. Strict/enforce blocks unsupported required capabilities instead of silently downgrading.

### Coverage And Wiring

```sh
npx --yes execfence coverage
npx --yes execfence coverage --fix-suggestions
npx --yes execfence wire --dry-run
npx --yes execfence wire --apply
npx --yes execfence guard enable
npx --yes execfence guard enable --apply
npx --yes execfence guard disable
npx --yes execfence guard status
```

`coverage` finds execution entrypoints that are not protected by `execfence run` or equivalent guardrails. `wire` suggests or applies wrappers. Coverage evidence uses two separate fields: `directGuarded` means the entrypoint command itself invokes ExecFence; `covered` also counts package prehooks, workflow-level gates, inherited guardrails, and active global package-manager shims. `ci` uses `covered/uncovered` for operational risk and keeps `directGuarded` visible for release review.

`guard` is the automatic project mode. It runs `init`, checks coverage, applies wiring, installs project-local agent rules, and summarizes remaining gaps. Global guard mode installs reversible package-manager shims:

```sh
npx --yes execfence guard global-status
npx --yes execfence guard global-enable
npx --yes execfence guard global-disable
```

It installs skill/defaults, global agent rules, and supported package-manager shims under `<home>/.execfence/shims/`. Marked shell-profile blocks put that directory before the real package managers in PATH, so terminal commands and agent-run commands pass through ExecFence first. `guard global-status` and the post-install result include an `actionPlan` for missing shims, inactive PATH, current-shell reload, Corepack/nvm/Volta/asdf path ordering, CI/container/IDE interception, and the command to apply the shim path in the current session. `global-disable` removes the shims and marked profile blocks without deleting reports, config, trust stores, cache, or quarantine metadata.

Install-like commands such as `npm install`, `pnpm add`, `yarn install`, `bun add`, `ci`, `update`, and `rebuild` run after a clean preflight scan and guarded dependency review. npm and Bun use `--ignore-scripts=true`, pnpm uses `--ignore-scripts`, Yarn 1 uses `--ignore-scripts=true`, and Yarn 2+ runs with `YARN_ENABLE_SCRIPTS=0`. Commands that intentionally run scripts, such as `run`, `test`, `start`, `pack`, and `publish`, keep normal package-manager behavior after the scan passes.

### Manifest

```sh
npx --yes execfence manifest
npx --yes execfence manifest diff
```

The manifest records execution surfaces such as package scripts, Makefiles, workflows, VS Code tasks, hooks, language build files, and agent rules.

`manifest.summary` reports `total`, `sensitive`, `directGuarded`, `covered`, and `uncovered`. A release can therefore show `directGuarded < total` while still being operationally OK when every sensitive entrypoint is covered by a prehook, workflow gate, or global shim.

### Config Validation

```sh
npx --yes execfence config validate
npx --yes execfence config validate --format json
npx --yes execfence config validate --strict
```

Config validation checks `.execfence/config/execfence.json`, `baseline.json`, `signatures.json`, `sandbox.json`, and local policy packs. It catches invalid regex signatures, expired baselines, executable allowlist entries without SHA-256, suspicious registry allowlists, sandbox enforce settings that would silently degrade, and strict supply-chain mode without complete coverage. `ci` runs config validation by default.

### Supply Chain

```sh
npx --yes execfence deps diff
npx --yes execfence deps review
npx --yes execfence deps review --base-ref main --package-manager yarn
npx --yes execfence deps review --format json
npx --yes execfence pack-audit
npx --yes execfence trust add tools/reviewed-helper.exe --reason "reviewed helper" --owner security --expires-at 2027-01-01
npx --yes execfence trust audit
```

These commands catch suspicious dependency drift, dangerous packaged files, unreviewed registries/actions/package scopes, and changed trusted artifacts. `deps review` aggregates supported manifests and lockfiles across JavaScript, Python, Rust, Go, JVM, .NET, PHP, and Ruby, then adds guarded metadata and reputation for new or changed packages: release cooldown, deprecation/security messaging, registry/source, integrity/checksum hints, provenance/signature hints where available, OSV advisory records, lifecycle/build/runtime hints, and recommended actions.

Metadata and reputation lookup is deliberately privacy-safe by default. It only queries allowlisted public registries, skips scoped packages unless `supplyChain.metadata.allowedPublicScopes` allows the scope, never uses npm tokens or `.npmrc` auth, caches under `.execfence/cache/`, caps packages per run, and treats network failure as a warning unless configured otherwise. The review also checks package age, recent metadata changes, maintainer presence, integrity, provenance/signature hints, package tarball content, and tarball delta against the previous resolved version when available.

Strict supply-chain mode is available for CI, release, or security-sensitive repositories:

```json
{
  "supplyChain": {
    "mode": "strict"
  }
}
```

`strict` blocks unavailable metadata/reputation/tarball signals, missing integrity/provenance signals, release cooldowns, new package age windows, uncovered package-manager surfaces, and dependency runtime audits without helper-backed containment.

For runtime-only dependency risk, attach changed-dependency review and sandbox containment status to a command:

```sh
npx --yes execfence run --dependency-behavior-audit --sandbox-mode audit -- npm test
```

This does not prove library code safe, but it records whether a test/build/start command that may import changed dependencies ran with network/process/filesystem containment or with degraded local enforcement. Runtime behavior risk is closed only when `--sandbox` uses a verified helper whose self-test proves the required outbound network blocking, sensitive-read denial, child-process supervision, and new executable/archive blocking. Unsupported capabilities remain blocking in strict/enforce; `--sandbox-mode audit` is evidence, not prevention.

### When Dependency Metadata Blocks Or Warns

Start with the report and the dependency review:

```sh
npx --yes execfence reports latest
npx --yes execfence deps review --format json
```

A block usually means ExecFence received a strong registry signal, such as a release inside the configured cooldown or security-relevant deprecation text. A warning means the package still needs review but the default policy is fail-open, for example because the registry was unreachable. Do not bypass with a private registry allowlist or public-scope allowlist unless sending those package names to that registry is acceptable for the project.

### Re-enable Lifecycle Scripts Safely

The global guard suppresses lifecycle scripts during install-like commands because recent npm attacks often used `preinstall`, `install`, or `postinstall`. If a package genuinely needs lifecycle scripts:

```sh
npx --yes execfence deps review
npx --yes execfence pack-audit
npx --yes execfence run --dependency-behavior-audit --sandbox-mode audit -- npm rebuild <package>
```

Review the package version, source, integrity, release age, and package contents first. Prefer a targeted rebuild or reviewed package script over rerunning a full install with scripts enabled.

### Token Theft Response

If ExecFence blocks a dependency or lifecycle payload that may have run before the guard was enabled:

1. Preserve `.execfence/reports/` and create an incident bundle.
2. Rotate npm, GitHub, cloud, CI, SSH, and package-publishing tokens that were reachable from the machine or runner.
3. Purge local and CI package caches before reinstalling.
4. Review new workflow files, package scripts, agent tool configs, and changed lockfiles with `agent-report`, `manifest diff`, and `deps review`.
5. Pin, downgrade, or remove the affected packages before re-enabling installs.

### Reports And Incidents

```sh
npx --yes execfence reports list
npx --yes execfence reports latest
npx --yes execfence reports show <report>
npx --yes execfence reports open <report>
npx --yes execfence reports diff <a> <b>
npx --yes execfence incident bundle --from-report .execfence/reports/<report>.json
```

Reports are JSON-first and timestamped. A report includes:

- package version and command
- cwd, platform, Node version
- git branch and commit
- effective config
- summary counts
- blocking summary with why blocked, how it can execute, affected ecosystem, activation surface, and next action
- findings with file, line, snippet, SHA-256, rule, remediation, confidence
- git blame and recent commits when available
- local analysis and suggested research queries
- runtime trace when available
- sandbox plan/capabilities when available
- enrichment status and sources when enabled

ExecFence never deletes suspicious payloads automatically. Quarantine data is metadata-only unless a future explicit feature safely copies redacted evidence.

## Using The Skill

The `execfence` skill is meant for coding agents. It tells the agent to add or use guardrails when working on persistent projects that may execute code or access the user's local machine.

The skill has been submitted to the OpenAI Skills catalog as [openai/skills#385](https://github.com/openai/skills/pull/385). Until that PR is merged, install it from the npm package.

Install from the package:

```sh
npx --yes execfence install-skill
```

This installs:

- Codex skill files under the local Codex skills directory
- global defaults under `<home>/.agents/skills/execfence/defaults.json`
- portable agent rules in common global agent instruction files

For project-local rules:

```sh
npx --yes execfence install-agent-rules --scope project
npx --yes execfence install-agent-rules --verify --scope project
```

When active, the skill should make the agent:

1. Detect the stack and execution surfaces.
2. Prefer `execfence init --preset auto`.
3. Prefer `execfence guard enable` and `execfence guard enable --apply` when the user wants automatic project setup.
4. Prefer `execfence run -- <command>` for dev/build/test commands.
5. Use `execfence run --sandbox-mode audit -- <command>` for higher-risk local execution.
6. Avoid ignoring `critical` or `high` findings unless a reviewed, unexpired baseline exists.
7. Use reports, manifest, coverage, dependency diff, pack audit, trust audit, and incident bundles when investigating a block.

## What To Do When ExecFence Blocks

1. Do not rerun the blocked project command outside ExecFence.
2. Open the newest report. If the block came from global npm guard, keep the guard enabled while reviewing:

   ```sh
   npx --yes execfence reports latest
   npx --yes execfence reports open <report>
   ```

   Disable global npm interception only when intentionally leaving guarded execution:

   ```sh
   npx --yes execfence guard global-disable
   ```

3. Preserve suspicious files and the report.
4. Review the finding file, line, snippet, SHA-256, git blame, and recent commits.
5. Run:

   ```sh
   npx --yes execfence incident bundle --from-report .execfence/reports/<report>.json
   ```

6. If dependency or lockfile risk is involved:

   ```sh
   npx --yes execfence deps diff
   npx --yes execfence pack-audit
   npx --yes execfence trust audit
   ```

7. If a credential could have been exposed, rotate it. ExecFence can preserve evidence, but it cannot prove a secret was not read by already-executed malware.

## CI Pattern

Recommended GitHub Actions shape:

```yaml
name: ExecFence

on:
  pull_request:
  push:
    branches: [main, master]

permissions:
  contents: read

jobs:
  guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<full-commit-sha>
      - uses: actions/setup-node@<full-commit-sha>
        with:
          node-version: 20
      - run: npx --yes execfence ci
      - run: npx --yes execfence run -- npm test
```

Use pinned action SHAs and least-privilege workflow permissions. Avoid `pull_request_target` for untrusted code unless the workflow is designed specifically for that risk.

## Release Cadence

ExecFence follows a weekly SemVer release cadence with planning checkpoints on Tuesday and Thursday and release readiness on Friday afternoon. The operational checklist lives in [Weekly Release Cadence](release-cadence.md).

## Design Principles

- Fail before execution when a blockable finding is present.
- Keep reports rich enough for incident response.
- Keep the default CLI dependency-free.
- Keep project-owned configuration inside `.execfence/`.
- Prefer explicit audit mode over silent security downgrade.
- Prefer narrow, hash-pinned exceptions over broad ignores.
- Treat agent/MCP tool configs as execution surfaces.
- Do not remove suspicious payloads automatically.

## References

- Trend Micro: [Void Dokkaebi Uses Fake Job Interview Lure to Spread Malware via Code Repositories](https://www.trendmicro.com/en_us/research/26/d/void-dokkaebi-uses-fake-job-interview-lure-to-spread-malware-via-code-repositories.html)
- Microsoft Security Blog: [Contagious Interview: Malware delivered through fake developer job interviews](https://www.microsoft.com/en-us/security/blog/2026/03/11/contagious-interview-malware-delivered-through-fake-developer-job-interviews/)
- Datadog Security Labs: [Compromised axios npm package delivers cross-platform RAT](https://securitylabs.datadoghq.com/articles/axios-npm-supply-chain-compromise/)
- OpenAI Skills catalog PR: [openai/skills#385](https://github.com/openai/skills/pull/385)
