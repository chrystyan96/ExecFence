# ExecFence: Guardrails Before Repository Code Executes

This is a technical launch article for ExecFence, a local guardrail for the moment a software project starts executing code on a developer machine, CI runner, or agent workspace.

The short version:

```sh
npx --yes execfence scan
npx --yes execfence run -- npm test
npx --yes execfence run --sandbox-mode audit -- npm run build
```

ExecFence exists because malicious code does not need to look like an obvious executable. It can hide in package hooks, build configs, IDE tasks, lockfiles, CI workflows, or agent tool manifests. The dangerous moment is often mundane: a developer runs test/build/dev, opens a folder in an IDE, installs dependencies, or lets an agent run the project.

## Quick Start

Run a scan:

```sh
npx --yes execfence scan
```

Expected clean output:

```text
[execfence] OK
[execfence] wrote report to /project/.execfence/reports/my-app_2026-05-01T19-00-00-000Z.json
```

Run a project command through the runtime gate:

```sh
npx --yes execfence run -- npm test
```

Expected clean runtime behavior:

```text
[execfence] preflight scan: OK
> npm test
...
[execfence] post-run scan: OK
[execfence] runtime report: /project/.execfence/reports/my-app_2026-05-01T19-01-00-000Z.json
```

If ExecFence detects a known injected loader marker or suspicious execution pattern, the command fails before project code runs:

```text
[execfence] blocked suspicious finding(s)

critical  void-dokkaebi-loader-marker  tailwind.config.js:1
Injected JavaScript loader marker associated with suspicious repository execution.

[execfence] wrote report to /project/.execfence/reports/my-app_2026-05-01T19-02-00-000Z.json
```

For higher-risk local execution, use sandbox audit mode:

```sh
npx --yes execfence sandbox doctor
npx --yes execfence sandbox plan -- npm test
npx --yes execfence run --sandbox-mode audit -- npm test
```

Hard sandbox enforcement is explicit:

```sh
npx --yes execfence run --sandbox -- npm test
```

If the platform or helper cannot enforce filesystem, process, or network policy, ExecFence blocks before execution. It does not silently downgrade `--sandbox` to audit mode.

## Why ExecFence Was Created

ExecFence started from a practical incident-response question. A project build/test path produced a temporary Go test binary that local security tooling flagged as `PasswordStealer.Spyware.Stealer.DDS`. The immediate question was whether that specific binary was malicious. The better engineering question was:

> What guardrail should exist so a developer does not need to manually notice every injected payload before running build, dev, or test?

That question maps directly to current developer-targeted attacks.

Trend Micro's research on Void Dokkaebi describes fake job interview lures that push developers toward code repositories and turn repository execution into a malware delivery path: [Void Dokkaebi Uses Fake Job Interview Lure to Spread Malware via Code Repositories](https://www.trendmicro.com/en_us/research/26/d/void-dokkaebi-uses-fake-job-interview-lure-to-spread-malware-via-code-repositories.html).

Microsoft's research on Contagious Interview describes a related trust problem: attackers use recruitment workflows, malicious packages, and Visual Studio Code task execution after repository trust is granted: [Contagious Interview: Malware delivered through fake developer job interviews](https://www.microsoft.com/en-us/security/blog/2026/03/11/contagious-interview-malware-delivered-through-fake-developer-job-interviews/).

Datadog's analysis of the 2026 axios npm compromise shows the supply-chain form of the same execution problem: malicious releases introduced a dependency with a `postinstall` script that downloaded and ran a cross-platform RAT during install, then removed traces from disk: [Compromised axios npm package delivers cross-platform RAT](https://securitylabs.datadoghq.com/articles/axios-npm-supply-chain-compromise/).

The shared lesson is operational: ordinary developer commands can become the execution trigger.

## How ExecFence Fits Into A Security Stack

ExecFence is not an antivirus, EDR, SCA platform, secret scanner, or malware sandbox. It does not try to replace those tools.

It sits earlier in the workflow:

```text
clone/open repo -> inspect execution surfaces -> scan -> gate command -> record evidence -> run existing security tools
```

Use it with:

- EDR/AV for endpoint behavior and malware response
- SCA for known vulnerable dependencies
- secret scanning for leaked tokens
- lockfile review and package provenance checks
- CI hardening and least-privilege credentials
- containers or VMs when true isolation is required

ExecFence's role is to stop or document suspicious execution before a normal project command becomes the payload trigger.

## Why Dependency-Free Matters

ExecFence's base CLI intentionally has zero runtime dependencies.

That matters in this threat model because installing a security tool should not create a large new dependency tree with its own install hooks, transitive packages, typosquatting surface, or postinstall behavior. A guardrail for package-execution risk should be small enough to inspect, run through `npx`, and package with low supply-chain blast radius.

Dependency-free also helps in CI and incident response:

- less network and install behavior before the first scan
- fewer transitive packages to audit
- fewer lifecycle hooks pulled in by the tool itself
- easier `npm pack --dry-run` review
- simpler use in temporary or suspicious workspaces

Optional helpers may exist for future platform enforcement, but the base scanner, runtime gate, reports, CI command, and skill remain usable without mandatory helper installation.

## What The Scanner Inspects

The scanner is designed around execution surfaces, not only source files.

It inspects:

- JavaScript/TypeScript executable configs
- package scripts and lifecycle hooks
- npm/pnpm/yarn/bun lockfiles
- Cargo, Go, Poetry, and uv lockfiles
- GitHub Actions workflows
- `.vscode/tasks.json`
- Makefiles
- Tauri/Electron/VS Code extension surfaces
- committed executable and archive artifacts
- MCP and agent instruction/config files
- project-specific signatures in `.execfence/config/signatures.json`
- reviewed baseline exceptions in `.execfence/config/baseline.json`

It skips normal generated or dependency directories such as `.git`, `node_modules`, `dist`, `build`, `coverage`, `target`, caches, and test output by default.

## How Detection Works

ExecFence combines several low-noise rule types.

### Exact IoC Matching

Known suspicious markers are detected as literal indicators. Examples include injected JavaScript loader markers and suspicious blockchain/RPC endpoints associated with known malicious repository payloads.

This is intentionally simple: exact matching is fast, deterministic, and explainable.

### Regex Signatures

Regex rules catch families of suspicious code that do not have a single stable string. Project teams can add their own regexes in:

```text
.execfence/config/signatures.json
```

Use this for team-specific IoCs instead of editing scanner code.

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

ExecFence looks for risky behavior such as:

- shell downloads
- pipe-to-shell
- hidden PowerShell
- `curl` or `wget` execution chains
- eval-style execution
- suspicious binary launch paths
- install hooks in local packages/workspaces

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

### Workflow And Agent Surface Audit

ExecFence treats CI and agents as execution surfaces. It audits:

- GitHub Actions permissions and risky triggers
- unpinned actions
- `curl | bash`
- publish workflows without provenance
- agent instruction files
- MCP/tool configs with broad shell, filesystem, browser, credential, or network access
- instructions attempting to skip or disable ExecFence/security checks

## Mapping To Real Attack Patterns

| Public case | Attack pattern | ExecFence control |
| --- | --- | --- |
| Trend Micro Void Dokkaebi | Fake interview repositories and malicious code execution through developer workflows | `scan`, known IoCs, loader heuristics, VS Code task checks, runtime gate |
| Microsoft Contagious Interview | Recruitment workflow abuse, malicious packages, VS Code trust/task execution | `coverage`, `.vscode/tasks.json` audit, package lifecycle checks, `run --sandbox-mode audit` |
| Datadog axios compromise | Compromised npm releases added a dependency with `postinstall` RAT execution and cleanup behavior | lifecycle script audit, lockfile diff, deps diff, pack audit, reports, CI gate |

ExecFence does not claim campaign attribution. It turns the lessons from those incidents into local controls around execution.

## Main Functional Areas

### Static Scan

```sh
npx --yes execfence scan
npx --yes execfence scan --mode audit
npx --yes execfence scan --changed-only --ci --format json
npx --yes execfence scan --ci --format sarif
```

Use this before running project code, during review, and in CI.

### Runtime Gate

```sh
npx --yes execfence run -- npm test
npx --yes execfence run -- npm run build
npx --yes execfence run -- go test ./...
npx --yes execfence run -- python -m pytest
npx --yes execfence run -- cargo test
```

`run` performs:

1. preflight scan
2. command execution only if allowed
3. runtime trace
4. file snapshot comparison
5. post-run scan of changed files
6. JSON report generation

For artifact-sensitive workflows:

```sh
npx --yes execfence run --record-artifacts --deny-on-new-executable -- npm test
```

### Sandbox Audit And Enforce Mode

```sh
npx --yes execfence sandbox init
npx --yes execfence sandbox doctor
npx --yes execfence sandbox plan -- npm test
npx --yes execfence run --sandbox-mode audit -- npm test
```

Audit mode records what would be allowed or blocked across filesystem, process, and network policy.

Enforce mode is explicit:

```sh
npx --yes execfence run --sandbox -- npm test
```

If enforcement is unavailable, the command blocks before running. Downgrade requires explicit `--sandbox-mode audit` or `--allow-degraded`.

### Execution Manifest And Coverage

```sh
npx --yes execfence manifest
npx --yes execfence manifest diff
npx --yes execfence coverage
npx --yes execfence coverage --fix-suggestions
```

These commands answer:

- What can execute code in this repository?
- What changed since the last manifest?
- Which sensitive entrypoints are unguarded?
- What exact wrapper should be added?

### Wiring

```sh
npx --yes execfence wire --dry-run
npx --yes execfence wire --apply
```

This helps move project commands from:

```sh
npm test
```

to:

```sh
execfence run -- npm test
```

### Supply Chain And Package Audit

```sh
npx --yes execfence deps diff
npx --yes execfence pack-audit
npx --yes execfence trust audit
```

These commands focus on lockfile drift, suspicious package sources, dangerous package contents, and changed trusted artifacts.

### Agent And MCP Report

```sh
npx --yes execfence agent-report
```

This flags sensitive changes in:

- package scripts
- workflows
- lockfiles
- config files that execute code
- agent instruction files
- MCP configs
- broad shell/filesystem/network/browser/credential tool definitions

## Evidence Reports

Every blocking-capable command writes a new JSON report under:

```text
.execfence/reports/
```

Reports include:

- command and package version
- cwd, platform, Node version
- git branch and commit
- effective config
- total, blocked, warning, and suppressed findings
- finding id, severity, file, line, snippet, SHA-256
- rule, reason, remediation, and confidence
- git blame and recent commits when available
- local analysis and suggested research queries
- runtime trace when available
- sandbox plan and capability matrix when available
- enrichment status when enabled

ExecFence does not delete suspicious payloads automatically. It preserves evidence first.

## Project Layout

ExecFence keeps project-owned state under `.execfence/`:

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

Important files:

- `.execfence/config/execfence.json`: main project policy
- `.execfence/config/signatures.json`: team-owned IoCs and regex rules
- `.execfence/config/baseline.json`: reviewed exceptions with owner, reason, expiry, and hash
- `.execfence/config/sandbox.json`: sandbox audit/enforce policy
- `.execfence/reports/`: JSON evidence reports
- `.execfence/trust/`: reviewed trust stores
- `.execfence/quarantine/`: metadata-only quarantine evidence
- `.execfence/manifest.json`: execution-surface inventory

Reports are gitignored by default. A project can opt into versioning reports with `reportsGitignore: false`.

## Recommended Adoption Path

For an existing project:

```sh
npx --yes execfence init --preset auto
npx --yes execfence scan
npx --yes execfence coverage
npx --yes execfence wire --dry-run
npx --yes execfence run -- npm test
```

For a project with existing noise:

```sh
npx --yes execfence adopt
npx --yes execfence adopt --write-baseline
```

For CI:

```sh
npx --yes execfence ci
```

For higher-risk local execution:

```sh
npx --yes execfence sandbox doctor
npx --yes execfence sandbox plan -- npm test
npx --yes execfence run --sandbox-mode audit -- npm test
```

## Using The Skill

ExecFence also ships as a skill for coding agents.

Install:

```sh
npx --yes execfence install-skill
```

Install project-local agent rules:

```sh
npx --yes execfence install-agent-rules --scope project
npx --yes execfence install-agent-rules --verify --scope project
```

When active, the skill should make the agent:

1. Detect the stack and execution surfaces.
2. Prefer `execfence init --preset auto`.
3. Prefer `execfence run -- <command>` for dev/build/test commands.
4. Use `execfence run --sandbox-mode audit -- <command>` for higher-risk local execution.
5. Avoid ignoring `critical` or `high` findings unless a reviewed, unexpired baseline exists.
6. Use reports, manifest, coverage, dependency diff, pack audit, trust audit, and incident bundles when investigating a block.

## What To Do When ExecFence Blocks

1. Do not rerun the blocked command outside ExecFence.
2. Preserve the report and suspicious files.
3. Open the newest report:

   ```sh
   npx --yes execfence reports latest
   npx --yes execfence reports open <report>
   ```

4. Build an incident bundle:

   ```sh
   npx --yes execfence incident bundle --from-report .execfence/reports/<report>.json
   ```

5. Review git blame, recent commits, snippets, hashes, lockfiles, workflows, package scripts, and agent/tool configs.
6. Rotate credentials if already-executed code may have touched secrets.

## Design Principles

- Block before execution when a blockable finding is present.
- Keep reports rich enough for incident response.
- Keep the base CLI dependency-free.
- Keep project-owned configuration under `.execfence/`.
- Prefer explicit audit mode over silent downgrade.
- Prefer narrow, hash-pinned exceptions over broad ignores.
- Treat agent/MCP tool configs as execution surfaces.
- Do not remove suspicious payloads automatically.

## Links

- GitHub Pages: [https://chrystyan96.github.io/ExecFence/](https://chrystyan96.github.io/ExecFence/)
- Repository: [https://github.com/chrystyan96/ExecFence](https://github.com/chrystyan96/ExecFence)
- npm package: [https://www.npmjs.com/package/execfence](https://www.npmjs.com/package/execfence)
- OpenAI Skills PR: [https://github.com/openai/skills/pull/385](https://github.com/openai/skills/pull/385)

## References

- Trend Micro: [Void Dokkaebi Uses Fake Job Interview Lure to Spread Malware via Code Repositories](https://www.trendmicro.com/en_us/research/26/d/void-dokkaebi-uses-fake-job-interview-lure-to-spread-malware-via-code-repositories.html)
- Microsoft Security Blog: [Contagious Interview: Malware delivered through fake developer job interviews](https://www.microsoft.com/en-us/security/blog/2026/03/11/contagious-interview-malware-delivered-through-fake-developer-job-interviews/)
- Datadog Security Labs: [Compromised axios npm package delivers cross-platform RAT](https://securitylabs.datadoghq.com/articles/axios-npm-supply-chain-compromise/)
