# ExecFence: A Local Guardrail For Code That Runs During Development

Software projects do not wait for production to execute code. They run code during install, test, build, dev servers, package preparation, CI workflows, IDE automation, and increasingly through coding agents and MCP tools. That makes the developer workstation and CI runner part of the attack surface.

ExecFence was created for that narrow but serious problem: suspicious repository code becoming active during normal development.

It is a dependency-free CLI and agent skill that puts a reviewable fence around commands like:

```sh
npm test
npm run build
go test ./...
python -m pytest
cargo test
make
npm pack
npm publish
```

Instead of asking a developer or an agent to remember every risky execution surface, ExecFence makes the safer path explicit:

```sh
npx --yes execfence scan
npx --yes execfence run -- npm test
npx --yes execfence run --sandbox-mode audit -- npm run build
```

## Why This Project Was Created

ExecFence started from a practical incident-response question. A project build/test path produced a temporary Go test binary that local security tooling flagged as `PasswordStealer.Spyware.Stealer.DDS`. The immediate question was whether that specific binary was malicious. The larger question was more important:

> What should exist so a developer does not have to manually catch every injected payload before running build, dev, or test?

That question maps directly to a growing class of developer-targeted attacks. Trend Micro's research on Void Dokkaebi describes fake job interview lures that push developers toward code repositories and turn normal repository execution into a malware delivery path: [Void Dokkaebi Uses Fake Job Interview Lure to Spread Malware via Code Repositories](https://www.trendmicro.com/en_us/research/26/d/void-dokkaebi-uses-fake-job-interview-lure-to-spread-malware-via-code-repositories.html).

The lesson is simple: the attacker does not need the victim to run a file named `malware.exe`. The attacker can rely on developer habits:

- clone or open a repository
- trust an interview task, coding challenge, dependency, or workspace
- run build, dev, or test
- allow IDE tasks or package hooks to execute
- expose local tokens, browser data, wallets, SSH keys, cloud credentials, source code, or package publishing credentials

Microsoft's research on Contagious Interview describes a similar developer-trust problem, including malicious packages and Visual Studio Code workflow abuse after repository trust is granted: [Contagious Interview: Malware delivered through fake developer job interviews](https://www.microsoft.com/en-us/security/blog/2026/03/11/contagious-interview-malware-delivered-through-fake-developer-job-interviews/).

Datadog's analysis of the 2026 axios npm compromise shows the supply-chain version of the same execution problem: malicious releases introduced a dependency whose `postinstall` script downloaded and ran a cross-platform RAT during install, then removed evidence from disk: [Compromised axios npm package delivers cross-platform RAT](https://securitylabs.datadoghq.com/articles/axios-npm-supply-chain-compromise/).

ExecFence exists because these incidents share the same operational point of failure: ordinary developer commands can become the execution trigger.

## The Threat Model

ExecFence focuses on local and CI execution before code reaches production. It watches places where code can execute even when the user thinks they are only building, testing, installing, or reviewing a project.

Primary surfaces:

- `package.json` scripts and package-manager lifecycle hooks
- npm, pnpm, yarn, bun, Cargo, Go, Poetry, and uv lockfiles
- build config files such as Vite, Next, Webpack, Rollup, Tailwind, PostCSS, and ESLint configs
- `.vscode/tasks.json`, especially folder-open automation
- GitHub Actions workflows
- Makefiles and language-specific build files
- Tauri, Electron, VS Code extension, and MCP project surfaces
- committed executables and archives in source/build-input folders
- coding-agent instructions and tool manifests

ExecFence is designed to detect or block:

- known injected JavaScript loader indicators
- suspicious dynamic loaders
- obfuscated JavaScript patterns
- shell/download/eval behavior in install/build scripts
- suspicious lockfile URLs
- unexpected executable or archive artifacts
- unguarded new execution entrypoints
- workflow hardening problems
- broad agent or MCP access to shell, filesystem, browser, network, credentials, or local machine capabilities
- instructions that try to disable or bypass ExecFence/security checks

It is not a replacement for:

- antivirus or EDR
- dependency vulnerability scanning
- manual malware analysis
- full VM/container sandboxing
- secret scanning
- production runtime security

The project is intentionally scoped: guard the moment repository code is about to execute.

## How ExecFence Responds To The Void Dokkaebi Pattern

Trend Micro's Void Dokkaebi reporting matters because it centers the repository itself as the delivery mechanism. ExecFence maps that risk to operational controls:

| Attack pressure | ExecFence response |
| --- | --- |
| Developer is told to clone or open a repository | `execfence scan` inspects the project before execution. |
| The repository hides suspicious JavaScript | Scanner rules look for injected loader markers, dynamic loading, obfuscation, shell execution, and known IoCs. |
| IDE tasks run after trust is granted | `.vscode/tasks.json` and folder-open tasks are treated as execution surfaces. |
| Package install/build runs attacker code | Package lifecycle scripts and lockfiles are audited. |
| Malware drops or modifies binaries | Runtime trace can detect created/modified executable artifacts; `--deny-on-new-executable` can block after execution. |
| CI runs changed scripts | `manifest diff`, `coverage`, and `ci` identify new or unguarded execution entrypoints. |
| Agent tools expose broad capabilities | `agent-report` audits MCP/tool/agent configs for shell, filesystem, browser, credential, and network access. |
| A block needs investigation | Every blocking-capable command writes a JSON report under `.execfence/reports/`. |

ExecFence does not claim to identify every campaign sample. Its value is putting a default review and evidence layer at the point where suspicious repository code would become active.

## Main Functional Areas

ExecFence is not one command. It is a set of guardrails that work together.

### 1. Static Scanner

The scanner looks for known IoCs, suspicious loaders, risky scripts, workflow issues, lockfile problems, and unexpected binaries or archives.

```sh
npx --yes execfence scan
npx --yes execfence scan --mode audit
npx --yes execfence scan --changed-only --ci --format json
npx --yes execfence scan --ci --format sarif
```

Use it before running project code, in CI, and during review of suspicious changes.

### 2. Runtime Gate

The runtime gate wraps commands that execute repository code.

```sh
npx --yes execfence run -- npm test
npx --yes execfence run -- npm run build
npx --yes execfence run -- go test ./...
```

It performs a preflight scan, executes only if allowed, records runtime evidence, snapshots file changes, rescans changed files, and writes a report.

For artifact-sensitive workflows:

```sh
npx --yes execfence run --record-artifacts --deny-on-new-executable -- npm test
```

### 3. Sandbox Readiness

ExecFence V3 adds sandbox policy and capability checks.

```sh
npx --yes execfence sandbox init
npx --yes execfence sandbox doctor
npx --yes execfence sandbox plan -- npm test
npx --yes execfence run --sandbox-mode audit -- npm test
```

Audit mode records the sandbox profile, intended filesystem/process/network decisions, and local capability matrix.

Hard enforcement is explicit:

```sh
npx --yes execfence run --sandbox -- npm test
```

If enforcement is requested but the platform/helper cannot enforce filesystem, process, or network policy, ExecFence blocks before execution. It does not silently downgrade enforce mode to audit mode.

### 4. Execution Manifest And Coverage

ExecFence inventories execution entrypoints:

```sh
npx --yes execfence manifest
npx --yes execfence manifest diff
npx --yes execfence coverage
npx --yes execfence coverage --fix-suggestions
```

This helps answer:

- What can execute code in this repository?
- Which entrypoints are new?
- Which entrypoints are not wrapped by `execfence run`?
- Which package scripts, workflows, Makefile targets, VS Code tasks, or agent rules are sensitive?

### 5. Wiring

ExecFence can suggest or apply wrappers:

```sh
npx --yes execfence wire --dry-run
npx --yes execfence wire --apply
```

The goal is to move projects from:

```sh
npm test
```

to:

```sh
execfence run -- npm test
```

### 6. Supply-Chain Protection

ExecFence checks dependency and package publication surfaces:

```sh
npx --yes execfence deps diff
npx --yes execfence pack-audit
npx --yes execfence trust audit
```

It can flag suspicious registry drift, raw/gist/paste URLs, lifecycle/bin entries, package source changes, committed archives, dangerous package contents, and changed trusted files.

### 7. Agent And MCP Protection

Agents can execute commands, edit files, browse, use MCP tools, and touch local state. ExecFence treats agent instructions and MCP/tool manifests as execution surfaces:

```sh
npx --yes execfence agent-report
```

It looks for changes involving:

- package scripts
- workflows
- lockfiles
- executable configs
- agent instruction files
- MCP configs
- broad shell/filesystem/network/browser/credential tools
- instructions that try to disable ExecFence or security checks

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

Reports are gitignored by default. The project can opt into versioning reports with `reportsGitignore: false`.

## Evidence Reports

Every blocking-capable command writes a timestamped JSON report.

Reports include:

- package version and command
- cwd, platform, Node version
- git branch and commit
- effective config
- findings and severities
- file, line, snippet, SHA-256, rule, remediation, and confidence
- git blame and recent commits when available
- local analysis and suggested research queries
- runtime trace when available
- sandbox plan and capability matrix when available
- enrichment status when enabled

ExecFence does not delete suspicious payloads automatically. It preserves evidence first.

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
