# ExecFence: Guardrails Before Repository Code Executes

This is a technical launch article for ExecFence, a local guardrail for the moment a software project starts executing code on a developer machine, CI runner, or agent workspace.

The short version:

```sh
npx --yes execfence scan
npx --yes execfence run -- npm test
npx --yes execfence run --sandbox-mode audit -- npm run build
```

Before going deeper, it is important to separate two installation surfaces:

- **ExecFence CLI from npm**: the executable tool that runs in a terminal, shell, package script, or CI runner. This is what scans files, blocks commands, writes JSON reports, audits lockfiles, and returns exit codes.
- **ExecFence skill for Codex/agents**: an instruction package that runs inside the coding agent's context. It does not scan files by itself. It teaches the agent when to call the CLI and how to wire guardrails into a project.

In short: npm runs the guardrail; the skill teaches the agent to use the guardrail.

The ExecFence skill is also proposed for the OpenAI Skills catalog in [openai/skills#385](https://github.com/openai/skills/pull/385), which gives the project an external integration path beyond the npm package.

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

## If ExecFence Blocks

This is the most important operational path. A block usually happens at the moment a developer or agent is about to run project code, so the right response should be clear and boring:

```sh
npx --yes execfence reports latest
npx --yes execfence reports open <report>
npx --yes execfence incident bundle --from-report .execfence/reports/<report>.json
```

When ExecFence blocks:

1. Do not rerun the blocked command outside ExecFence.
2. Preserve the JSON report and suspicious files.
3. Review the finding id, severity, file, line, snippet, SHA-256, git blame, and recent commits.
4. Check package scripts, lockfiles, workflows, and agent/MCP configs related to the finding.
5. If already-executed code may have touched secrets, rotate credentials.

The report is the evidence handoff. It is designed to answer: what blocked, where it was, why it was suspicious, what changed recently, and what to inspect next.

## Why ExecFence Was Created

ExecFence started from a practical incident-response question. A project build/test path produced a temporary Go test binary that local security tooling flagged as `PasswordStealer.Spyware.Stealer.DDS`. The immediate question was whether that specific binary was malicious. The better engineering question was:

> What guardrail should exist so a developer does not need to manually notice every injected payload before running build, dev, or test?

That question maps directly to current developer-targeted attacks.

Trend Micro's research on Void Dokkaebi describes fake job interview lures that push developers toward code repositories and turn repository execution into a malware delivery path: [Void Dokkaebi Uses Fake Job Interview Lure to Spread Malware via Code Repositories](https://www.trendmicro.com/en_us/research/26/d/void-dokkaebi-uses-fake-job-interview-lure-to-spread-malware-via-code-repositories.html).

Microsoft's research on Contagious Interview describes a related trust problem: attackers use recruitment workflows, malicious packages, and Visual Studio Code task execution after repository trust is granted: [Contagious Interview: Malware delivered through fake developer job interviews](https://www.microsoft.com/en-us/security/blog/2026/03/11/contagious-interview-malware-delivered-through-fake-developer-job-interviews/).

Datadog's analysis of the 2026 axios npm compromise shows the supply-chain form of the same execution problem: malicious releases introduced a dependency with a `postinstall` script that downloaded and ran a cross-platform RAT during install, then removed traces from disk: [Compromised axios npm package delivers cross-platform RAT](https://securitylabs.datadoghq.com/articles/axios-npm-supply-chain-compromise/).

The shared lesson is operational: ordinary developer commands can become the execution trigger.

## CLI Install vs Codex Skill Install

ExecFence has two installation paths because there are two different users of the tool: humans/CI running commands, and coding agents deciding which commands to run.

### The npm CLI

The npm package provides the actual `execfence` command.

You can run it without a global install:

```sh
npx --yes execfence scan
npx --yes execfence run -- npm test
npx --yes execfence ci
```

Or install it globally if you prefer:

```sh
npm install -g execfence
execfence scan
```

The CLI runs in:

- your terminal
- package scripts
- GitHub Actions or other CI runners
- local shell sessions used by agents
- pre-commit hooks
- build/test/publish workflows

The CLI is the part that performs enforcement and evidence collection:

- scans files
- checks package scripts and lockfiles
- blocks risky findings
- wraps commands with `execfence run -- <command>`
- records runtime traces
- writes `.execfence/reports/*.json`
- audits dependency diffs and package contents
- checks sandbox capability and audit/enforce mode
- exits nonzero when policy says a command must fail

If you only want terminal/CI protection, the npm CLI is enough.

### The Codex/Agent Skill

The skill is different. It is not the scanner. It is an instruction layer for Codex and compatible agent workflows.

Install it with:

```sh
npx --yes execfence install-skill
```

That command installs:

- the Codex skill under the local Codex skills directory
- default skill config at `<home>/.agents/skills/execfence/defaults.json`
- global agent instructions that tell agents to prefer ExecFence before risky project execution

After that, Codex can use the skill when it is working on a persistent project. The skill should make the agent:

- detect execution surfaces before running project code
- call `npx --yes execfence init --preset auto` when guardrails are missing
- prefer `execfence run -- <command>` instead of raw `npm test`, `go test`, or similar commands
- use `execfence run --sandbox-mode audit -- <command>` for higher-risk local execution
- run `execfence ci`, `coverage`, `deps diff`, `pack-audit`, and `agent-report` when appropriate
- avoid ignoring `critical` or `high` findings unless a reviewed baseline exists
- preserve `.execfence/reports/*.json` after a block

The skill runs in the agent's reasoning context. The CLI runs in the operating system process. That distinction matters:

| Question | npm CLI | Codex/agent skill |
| --- | --- | --- |
| Does it scan files? | Yes | No, it tells the agent to run the CLI |
| Does it block commands? | Yes, by exit code | No, it instructs the agent not to bypass blocks |
| Does it write reports? | Yes, under `.execfence/reports/` | No, but it tells the agent to preserve/read reports |
| Does it run in CI? | Yes | No |
| Does it change agent behavior? | Only if the agent calls it | Yes |
| Is it useful without Codex? | Yes | No, except as portable guidance |
| Is it useful without npm CLI? | No | Limited; it needs a guardrail command to invoke |

For best results, use both:

```sh
npx --yes execfence install-skill
npx --yes execfence init --preset auto
npx --yes execfence run -- npm test
```

This gives the human and CI a real command-line guardrail, and gives Codex/agents the instruction to keep using it.

### Project-Local Agent Rules

There is a third, portable option:

```sh
npx --yes execfence install-agent-rules --scope project
```

This writes project-local rules for tools such as Codex, Claude, Gemini, Cursor, Copilot, Continue, Windsurf, Aider, Roo, and Cline.

Use this when the repository itself should carry the instruction:

> before running build/dev/test or changing execution surfaces, use ExecFence.

This is useful for teams because the rule travels with the repository instead of living only in one developer's global Codex setup.

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

ExecFence combines exact IoC matching, project/team regex signatures, suspicious loader heuristics, lifecycle-script audit, lockfile source review, executable/archive detection, workflow hardening checks, and agent/MCP surface audit.

The important design choice is scope: rules are weighted toward files that execute during development, build, test, CI, package, publish, IDE, or agent workflows. ExecFence is not trying to lint every source file; it is trying to catch suspicious code where a normal command can activate it.

For the full technical detection breakdown, including baselines and exceptions, see [Detection Model](./detection).

## Mapping To Real Attack Patterns

| Public case | Attack pattern | ExecFence control |
| --- | --- | --- |
| Trend Micro Void Dokkaebi | Fake interview repositories and malicious code execution through developer workflows | `scan`, known IoCs, loader heuristics, VS Code task checks, runtime gate |
| Microsoft Contagious Interview | Recruitment workflow abuse, malicious packages, VS Code trust/task execution | `coverage`, `.vscode/tasks.json` audit, package lifecycle checks, `run --sandbox-mode audit` |
| Datadog axios compromise | Compromised npm releases added a dependency with `postinstall` RAT execution and cleanup behavior | lifecycle script audit, lockfile diff, deps diff, pack audit, reports, CI gate |

ExecFence does not claim campaign attribution. It turns the lessons from those incidents into local controls around execution.

## Main Functional Areas

### Essential Commands

These are the commands most projects should start with:

```sh
npx --yes execfence init --preset auto
npx --yes execfence scan
npx --yes execfence run -- npm test
npx --yes execfence ci
```

Use them to initialize policy, scan before execution, wrap local test/build commands, and run the aggregate CI guard.

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

Example output:

```json
{
  "ok": false,
  "sensitiveChanges": ["mcp.json"],
  "mcpFindings": [
    {
      "id": "agent-mcp-shell-access",
      "severity": "high",
      "file": "mcp.json",
      "line": 4,
      "detail": "MCP/tool config exposes broad shell or process execution capability."
    },
    {
      "id": "agent-disable-execfence-instruction",
      "severity": "high",
      "file": "mcp.json",
      "line": 5,
      "detail": "Agent or tool instruction appears to disable, skip, ignore, or bypass ExecFence/security guardrails."
    }
  ]
}
```

This is one of the more differentiated parts of ExecFence: it treats agent tooling as part of the execution surface, not as a trusted control plane by default.

### Advanced Commands

These commands are useful once the basic workflow is in place:

```sh
npx --yes execfence scan --changed-only --ci --format json
npx --yes execfence scan --ci --format sarif
npx --yes execfence manifest diff
npx --yes execfence coverage --fix-suggestions
npx --yes execfence wire --dry-run
npx --yes execfence deps diff
npx --yes execfence pack-audit
npx --yes execfence trust audit
npx --yes execfence reports diff <old-report.json> <new-report.json>
npx --yes execfence pr-comment --report .execfence/reports/<report>.json
```

Use them for CI output, PR review, lockfile investigation, package publishing checks, report comparison, and team adoption.

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

For scanner internals, rule layers, and exception policy, continue to the [Detection Model](./detection).

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
