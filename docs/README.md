# ExecFence Documentation

ExecFence is a local execution guardrail for projects that run code during development, build, test, CI, packaging, or agent workflows. It was created to stop the specific class of incident where a developer clones or opens a repository, runs a normal project command, and unintentionally executes attacker-controlled code.

The project intentionally sits close to the developer workflow:

- before `npm test`, `go test`, `cargo test`, `python -m pytest`, `npm run build`, `make`, packaging, or publishing
- around project commands through `execfence run -- <command>`
- inside CI through `execfence ci`
- in agent workflows through the `execfence` skill and portable agent rules
- in investigation workflows through automatic JSON reports, evidence bundles, baselines, trust stores, and incident helpers

ExecFence is not an antivirus, EDR, SCA platform, or remote sandbox service. It is a lightweight, dependency-free CLI and agent skill that focuses on one narrow but high-impact problem: suspicious code becoming active during normal development.

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
| Package install/build runs attacker code | npm/pnpm/yarn/bun lifecycle scripts and lockfiles are audited. |
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
- npm/pnpm/yarn/bun lifecycle scripts with download/eval/shell behavior
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

Use hard sandbox enforcement only when the local platform/helper can actually enforce the requested controls:

```sh
npx --yes execfence run --sandbox -- npm test
```

If hard enforcement is requested and filesystem/process/network enforcement is unavailable, ExecFence blocks before running the command. It never silently downgrades `--sandbox` to audit mode.

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
- `helper.path`, `helper.requiredForEnforce`

## Commands By Job

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
npx --yes execfence helper audit
```

Audit mode records the plan and local capability matrix. Enforce mode requires actual enforcement support. Without a verified helper/capability, enforce mode blocks before execution.

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

`coverage` finds execution entrypoints that are not protected by `execfence run` or equivalent guardrails. `wire` suggests or applies wrappers.

`guard` is the automatic project mode. It runs `init`, checks coverage, applies wiring, installs project-local agent rules, and summarizes remaining gaps. Global guard mode is intentionally non-invasive:

```sh
npx --yes execfence guard global-status
npx --yes execfence guard global-enable
```

It installs skill/defaults and global agent rules only. It does not alter PATH, aliases, shims, shell profiles, or globally intercept package-manager commands.

### Manifest

```sh
npx --yes execfence manifest
npx --yes execfence manifest diff
```

The manifest records execution surfaces such as package scripts, Makefiles, workflows, VS Code tasks, hooks, language build files, and agent rules.

### Supply Chain

```sh
npx --yes execfence deps diff
npx --yes execfence pack-audit
npx --yes execfence trust add tools/reviewed-helper.exe --reason "reviewed helper" --owner security --expires-at 2027-01-01
npx --yes execfence trust audit
```

These commands catch suspicious dependency drift, dangerous packaged files, unreviewed registries/actions/package scopes, and changed trusted artifacts.

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
- findings with file, line, snippet, SHA-256, rule, remediation, confidence
- git blame and recent commits when available
- local analysis and suggested research queries
- runtime trace when available
- sandbox plan/capabilities when available
- enrichment status and sources when enabled

ExecFence never deletes suspicious payloads automatically. Quarantine data is metadata-only unless a future explicit feature safely copies redacted evidence.

## Using The Skill

The `execfence` skill is meant for coding agents. It tells the agent to add or use guardrails when working on persistent projects that may execute code or access the user's local machine.

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
2. Open the newest report:

   ```sh
   npx --yes execfence reports latest
   npx --yes execfence reports open <report>
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
- OpenAI Skills catalog: [openai/skills](https://github.com/openai/skills)
