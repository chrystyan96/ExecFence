# ExecFence

ExecFence is a local execution guardrail for projects that run code during development, build, test, CI, packaging, publishing, or agent workflows.

It was created for a specific failure mode: a repository looks like normal source code, but contains injected code, suspicious scripts, task files, package hooks, binaries, archives, or agent/tool configuration that can execute when a developer or coding agent runs an ordinary command.

Full documentation: [chrystyan96.github.io/ExecFence](https://chrystyan96.github.io/ExecFence/)

Technical detection reference: [Detection Model](https://chrystyan96.github.io/ExecFence/detection)

OpenAI Skills catalog PR: [openai/skills#385](https://github.com/openai/skills/pull/385)

## Why It Exists

Public incidents increasingly show developer machines being targeted through project execution paths, not only through deployed applications. Examples include fake interview repositories, malicious package lifecycle hooks, suspicious editor tasks, and compromised packages that execute during install or build.

Background reading:

- Trend Micro: [Void Dokkaebi Uses Fake Job Interview Lure to Spread Malware via Code Repositories](https://www.trendmicro.com/en_us/research/26/d/void-dokkaebi-uses-fake-job-interview-lure-to-spread-malware-via-code-repositories.html)
- Microsoft: [Contagious Interview: Malware delivered through fake developer job interviews](https://www.microsoft.com/en-us/security/blog/2026/03/11/contagious-interview-malware-delivered-through-fake-developer-job-interviews/)
- Datadog Security Labs: [Compromised axios npm package delivers cross-platform RAT](https://securitylabs.datadoghq.com/articles/axios-npm-supply-chain-compromise/)
- ExecFence analysis: [npm Supply Chain Assessment](https://chrystyan96.github.io/ExecFence/npm-supply-chain-assessment)

ExecFence does not replace antivirus, EDR, dependency review, secret scanning, or SCA. It adds a local fence at the moment suspicious repository content would become active: before `test`, `build`, `dev`, `pack`, `publish`, CI, or agent-driven execution.

Current detection coverage includes injected JavaScript loader markers, suspicious executable configs, folder-open editor tasks, risky GitHub Actions, unexpected binaries or archives, lockfile source risk, and npm lifecycle scripts that download, evaluate, pipe to shells, or launch Windows LOLBins such as `bitsadmin`, `mshta`, `rundll32`, and `regsvr32`.

## Two Ways To Use ExecFence

ExecFence has two installation/use paths. They are related, but they do not do the same thing.

| Path | Runs where | What it does | Use it when |
| --- | --- | --- | --- |
| npm CLI: `npx --yes execfence ...` | Terminal, package scripts, CI | Actually scans files, gates commands, writes reports, audits dependencies, and returns blocking exit codes | You want protection now, without relying on an agent |
| Agent skill: `npx --yes execfence install-skill` | Codex and compatible agent instruction systems | Installs instructions telling agents when and how to use the ExecFence CLI | You use Codex or other coding agents on persistent projects |
| Project agent rules: `install-agent-rules --scope project` | Repository-local agent instruction files | Carries ExecFence rules with the project so agents see them in future sessions | You want the repo itself to instruct agents to run ExecFence |

The CLI is the enforcement tool. The skill is the operating rule for agents. For agent-heavy work, install both.

## Use The npm CLI

Run ExecFence without a global install:

```sh
npx --yes execfence scan
```

Recommended automatic project setup:

```sh
npx --yes execfence guard enable
npx --yes execfence guard enable --apply
npx --yes execfence guard status
```

`guard enable` is a dry-run by default. It plans project config, wrappers for scripts/workflows/tasks, CI checks, local agent rules, and coverage status. Use `--apply` to write those project-local changes.

Rollback generated wrappers and marked project agent rules:

```sh
npx --yes execfence guard disable
```

`guard disable` preserves reports, config, baselines, signatures, trust stores, cache, and quarantine metadata.

Gate a command before it runs:

```sh
npx --yes execfence run -- npm test
npx --yes execfence run -- npm run build
```

Run the CI guardrail bundle:

```sh
npx --yes execfence ci
```

Initialize project config:

```sh
npx --yes execfence init --preset auto
```

Check whether build/dev/test entrypoints are protected:

```sh
npx --yes execfence coverage
```

Preview or apply wrappers around risky entrypoints:

```sh
npx --yes execfence wire --dry-run
npx --yes execfence wire --apply
```

Audit package contents before publishing:

```sh
npx --yes execfence pack-audit
```

Use sandbox planning/audit mode:

```sh
npx --yes execfence sandbox doctor
npx --yes execfence sandbox plan -- npm test
npx --yes execfence run --sandbox-mode audit -- npm test
```

Use sandbox enforcement when available:

```sh
npx --yes execfence run --sandbox -- npm test
```

If the requested enforcement capability is unavailable, ExecFence should block before execution and explain what is missing. It does not silently downgrade enforcement.

Global package-manager guard setup:

```sh
npx --yes execfence guard global-status
npx --yes execfence guard global-enable
npx --yes execfence guard global-disable
```

Global guard mode installs skill/defaults, global agent rules, and reversible `npm`/`npx`/`pnpm`/`yarn`/`yarnpkg`/`bun`/`bunx` shims under `<home>/.execfence/shims/`. It adds marked shell-profile blocks so terminal commands and agent-run package-manager commands enter ExecFence before the real tool starts. `global-disable` removes the shims and profile blocks.

Install-like commands such as `npm install`, `pnpm add`, `yarn install`, `bun add`, `ci`, `update`, and `rebuild` get a clean preflight scan, guarded dependency review, and lifecycle-script suppression before delegation. npm and Bun use `--ignore-scripts=true`, pnpm uses `--ignore-scripts`, Yarn 1 uses `--ignore-scripts=true`, and Yarn 2+ runs with `YARN_ENABLE_SCRIPTS=0`. Script-running commands such as `npm run`, `pnpm test`, `yarn start`, `bun test`, `pack`, and `publish` keep their primary script semantics after the scan passes.

Review changed dependency versions and guarded metadata before install or CI:

```sh
npx --yes execfence deps review
npx --yes execfence deps review --base-ref main --package-manager pnpm
npx --yes execfence deps review --format json
```

`deps review` aggregates `package-lock.json`, `pnpm-lock.yaml`, and `yarn.lock`. Metadata and reputation checks are guarded: public npm registry lookups are limited to new or changed packages, scoped packages are skipped unless allowlisted, non-allowlisted registries are skipped, no npm tokens are used, results are cached under `.execfence/cache/`, and network failures warn by default. It also reviews package age, recent metadata changes, maintainer presence, integrity, provenance/signature hints, OSV advisory records, package tarball contents, and tarball delta against the previous resolved version when available.

For security-sensitive CI or release workflows, enable strict supply-chain mode:

```json
{
  "supplyChain": {
    "mode": "strict"
  }
}
```

`strict` blocks unavailable metadata/reputation/tarball signals, missing integrity/provenance signals, release cooldowns, new package age windows, uncovered package-manager surfaces, and dependency runtime audits that lack helper-backed containment.

Audit runtime behavior for commands likely to import changed dependencies:

```sh
npx --yes execfence run --dependency-behavior-audit --sandbox-mode audit -- npm test
```

Audit mode records containment evidence. To close runtime behavior risk, `--sandbox` requires a verified helper that declares enforcement for outbound network blocking, sensitive path reads, child-process supervision, and new executable/archive blocking; otherwise ExecFence blocks instead of silently downgrading.

## Use The Skill

Install the skill:

```sh
npx --yes execfence install-skill
```

The skill is for Codex and compatible coding agents. It teaches the agent to:

- run `execfence scan` before risky build/dev/test actions
- prefer `execfence run -- <command>` when executing project commands
- use sandbox audit/planning when available
- avoid ignoring `critical` or `high` findings without an explicit, justified baseline
- preserve `.execfence/reports/` evidence instead of deleting suspicious files automatically
- check agent/MCP/tool configuration changes with `execfence agent-report`

The skill does not scan a repository by itself. It makes the agent call the CLI.

Skill installation writes global defaults under:

```text
<home>/.agents/skills/execfence/defaults.json
```

Treat that file as package/skill-owned reference data. Users should normally edit project config in `.execfence/config/`, not the global defaults file.

## Add Project-Local Agent Rules

To make a repository carry ExecFence guidance for future agent sessions:

```sh
npx --yes execfence install-agent-rules --scope project
```

Verify configured rules:

```sh
npx --yes execfence install-agent-rules --verify
```

These rules are intended for Codex, Claude, Gemini, Cursor, Copilot, Continue, Windsurf, Aider, Roo, Cline, and similar tools. They tell agents to use the CLI before executing project code.

## Project Configuration

After `init`, ExecFence uses a project-local `.execfence/` directory:

```text
.execfence/
  config/
    execfence.json
    signatures.json
    baseline.json
    sandbox.json
  reports/
  cache/
  quarantine/
  trust/
  manifest.json
```

Main user-editable files:

| File | Purpose |
| --- | --- |
| `.execfence/config/execfence.json` | Main project policy: mode, policy packs, fail/warn severities, reports, enrichment, CI behavior |
| `.execfence/config/signatures.json` | Project-specific detection signatures |
| `.execfence/config/baseline.json` | Time-bound, owner-backed exceptions for known findings |
| `.execfence/config/sandbox.json` | Sandbox audit/enforcement profile and filesystem/process/network policy |
| `.execfence/trust/*.json` | Trusted files, registries, package scopes, actions, and package sources |

Reports are written to `.execfence/reports/` by default. ExecFence adds this directory to `.gitignore` unless project config sets reports to be versioned.

## When ExecFence Blocks

Do not rerun the same command outside ExecFence just to get past the block. Start with the report:

```sh
npx --yes execfence reports latest
npx --yes execfence reports open
```

Create an incident bundle:

```sh
npx --yes execfence incident bundle --from-report .execfence/reports/<report>.json
```

If a finding is legitimate and must be allowed, baseline it with an owner, reason, expiry, and hash:

```sh
npx --yes execfence baseline add --from-report .execfence/reports/<report>.json
```

Baselines are meant for reviewed exceptions, not for forcing a build through unknown `critical` or `high` findings.

## Common Commands

| Command | Purpose |
| --- | --- |
| `execfence scan` | Static project scan |
| `execfence --help` / `execfence help` | Full grouped command reference |
| `execfence run -- <command>` | Preflight scan, command execution, post-run evidence report |
| `execfence run --dependency-behavior-audit -- <command>` | Attach changed-dependency review and containment status to runtime evidence |
| `execfence ci` | Combined CI guardrail bundle |
| `execfence coverage` | Detect unprotected build/dev/test entrypoints |
| `execfence wire --dry-run` | Show wrapper changes without writing |
| `execfence wire --apply` | Apply wrappers where supported |
| `execfence guard enable` | Show automatic project guardrail plan without writing |
| `execfence guard enable --apply` | Apply project guardrails, wrappers, CI setup, and local agent rules |
| `execfence guard disable` | Remove generated wrappers/rules while preserving evidence |
| `execfence guard global-enable` | Install global skill, agent rules, and reversible npm/pnpm/yarn/bun shims |
| `execfence guard global-disable` | Remove global npm/pnpm/yarn/bun shims and marked PATH profile blocks |
| `execfence manifest` | Generate execution-entrypoint manifest |
| `execfence manifest diff` | Detect new or changed execution entrypoints |
| `execfence deps diff` | Compare dependency/lockfile risk |
| `execfence deps review` | Review changed npm/pnpm/yarn packages with guarded metadata checks |
| `execfence pack-audit` | Audit package contents before publish |
| `execfence agent-report` | Review agent, MCP, tool, and instruction-file changes |
| `execfence reports latest` | Show the latest report |
| `execfence report --html <report.json>` | Generate a local HTML report |
| `execfence sandbox doctor` | Check local sandbox capability |
| `execfence sandbox plan -- <command>` | Explain what sandbox policy would allow/block |

## More Documentation

- Project overview and launch article: [GitHub Pages](https://chrystyan96.github.io/ExecFence/)
- Technical detection details: [Detection Model](https://chrystyan96.github.io/ExecFence/detection)
- npm incident mapping: [npm Supply Chain Assessment](https://chrystyan96.github.io/ExecFence/npm-supply-chain-assessment)
- Weekly release cadence: [docs/release-cadence.md](docs/release-cadence.md)
- Source documentation: [docs/](docs/)
- License: [Apache-2.0](LICENSE)
