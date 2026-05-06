---
name: execfence
description: Use when creating or hardening persistent projects that run on the web, build executable code, use Node/Go/Rust/Python supply chains, run CI/CD, or access the user's filesystem, credentials, browser, network, shell, desktop APIs, or local machine. Evaluates the stack and adds lightweight malware/supply-chain guardrails to block known injected payloads, suspicious executable configs, autostart tasks, and unexpected binaries before build/test/dev.
---

# ExecFence

Add stack-aware guardrails that fail fast before dev/build/test/CI when a persistent project could execute attacker-controlled code.

## Trigger

Use this skill automatically for:
- Web apps, desktop apps, CLIs, local agents, backend services, CI/CD projects, or apps that read/write user files.
- Projects using executable configuration or package hooks: `package.json`, `vite.config.*`, `next.config.*`, `postcss.config.*`, `tailwind.config.*`, `eslint.config.*`, `webpack.config.*`, `Makefile`, `go test`, `build.rs`, `pyproject.toml`, `setup.py`, `.vscode/tasks.json`, GitHub Actions.
- Requests involving persistence, build hardening, malware injection, supply-chain risk, local filesystem access, token/credential handling, browser/desktop integration, or security guardrails.

Skip only for throwaway snippets, one-off static files, pure documentation, or when the user explicitly says not to add guardrails.

## Workflow

1. Detect stack and execution surfaces.
2. Prefer `npx --yes execfence guard enable` to preview automatic project setup.
3. Use `npx --yes execfence guard enable --apply` when the user wants the project wired automatically.
4. Integrate normal build/test/dev commands with `execfence run -- <command>`.
5. Ignore dependency/build/cache folders to keep false positives low.
6. Verify with direct scanner execution and one stack-specific command.

Prefer these commands when available:

```sh
npx --yes execfence init --preset auto
npx --yes execfence guard enable
npx --yes execfence guard enable --apply
npx --yes execfence guard status
npx --yes execfence guard disable
npx --yes execfence guard global-status
npx --yes execfence guard global-enable
npx --yes execfence guard global-disable
npx --yes execfence run -- npm test
npx --yes execfence run -- npm run build
npx --yes execfence run --sandbox-mode audit -- npm test
npx --yes execfence run --dependency-behavior-audit --sandbox-mode audit -- npm test
npx --yes execfence run --sandbox -- npm test
npx --yes execfence sandbox doctor
npx --yes execfence sandbox plan -- npm test
npx --yes execfence run --record-artifacts --deny-on-new-executable -- npm test
npx --yes execfence ci
npx --yes execfence adopt
npx --yes execfence adopt --write-baseline
npx --yes execfence wire --dry-run
npx --yes execfence deps diff
npx --yes execfence deps review
npx --yes execfence policy explain
npx --yes execfence policy test
npx --yes execfence manifest
npx --yes execfence manifest diff
npx --yes execfence scan --ci --format json
npx --yes execfence scan --mode audit --ci --format json
npx --yes execfence scan --fail-on critical,high
npx --yes execfence scan --ci --format sarif
npx --yes execfence diff-scan --staged
npx --yes execfence coverage
npx --yes execfence scan-history --max-commits 1000
npx --yes execfence doctor
npx --yes execfence pack-audit
npx --yes execfence trust audit
npx --yes execfence baseline add --from-report .execfence/reports/<report>.json --owner <owner> --reason <reason> --expires-at <date>
npx --yes execfence agent-report
npx --yes execfence reports list
npx --yes execfence reports latest
npx --yes execfence reports open <report>
npx --yes execfence report --markdown .execfence/reports/<report>.json
npx --yes execfence enrich --preview .execfence/reports/<report>.json
npx --yes execfence incident bundle --from-report .execfence/reports/<report>.json
npx --yes execfence pr-comment --report .execfence/reports/<report>.json
npx --yes execfence explain suspicious-package-script
npx --yes execfence install-hooks
npx --yes execfence install-agent-rules --scope project
npx --yes execfence install-agent-rules --verify --scope project
```

`guard enable` is dry-run by default. It should be the first recommendation when the user wants project-local automatic protection for `test`, `build`, `dev`, `pack`, `publish`, CI, and agent-driven execution. `guard global-enable` installs skill/defaults, global agent rules, and reversible `npm`/`npx`/`pnpm`/`yarn`/`yarnpkg`/`bun`/`bunx` shims under `<home>/.execfence/shims/` with marked shell-profile PATH blocks. Use `guard global-disable` to remove those shims and PATH blocks.

## Minimum Detections

Block known injected JavaScript loader IoCs:
- `global.i='2-30-4'`
- `_$_a7ae`
- `_$_d609`
- `tLl(5394)`
- `global['_V']`
- `api.trongrid.io/v1/accounts`
- `fullnode.mainnet.aptoslabs.com/v1/accounts`
- `bsc-dataseed.binance.org`
- `bsc-rpc.publicnode.com`
- `eth_getTransactionByHash`
- `temp_auto_push`

Block suspicious execution patterns:
- `.vscode/tasks.json` with `"runOn": "folderOpen"`
- `global[...] = require` in executable JS/config files
- dynamic `Function`/`constructor` loaders that combine `eval`, `fromCharCode`, or `child_process`
- very long obfuscated JavaScript lines with loader markers
- executable artifacts such as `.exe`, `.dll`, `.bat`, `.cmd`, `.scr`, `.vbs`, `.wsf` inside source/build-input folders
- suspicious npm lifecycle scripts and insecure or suspicious npm/pnpm/yarn/bun/Cargo/Go/Python lockfile URLs

Prefer project config under `.execfence/config/` for policy packs, reviewed exceptions, extra literal IoCs, extra regex detections, reports, and audit/block mode instead of weakening scanner code. When allowing a committed executable, use a `{ "path": "...", "sha256": "..." }` entry. Put team-specific IoCs in `.execfence/config/signatures.json` and reviewed legacy findings in `.execfence/config/baseline.json` with an owner, reason, expiry, and hash.

## User Configuration Surface

Create project configuration through `execfence init`:
- `.execfence/config/execfence.json`: main config for `policyPack`, `mode`, `blockSeverities`, `warnSeverities`, scan `roots`, `ignoreDirs`, `skipFiles`, `allowExecutables`, `extraSignatures`, `extraRegexSignatures`, `signaturesFile`, `baselineFile`, `reportsDir`, `reportsGitignore`, `runtimeTrace`, `analysis.webEnrichment`, `manifest.blockNewEntrypoints`, `ci`, `wire`, `deps`, `supplyChain.mode`, `supplyChain.metadata`, `supplyChain.reputation`, `adopt`, `policy`, `trustStore`, `reportRetention`, `reports.retention`, `htmlReport`, `redaction`, `workflowHardening`, `archiveAudit`, and `auditAllPackageScripts`.
- `.execfence/config/signatures.json`: optional team-owned literal and regex indicators. Use this for new IoCs instead of editing scanner code.
- `.execfence/config/baseline.json`: optional reviewed exceptions for existing findings. Require `findingId`, `file`, `reason`, `owner`, `expiresAt`, and preferably `sha256`.
- `.execfence/config/sandbox.json`: sandbox policy for `execfence run --sandbox`, including `mode`, `profile`, filesystem, process, network, and helper settings. Audit mode is evidence without a helper; enforce mode must block if network/filesystem/sensitive-read/child-process/new-executable enforcement is unavailable unless the user explicitly uses `--allow-degraded`.
- `.execfence/config/policies/*.json`: optional project/team policy packs selected by `policyPack`.
- `.execfence/reports/`: automatic JSON reports. Keep it gitignored unless the user sets `reportsGitignore: false`.
- `.execfence/manifest.json`: generated execution-surface manifest for package scripts, Makefiles, workflows, tasks, hooks, language build files, and agent rules.
- `.execfence/cache/enrichment/`: local cache for public-source enrichment of critical/high findings.
- `.execfence/trust/*.json`: trust stores for reviewed files, actions, registries, package scopes, and package sources.
- `.execfence/helper/execfence-helper.json`: optional helper metadata. Validate with `execfence helper audit`; do not trust helpers without hash/provenance metadata.
- `.execfence/quarantine/<report-id>/metadata.json`: quarantine metadata only; do not delete payloads automatically.
- `<home>/.agents/skills/execfence/defaults.json`: read-only global defaults installed with the skill. Do not ask the user to edit it; project config wins.

Evidence is created automatically for `run`, `scan`, `diff-scan`, `scan-history`, and `doctor`. Each report is a new `.execfence/reports/<project>_<datetime>.json` file with findings, snippets, hashes, git evidence, local analysis, runtime trace when available, and research queries. For dependency changes, prefer `deps review` to aggregate npm/pnpm/yarn lockfiles with guarded metadata/reputation checks for release cooldown, OSV advisories, package reputation, deprecation/security text, source, integrity, provenance/signature hints, tarball content, tarball delta, lifecycle/bin hints, privacy status, and recommended actions. Use `supplyChain.mode: "strict"` in CI/release/security-sensitive repos when unavailable signals, cooldowns, missing integrity/provenance, uncovered package-manager surfaces, and runtime dependency behavior without helper enforcement should block. For commands likely to import changed dependencies, prefer `execfence run --dependency-behavior-audit --sandbox-mode audit -- <command>` for evidence or `--sandbox` with a verified helper for enforcement. For `critical` and `high` findings, enrich with public safe sources (OSV, GitHub Advisory, npm metadata, CISA KEV, and reputable web sources when available) after redacting local paths and sensitive snippets. Network/enrichment failure never lowers severity or unblocks execution. Do not delete or rewrite suspicious payloads automatically.

## Preferred CLI

When the package is available, prefer:

```sh
npx --yes execfence init
npx --yes execfence run -- npm test
npx --yes execfence scan
```

## Final Report

Report files changed, commands wired, detections covered, verification results, and remaining runtime/credential risks.
