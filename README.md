# ExecFence

Execution-fence guardrails for persistent web, desktop, backend, and local-agent projects.

It is a small dependency-free CLI intended to fail fast before dev/build/test/CI when a repository contains known injected payloads, suspicious executable configuration, autostart tasks, or unexpected binaries in source/build-input folders.

## Quick Start

Run the runtime gate or a scan without installing:

```sh
npx --yes execfence run -- npm test
npx --yes execfence run --sandbox-mode audit -- npm test
npx --yes execfence scan
npx --yes execfence scan --mode audit
```

Initialize common project hooks:

```sh
npx --yes execfence init --preset auto
```

Install the bundled Codex skill and automatically update global agent instructions:

```sh
npx --yes execfence install-skill
```

Install portable rules for non-Codex agents in a project:

```sh
npx --yes execfence install-agent-rules --scope project
```

Print the portable instruction snippet:

```sh
npx --yes execfence print-agents-snippet
```

## What It Blocks

Known injected JavaScript loader IoCs:

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

Suspicious execution patterns:

- `.vscode/tasks.json` with `"runOn": "folderOpen"`
- hidden Node loader patterns such as `global[...] = require`
- dynamic `Function`/`constructor` loaders combined with `eval`, `fromCharCode`, or `child_process`
- very long obfuscated JavaScript lines with loader markers
- executable artifacts such as `.exe`, `.dll`, `.bat`, `.cmd`, `.scr`, `.vbs`, `.wsf` inside source/build-input folders
- suspicious npm lifecycle scripts and insecure or suspicious package-manager lockfile URLs

## Default Ignored Paths

The scanner ignores normal dependency/build/cache folders:

`.git`, `node_modules`, `dist`, `build`, `.angular`, `coverage`, `target`, `target-*`, `bin`, `.pytest_cache`, `test-results`, `visual-checks`, and similar generated output paths.

## Commands

```sh
execfence run [--sandbox] [--sandbox-mode audit|enforce] [--allow-degraded] [--record-artifacts] [--deny-on-new-executable] -- <command>
execfence scan [paths...]
execfence scan [--mode block|audit] [--fail-on critical,high] [--changed-only] [--full-ioc-scan] [--report <dir>] --ci [--format text|json|sarif] [paths...]
execfence diff-scan [--staged] [--mode block|audit]
execfence scan-history [--max-commits <n>] [--format text|json|sarif] [--include-self]
execfence coverage [--fix-suggestions] [--format text|json]
execfence wire [--dry-run|--apply]
execfence adopt [--write-baseline]
execfence ci [--base-ref <ref>]
execfence deps diff [--base-ref <ref>]
execfence manifest
execfence manifest diff
execfence report [--dir <dir>] [paths...]
execfence report --html <report.json>
execfence report --markdown <report.json>
execfence reports list|latest|show <id>|open <id>|diff <a> <b>|compare [--since <report>]|regression [--since <report>]|prune
execfence incident create|bundle|timeline --from-report <report.json>
execfence baseline add --from-report <report.json> --owner <owner> --reason <reason> --expires-at <date>
execfence enrich [--preview] <report.json>
execfence policy explain|test [--policy-pack <name>]
execfence sandbox init|doctor|plan|explain|install-helper|uninstall-helper|helper-audit
execfence helper audit
execfence pack-audit
execfence trust add <path|registry|action|scope> [--type file|registry|action|package-scope] --reason <reason> --owner <owner> --expires-at <date>
execfence trust audit
execfence agent-report
execfence pr-comment --report <report.json>
execfence doctor
execfence explain <finding-id>
execfence init [--preset auto|node|go|tauri|python|rust] [--dry-run]
execfence detect
execfence install-hooks
execfence install-skill [--codex-home <path>] [--home <path>]
execfence install-agent-rules [--scope global|project|both] [--verify] [--home <path>] [--project <path>]
execfence publish [--real]
execfence print-agents-snippet
```

## Files, Logs, and Configuration

`execfence` does not keep a background daemon. Normal command output goes to the terminal or CI log. Every blocking-capable command writes a new structured JSON evidence report under `.execfence/reports/`.

Project-level files:

| File or directory | Created by | Purpose |
| --- | --- | --- |
| `.execfence/config/execfence.json` | `init` | Main project policy: mode, severities, roots, policy pack, reports, allowlists, custom signatures, and feature toggles. |
| `.execfence/config/signatures.json` | `init` / user/team | Optional project IoCs and regex detections. The path is configurable with `signaturesFile`. |
| `.execfence/config/baseline.json` | `init` / user/team | Optional reviewed exceptions for existing findings. The path is configurable with `baselineFile`. |
| `.execfence/config/sandbox.json` | `init` / `sandbox init` | Sandbox policy for `execfence run --sandbox`, including profile, filesystem, process, network, and helper metadata settings. |
| `.execfence/manifest.json` | `manifest` | Execution-surface inventory for package scripts, Makefiles, workflows, VS Code tasks, hooks, language build files, and agent rules. |
| `.execfence/reports/<project>_<datetime>.json` | `run`, `scan`, `diff-scan`, `scan-history`, `doctor`, or `report` | Machine-readable evidence bundle with findings, hashes, snippets, git blame, recent commits, command, config, local analysis, runtime trace when available, enrichment, and research queries. |
| `.execfence/cache/enrichment/` | report/enrich commands | Local cache for public-source enrichment of critical/high findings. |
| `.execfence/trust/*.json` | `trust add` | Trust stores for reviewed files, actions, registries, package scopes, and package sources. |
| `.execfence/quarantine/<report-id>/metadata.json` | report commands | Quarantine metadata only; ExecFence does not remove suspicious payloads automatically. |
| `.gitignore` | `init` / scan commands | Keeps `.execfence/reports/` out of git unless `reportsGitignore` is `false`. |
| `.git/hooks/pre-commit` | `install-hooks` | Local pre-commit scan hook. |
| agent instruction files | `install-agent-rules` / `install-skill` | Portable instructions for Codex, Claude, Gemini, Cursor, Copilot, Continue, Windsurf, Aider, Roo, and Cline. |
| `<home>/.agents/skills/execfence/defaults.json` | `install-skill` | Read-only global defaults for agents and the skill; project config wins. |

The default report directory is `.execfence/reports` under the project root. ExecFence ignores `.execfence/` during scans so report bundles and config IoCs do not poison later scan output.

Copyable examples are available in `examples/`. JSON schemas are published under `schema/` for the main config, V2/V3 reports, sandbox policy, external signatures, and reviewed baseline files.

## Sandbox Mode

V3 adds a local sandbox policy surface for commands that execute project code:

```sh
execfence sandbox init
execfence sandbox doctor
execfence sandbox plan -- npm test
execfence run --sandbox-mode audit -- npm test
execfence run --sandbox -- npm test
```

`--sandbox-mode audit` records the sandbox profile, capability matrix, intended filesystem/process/network decisions, and post-run evidence without promising hard isolation. `--sandbox` is equivalent to `--sandbox-mode enforce`; if the required filesystem, process, or network enforcement is unavailable, ExecFence blocks before executing the command and explains the missing capability. Downgrade is never silent: use `--sandbox-mode audit` or explicit `--allow-degraded`.

The base CLI does not require a sandbox helper. Optional helpers are validated through metadata at `.execfence/helper/execfence-helper.json`:

```sh
execfence helper audit
execfence sandbox install-helper --metadata verified-helper.json
execfence sandbox uninstall-helper
```

## Configuration

`init` creates `.execfence/config/execfence.json`, `.execfence/config/signatures.json`, `.execfence/config/baseline.json`, and `.execfence/reports/` when they do not exist:

```json
{
  "$schema": "https://raw.githubusercontent.com/chrystyan96/execfence/master/schema/execfence.schema.json",
  "policyPack": "baseline",
  "mode": "block",
  "blockSeverities": ["critical", "high"],
  "warnSeverities": ["medium", "low"],
  "roots": ["backend-go", "backend", "frontend", "desktop", "packages", "scripts", ".github", ".vscode"],
  "ignoreDirs": [],
  "skipFiles": [],
  "allowExecutables": [
    { "path": "tools/reviewed-helper.exe", "sha256": "0000000000000000000000000000000000000000000000000000000000000000" }
  ],
  "extraSignatures": [],
  "extraRegexSignatures": [],
  "signaturesFile": ".execfence/config/signatures.json",
  "baselineFile": ".execfence/config/baseline.json",
  "sandboxFile": ".execfence/config/sandbox.json",
  "reportsDir": ".execfence/reports",
  "reportsGitignore": true,
  "runtimeTrace": {
    "enabled": true,
    "postRunScan": true,
    "captureGitStatus": true,
    "redactEnv": true,
    "snapshotFiles": true,
    "recordArtifacts": false,
    "denyOnNewExecutable": false
  },
  "analysis": {
    "webEnrichment": {
      "enabled": true,
      "automaticForSeverities": ["critical", "high"],
      "maxQueriesPerFinding": 3,
      "allowedDomains": [],
      "timeoutMs": 4000,
      "cacheTtlMs": 86400000
    }
  },
  "manifest": {
    "path": ".execfence/manifest.json",
    "requireRunWrapper": true,
    "blockNewEntrypoints": true,
    "sensitiveEntrypoints": ["build", "test", "dev", "start", "serve", "watch", "prepare", "install", "postinstall"]
  },
  "ci": {
    "enabled": true,
    "baseRef": "HEAD",
    "checks": ["scan", "manifest-diff", "deps-diff", "pack-audit", "trust-audit"]
  },
  "wire": {
    "packageScripts": true,
    "workflows": true,
    "makefile": true,
    "vscodeTasks": true
  },
  "deps": {
    "detectRegistryDrift": true,
    "detectSuspiciousSources": true,
    "detectLifecycleEntries": true,
    "detectBinEntries": true,
    "detectTyposquatting": true
  },
  "adopt": {
    "writeSuggestedBaseline": false,
    "blockDuringAdoption": false
  },
  "policy": {
    "customPoliciesDir": ".execfence/config/policies",
    "requiredOwners": {},
    "requireSignedPolicyFiles": false
  },
  "trustStore": {
    "files": ".execfence/trust/files.json",
    "actions": ".execfence/trust/actions.json",
    "registries": ".execfence/trust/registries.json",
    "packageScopes": ".execfence/trust/package-scopes.json",
    "packageSources": ".execfence/trust/package-sources.json"
  },
  "htmlReport": {
    "enabled": true,
    "includeRuntimeTrace": true,
    "includeManifest": true
  },
  "reportRetention": {
    "maxReports": 100,
    "maxAgeDays": 90
  },
  "reports": {
    "retention": {
      "maxReports": 100,
      "maxAgeDays": 90
    }
  },
  "redaction": {
    "redactLocalPaths": true,
    "redactEnv": true,
    "extraPatterns": []
  },
  "auditAllPackageScripts": false
}
```

Configurable fields:

| Field | What it controls |
| --- | --- |
| `policyPack` | Enables stack-aware defaults: `baseline`, `web`, `desktop`, `node`, `go`, `python`, `rust`, `agentic`, or `strict`. |
| `mode` | `block` fails the command for blocked severities; `audit` reports without failing. |
| `blockSeverities` | Severities that fail in block mode. Defaults to `critical` and `high`. |
| `warnSeverities` | Severities shown as warnings when not blocked. Defaults to `medium` and `low`. |
| `roots` | Directories/files to scan when no explicit paths are passed. |
| `ignoreDirs` | Directory names to skip recursively, useful for custom generated output folders. |
| `skipFiles` | Exact file names to skip. Use narrowly for generated files that cannot be moved. |
| `allowExecutables` | Reviewed executable artifacts allowed in source/build-input folders, preferably pinned by SHA-256. |
| `extraSignatures` | Literal project-specific IoCs. |
| `extraRegexSignatures` | Reviewed regex detections for project-specific patterns. |
| `signaturesFile` | Path to an external signatures JSON file. |
| `baselineFile` | Path to a reviewed baseline/exceptions JSON file. |
| `reportsDir` | Directory for automatic JSON evidence reports. |
| `reportsGitignore` | Whether ExecFence keeps the reports directory in `.gitignore`. |
| `runtimeTrace` | Enables preflight/post-run trace data for `execfence run`. |
| `analysis.webEnrichment` | Public-source enrichment settings for critical/high findings. Queries are kept to IoCs, hashes, package names, domains, and rule IDs. |
| `manifest` | Path and policy for execution entrypoint inventory and wrapper requirements. |
| `ci` | Checks run by `execfence ci`: scan, manifest diff, dependency diff, pack audit, and trust audit. |
| `wire` | Which project entrypoint files `execfence wire` may suggest or update. |
| `deps` | Deep lockfile diff checks for registry drift, suspicious sources, lifecycle/bin entries, dependency confusion, and local typosquatting. |
| `adopt` | Low-noise first-run adoption behavior, including suggested baselines without changing blocking policy. |
| `policy` | Local organization controls, custom policy pack directory, required owners, and optional signing flags. |
| `trustStore` | Paths for file/action/registry/package-scope/package-source trust stores. |
| `htmlReport` | Local HTML report rendering settings. |
| `reportRetention` | Local retention hints for generated evidence reports. |
| `reports.retention` | V2.1 retention settings used by automatic report pruning. |
| `redaction` | Redaction settings for runtime evidence and enrichment queries. |
| `workflowHardening` | Enables/disables GitHub Actions hardening checks. |
| `archiveAudit` | Enables/disables source-tree archive checks for `.zip`, `.tar`, `.tgz`, and `.asar`. |
| `auditAllPackageScripts` | Audits all package scripts instead of only install/prepare lifecycle scripts. |

Use `allowExecutables` sparingly for reviewed binaries that are intentionally committed.
Prefer `{ "path": "...", "sha256": "..." }` entries so a reviewed binary cannot be silently replaced.
Use `extraSignatures` for literal project-specific IoCs and `extraRegexSignatures` for reviewed regex detections.

For larger teams, keep project-specific detections in `.execfence/config/signatures.json`:

```json
{
  "$schema": "https://raw.githubusercontent.com/chrystyan96/execfence/master/schema/execfence-signatures.schema.json",
  "exact": [{ "id": "team-ioc", "value": "bad-domain.example" }],
  "regex": [{ "id": "team-wallet-marker", "pattern": "wallet-[0-9]+" }]
}
```

`mode: "audit"` reports findings without failing the command. `mode: "block"` fails only for configured `blockSeverities`, which default to `critical` and `high`.

Policy packs are available for `baseline`, `web`, `desktop`, `node`, `go`, `python`, `rust`, `agentic`, and `strict`.

Use `.execfence/config/baseline.json` to suppress reviewed existing findings without weakening future detections:

```json
{
  "$schema": "https://raw.githubusercontent.com/chrystyan96/execfence/master/schema/execfence-baseline.schema.json",
  "findings": [
    {
      "findingId": "suspicious-package-script",
      "file": "package.json",
      "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
      "reason": "reviewed legacy install hook",
      "owner": "security",
      "expiresAt": "2026-12-31"
    }
  ]
}
```

## Presets

`init --preset auto` detects the stack. Explicit presets are available for `node`, `go`, `tauri`, `python`, and `rust`.

Current integrations:

- Node: adds `execfence:scan`, wraps existing `test` and `build` with `execfence run --`, and prepends existing `prestart`, `prebuild`, `pretest`, and `prewatch` hooks.
- Go: adds a guarded `Makefile` target when requested and wires `build`, `test`, `test-race`, and `vet`.
- Python: adds a pytest guard test when `pyproject.toml` is present.
- GitHub Actions: adds `.github/workflows/execfence.yml` when workflows already exist.

## Runtime Gate

Use `execfence run -- <command>` for commands that execute project code:

```sh
npx --yes execfence run -- npm test
npx --yes execfence run -- npm run build
npx --yes execfence run -- go test ./...
npx --yes execfence run --record-artifacts --deny-on-new-executable -- npm test
```

`run` performs a preflight scan, blocks before execution when configured severities are found, executes the command when clean, records a lightweight local runtime trace, snapshots file changes, and rescans changed files afterwards. It does not implement a sandbox or network block in V2.

Generate and compare execution manifests:

```sh
npx --yes execfence manifest
npx --yes execfence manifest diff
```

Wire existing entrypoints to the runtime gate:

```sh
npx --yes execfence wire --dry-run
npx --yes execfence wire --apply
```

For first adoption in existing repositories, use audit-first mode:

```sh
npx --yes execfence adopt
npx --yes execfence adopt --write-baseline
```

`adopt` produces a correction plan, wiring suggestions, dependency/package checks, and an optional `.execfence/config/baseline.suggested.json` that still requires owner, reason, expiry, and review before use.

## CI Output

Use JSON or SARIF in CI:

```sh
npx --yes execfence ci
npx --yes execfence scan --ci --format json
npx --yes execfence scan --ci --format sarif > execfence.sarif
```

`execfence ci` is the V2.1 aggregate gate. It runs scan, manifest diff, dependency diff, package-content audit, trust audit, writes a report, and fails on configured blocking severities.

The repository includes `.github/workflows/ci.yml`, which runs tests, scan, SARIF generation, and package dry-run on Ubuntu, Windows, and macOS. `.github/workflows/scorecard.yml` runs OpenSSF Scorecard as an optional repository-health signal.

## Git Workflows

Scan only changed files:

```sh
npx --yes execfence diff-scan
npx --yes execfence diff-scan --staged
```

Scan history for known IoCs:

```sh
npx --yes execfence scan-history --max-commits 1000
```

When the package scans its own repository, history scanning skips documented signatures by default. Use `--include-self` when you intentionally want to audit the package's own signature history.

Install a pre-commit hook:

```sh
npx --yes execfence install-hooks
```

Explain a finding:

```sh
npx --yes execfence explain suspicious-package-script
```

Check whether build/dev/test entrypoints are protected:

```sh
npx --yes execfence coverage
npx --yes execfence coverage --fix-suggestions
```

Generate or redirect an evidence bundle without deleting suspicious files. Runtime and scan commands also generate reports automatically:

```sh
npx --yes execfence run -- npm test
npx --yes execfence scan
npx --yes execfence scan --report .execfence/reports
npx --yes execfence report --dir .execfence/reports
```

Investigate reports locally:

```sh
npx --yes execfence reports list
npx --yes execfence reports latest
npx --yes execfence reports show <report-id>
npx --yes execfence reports open <report-id>
npx --yes execfence reports diff <old-report.json> <new-report.json>
npx --yes execfence reports compare --since <old-report.json>
npx --yes execfence reports regression --since <old-report.json>
npx --yes execfence report --html .execfence/reports/<report>.json
npx --yes execfence report --markdown .execfence/reports/<report>.json
npx --yes execfence incident create --from-report .execfence/reports/<report>.json
npx --yes execfence incident bundle --from-report .execfence/reports/<report>.json
npx --yes execfence incident timeline --from-report .execfence/reports/<report>.json
npx --yes execfence baseline add --from-report .execfence/reports/<report>.json --owner security --reason "reviewed false positive" --expires-at 2026-12-31
npx --yes execfence enrich --preview .execfence/reports/<report>.json
npx --yes execfence pr-comment --report .execfence/reports/<report>.json
```

Explain and validate policies:

```sh
npx --yes execfence policy explain
npx --yes execfence policy explain --policy-pack strict
npx --yes execfence policy test
```

Custom policy packs live in `.execfence/config/policies/<name>.json` and are selected with `policyPack: "<name>"` or `--policy-pack <name>`.

Audit supply-chain and trust metadata:

```sh
npx --yes execfence deps diff
npx --yes execfence pack-audit
npx --yes execfence trust add tools/reviewed-helper.exe --reason "reviewed helper" --owner security --expires-at 2026-12-31
npx --yes execfence trust add https://registry.npmjs.org --type registry --reason "official npm registry" --owner security --expires-at 2026-12-31
npx --yes execfence trust add @company --type package-scope --reason "internal scope" --owner security --expires-at 2026-12-31
npx --yes execfence trust audit
npx --yes execfence agent-report
```

Verify the scanner blocks a temporary known-bad fixture in the current environment:

```sh
npx --yes execfence doctor
```

`install-skill` writes:

- `<codex-home>/skills/execfence/SKILL.md`
- `<codex-home>/skills/execfence/defaults.json`
- `<codex-home>/AGENTS.md`, inserting or replacing a marker-bounded `ExecFence` section
- `<home>/.agents/skills/execfence/defaults.json`
- `<home>/.codex/AGENTS.md`
- `<home>/.claude/CLAUDE.md`
- `<home>/.gemini/GEMINI.md`

`install-agent-rules --scope project` writes portable project-level instruction files:

- `AGENTS.md`
- `CLAUDE.md`
- `GEMINI.md`
- `.cursor/rules/execfence.mdc`
- `.github/copilot-instructions.md`
- `.continue/rules/execfence.md`
- `.windsurf/rules/execfence.md`
- `.aider/execfence.md`
- `.roo/rules/execfence.md`
- `.clinerules`

`install-agent-rules --scope both` writes both global and project-level rules.
`install-agent-rules --verify --scope both` checks whether those rule files exist and contain a guardrails instruction.

## Publishing

Suggested first release flow:

```sh
npm test
npm run scan
npm pack --dry-run
git init
git add .
git commit -m "Create ExecFence CLI"
git branch -M master
git remote add origin https://github.com/chrystyan96/execfence.git
git push -u origin master
npm publish --access public --provenance
```

The repository includes `.github/workflows/release.yml` for manual npm releases. It bumps the requested version, updates `CHANGELOG.md`, creates the commit/tag, and publishes with provenance. Configure npm Trusted Publishing for `chrystyan96/execfence` with workflow filename `release.yml`; npm will use OIDC and publish provenance for that workflow.

The packaged helper runs the safe release checks:

```sh
npx --yes execfence publish
```

After `npm login`, publish for real:

```sh
npx --yes execfence publish --real
```

After publish, users can run:

```sh
npx --yes execfence scan
```

## Scope

This is a repo-level fail-fast guard. It does not replace antivirus, EDR, secret scanning, software composition analysis, sandboxing, or credential rotation.
