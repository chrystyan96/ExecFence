# security-guardrails

Stack-aware malware and supply-chain guardrails for persistent web, desktop, backend, and local-agent projects.

It is a small dependency-free CLI intended to fail fast before dev/build/test/CI when a repository contains known injected payloads, suspicious executable configuration, autostart tasks, or unexpected binaries in source/build-input folders.

## Quick Start

Run a scan without installing:

```sh
npx --yes security-guardrails scan
npx --yes security-guardrails scan --mode audit
```

Initialize common project hooks:

```sh
npx --yes security-guardrails init --preset auto
```

Install the bundled Codex skill and automatically update global agent instructions:

```sh
npx --yes security-guardrails install-skill
```

Install portable rules for non-Codex agents in a project:

```sh
npx --yes security-guardrails install-agent-rules --scope project
```

Print the portable instruction snippet:

```sh
npx --yes security-guardrails print-agents-snippet
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
security-guardrails scan [paths...]
security-guardrails scan [--mode block|audit] [--fail-on critical,high] [--changed-only] [--full-ioc-scan] [--report <dir>] --ci [--format text|json|sarif] [paths...]
security-guardrails diff-scan [--staged] [--mode block|audit]
security-guardrails scan-history [--max-commits <n>] [--format text|json|sarif] [--include-self]
security-guardrails coverage [--format text|json]
security-guardrails report [--dir <dir>] [paths...]
security-guardrails doctor
security-guardrails explain <finding-id>
security-guardrails init [--preset auto|node|go|tauri|python|rust] [--dry-run]
security-guardrails detect
security-guardrails install-hooks
security-guardrails install-skill [--codex-home <path>] [--home <path>]
security-guardrails install-agent-rules [--scope global|project|both] [--verify] [--home <path>] [--project <path>]
security-guardrails publish [--real]
security-guardrails print-agents-snippet
```

## Files, Logs, and Configuration

`security-guardrails` does not keep a global log or background daemon. Normal command output goes to the terminal or CI log. Durable evidence is written only when the user requests a report.

Project-level files:

| File or directory | Created by | Purpose |
| --- | --- | --- |
| `.security-guardrails.json` | `init` | Main project policy: mode, severities, roots, policy pack, allowlists, custom signatures, and feature toggles. |
| `.security-guardrails.signatures.json` | user/team | Optional project IoCs and regex detections. The path is configurable with `signaturesFile`. |
| `.security-guardrails.baseline.json` | user/team | Optional reviewed exceptions for existing findings. The path is configurable with `baselineFile`. |
| `security-guardrails-report/report.json` | `scan --report` or `report` | Machine-readable evidence bundle with findings, hashes, snippets, git blame, recent commits, command, and config path. |
| `security-guardrails-report/report.md` | `scan --report` or `report` | Human-readable incident or CI evidence summary. |
| `.git/hooks/pre-commit` | `install-hooks` | Local pre-commit scan hook. |
| agent instruction files | `install-agent-rules` / `install-skill` | Portable instructions for Codex, Claude, Gemini, Cursor, Copilot, Continue, Windsurf, Aider, Roo, and Cline. |

The default report directory is `security-guardrails-report` under the project root and is ignored by future scans. If you use a custom report directory inside the repository, add that directory name to `ignoreDirs`.

Copyable examples are available in `examples/`. JSON schemas are published under `schema/` for the main config, external signatures, and reviewed baseline files.

## Configuration

`init` creates `.security-guardrails.json` when one does not exist:

```json
{
  "$schema": "https://raw.githubusercontent.com/chrystyan96/security-guardrails/master/schema/security-guardrails.schema.json",
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
  "signaturesFile": ".security-guardrails.signatures.json",
  "baselineFile": ".security-guardrails.baseline.json",
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
| `workflowHardening` | Enables/disables GitHub Actions hardening checks. |
| `archiveAudit` | Enables/disables source-tree archive checks for `.zip`, `.tar`, `.tgz`, and `.asar`. |
| `auditAllPackageScripts` | Audits all package scripts instead of only install/prepare lifecycle scripts. |

Use `allowExecutables` sparingly for reviewed binaries that are intentionally committed.
Prefer `{ "path": "...", "sha256": "..." }` entries so a reviewed binary cannot be silently replaced.
Use `extraSignatures` for literal project-specific IoCs and `extraRegexSignatures` for reviewed regex detections.

For larger teams, keep project-specific detections in `.security-guardrails.signatures.json`:

```json
{
  "$schema": "https://raw.githubusercontent.com/chrystyan96/security-guardrails/master/schema/security-guardrails-signatures.schema.json",
  "exact": [{ "id": "team-ioc", "value": "bad-domain.example" }],
  "regex": [{ "id": "team-wallet-marker", "pattern": "wallet-[0-9]+" }]
}
```

`mode: "audit"` reports findings without failing the command. `mode: "block"` fails only for configured `blockSeverities`, which default to `critical` and `high`.

Policy packs are available for `baseline`, `web`, `desktop`, `node`, `go`, `python`, `rust`, `agentic`, and `strict`.

Use `.security-guardrails.baseline.json` to suppress reviewed existing findings without weakening future detections:

```json
{
  "$schema": "https://raw.githubusercontent.com/chrystyan96/security-guardrails/master/schema/security-guardrails-baseline.schema.json",
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

- Node: adds `security:guardrails` and prepends existing `prestart`, `prebuild`, `pretest`, and `prewatch` hooks.
- Go: adds a guarded `Makefile` target when requested and wires `build`, `test`, `test-race`, and `vet`.
- Python: adds a pytest guard test when `pyproject.toml` is present.
- GitHub Actions: adds `.github/workflows/security-guardrails.yml` when workflows already exist.

## CI Output

Use JSON or SARIF in CI:

```sh
npx --yes security-guardrails scan --ci --format json
npx --yes security-guardrails scan --ci --format sarif > security-guardrails.sarif
```

The repository includes `.github/workflows/ci.yml`, which runs tests, scan, SARIF generation, and package dry-run on Ubuntu, Windows, and macOS. `.github/workflows/scorecard.yml` runs OpenSSF Scorecard as an optional repository-health signal.

## Git Workflows

Scan only changed files:

```sh
npx --yes security-guardrails diff-scan
npx --yes security-guardrails diff-scan --staged
```

Scan history for known IoCs:

```sh
npx --yes security-guardrails scan-history --max-commits 1000
```

When the package scans its own repository, history scanning skips documented signatures by default. Use `--include-self` when you intentionally want to audit the package's own signature history.

Install a pre-commit hook:

```sh
npx --yes security-guardrails install-hooks
```

Explain a finding:

```sh
npx --yes security-guardrails explain suspicious-package-script
```

Check whether build/dev/test entrypoints are protected:

```sh
npx --yes security-guardrails coverage
```

Generate an evidence bundle without deleting suspicious files:

```sh
npx --yes security-guardrails scan --report security-guardrails-report
npx --yes security-guardrails report --dir security-guardrails-report
```

Verify the scanner blocks a temporary known-bad fixture in the current environment:

```sh
npx --yes security-guardrails doctor
```

`install-skill` writes:

- `<codex-home>/skills/security-guardrails/SKILL.md`
- `<codex-home>/AGENTS.md`, inserting or replacing a marker-bounded `Security Guardrails` section
- `<home>/.codex/AGENTS.md`
- `<home>/.claude/CLAUDE.md`
- `<home>/.gemini/GEMINI.md`

`install-agent-rules --scope project` writes portable project-level instruction files:

- `AGENTS.md`
- `CLAUDE.md`
- `GEMINI.md`
- `.cursor/rules/security-guardrails.mdc`
- `.github/copilot-instructions.md`
- `.continue/rules/security-guardrails.md`
- `.windsurf/rules/security-guardrails.md`
- `.aider/security-guardrails.md`
- `.roo/rules/security-guardrails.md`
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
git commit -m "Create security guardrails CLI"
git branch -M master
git remote add origin https://github.com/chrystyan96/security-guardrails.git
git push -u origin master
npm publish --access public --provenance
```

The repository includes `.github/workflows/release.yml` for manual npm releases. It bumps the requested version, updates `CHANGELOG.md`, creates the commit/tag, and publishes with provenance. Configure npm Trusted Publishing for `chrystyan96/security-guardrails` with workflow filename `release.yml`; npm will use OIDC and publish provenance for that workflow.

The packaged helper runs the safe release checks:

```sh
npx --yes security-guardrails publish
```

After `npm login`, publish for real:

```sh
npx --yes security-guardrails publish --real
```

After publish, users can run:

```sh
npx --yes security-guardrails scan
```

## Scope

This is a repo-level fail-fast guard. It does not replace antivirus, EDR, secret scanning, software composition analysis, sandboxing, or credential rotation.
