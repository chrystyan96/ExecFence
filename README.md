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
security-guardrails scan [--mode block|audit] --ci [--format text|json|sarif] [paths...]
security-guardrails diff-scan [--staged] [--mode block|audit]
security-guardrails scan-history [--max-commits <n>] [--format text|json|sarif] [--include-self]
security-guardrails explain <finding-id>
security-guardrails init [--preset auto|node|go|tauri|python|rust]
security-guardrails detect
security-guardrails install-hooks
security-guardrails install-skill [--codex-home <path>] [--home <path>]
security-guardrails install-agent-rules [--scope global|project|both] [--home <path>] [--project <path>]
security-guardrails publish [--real]
security-guardrails print-agents-snippet
```

## Configuration

`init` creates `.security-guardrails.json` when one does not exist:

```json
{
  "$schema": "https://raw.githubusercontent.com/chrystyan96/security-guardrails/master/schema/security-guardrails.schema.json",
  "mode": "block",
  "blockSeverities": ["critical", "high"],
  "roots": ["backend-go", "backend", "frontend", "desktop", "packages", "scripts", ".github", ".vscode"],
  "ignoreDirs": [],
  "skipFiles": [],
  "allowExecutables": [
    { "path": "tools/reviewed-helper.exe", "sha256": "0000000000000000000000000000000000000000000000000000000000000000" }
  ],
  "extraSignatures": [],
  "extraRegexSignatures": [],
  "signaturesFile": ".security-guardrails.signatures.json",
  "auditAllPackageScripts": false
}
```

Use `allowExecutables` sparingly for reviewed binaries that are intentionally committed.
Prefer `{ "path": "...", "sha256": "..." }` entries so a reviewed binary cannot be silently replaced.
Use `extraSignatures` for literal project-specific IoCs and `extraRegexSignatures` for reviewed regex detections.

For larger teams, keep project-specific detections in `.security-guardrails.signatures.json`:

```json
{
  "exact": [{ "id": "team-ioc", "value": "bad-domain.example" }],
  "regex": [{ "id": "team-wallet-marker", "pattern": "wallet-[0-9]+" }]
}
```

`mode: "audit"` reports findings without failing the command. `mode: "block"` fails only for configured `blockSeverities`, which default to `critical` and `high`.

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

The repository includes `.github/workflows/ci.yml`, which runs tests, scan, SARIF generation, and package dry-run on Ubuntu, Windows, and macOS.

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
