# security-guardrails

Stack-aware malware and supply-chain guardrails for persistent web, desktop, backend, and local-agent projects.

It is a small dependency-free CLI intended to fail fast before dev/build/test/CI when a repository contains known injected payloads, suspicious executable configuration, autostart tasks, or unexpected binaries in source/build-input folders.

## Quick Start

Run a scan without installing:

```sh
npx --yes security-guardrails scan
```

Initialize common project hooks:

```sh
npx --yes security-guardrails init
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

## Default Ignored Paths

The scanner ignores normal dependency/build/cache folders:

`.git`, `node_modules`, `dist`, `build`, `.angular`, `coverage`, `target`, `target-*`, `bin`, `.pytest_cache`, `test-results`, `visual-checks`, and similar generated output paths.

## Commands

```sh
security-guardrails scan [paths...]
security-guardrails init
security-guardrails detect
security-guardrails install-skill [--codex-home <path>] [--home <path>]
security-guardrails install-agent-rules [--scope global|project|both] [--home <path>] [--project <path>]
security-guardrails print-agents-snippet
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
git branch -M main
git remote add origin https://github.com/TwinSparkGames/security-guardrails.git
git push -u origin main
npm publish --access public
```

After publish, users can run:

```sh
npx --yes security-guardrails scan
```

## Scope

This is a repo-level fail-fast guard. It does not replace antivirus, EDR, secret scanning, software composition analysis, sandboxing, or credential rotation.
