---
name: security-guardrails
description: Use when creating or hardening persistent projects that run on the web, build executable code, use Node/Go/Rust/Python supply chains, run CI/CD, or access the user's filesystem, credentials, browser, network, shell, desktop APIs, or local machine. Evaluates the stack and adds lightweight malware/supply-chain guardrails to block known injected payloads, suspicious executable configs, autostart tasks, and unexpected binaries before build/test/dev.
---

# Security Guardrails

Add stack-aware guardrails that fail fast before dev/build/test/CI when a persistent project could execute attacker-controlled code.

## Trigger

Use this skill automatically for:
- Web apps, desktop apps, CLIs, local agents, backend services, CI/CD projects, or apps that read/write user files.
- Projects using executable configuration or package hooks: `package.json`, `vite.config.*`, `next.config.*`, `postcss.config.*`, `tailwind.config.*`, `eslint.config.*`, `webpack.config.*`, `Makefile`, `go test`, `build.rs`, `pyproject.toml`, `setup.py`, `.vscode/tasks.json`, GitHub Actions.
- Requests involving persistence, build hardening, malware injection, supply-chain risk, local filesystem access, token/credential handling, browser/desktop integration, or security guardrails.

Skip only for throwaway snippets, one-off static files, pure documentation, or when the user explicitly says not to add guardrails.

## Workflow

1. Detect stack and execution surfaces.
2. Create or reuse one small scanner script in the repo, preferably with no new dependency.
3. Integrate it before normal build/test/dev commands.
4. Ignore dependency/build/cache folders to keep false positives low.
5. Verify with direct scanner execution and one stack-specific command.

Prefer these commands when available:

```sh
npx --yes security-guardrails init --preset auto
npx --yes security-guardrails scan --ci --format json
npx --yes security-guardrails scan --mode audit --ci --format json
npx --yes security-guardrails scan --ci --format sarif
npx --yes security-guardrails diff-scan --staged
npx --yes security-guardrails scan-history --max-commits 1000
npx --yes security-guardrails explain suspicious-package-script
npx --yes security-guardrails install-hooks
npx --yes security-guardrails install-agent-rules --scope project
```

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

Prefer a project `.security-guardrails.json` for reviewed exceptions, extra literal IoCs, extra regex detections, and audit/block mode instead of weakening the scanner code. When allowing a committed executable, use a `{ "path": "...", "sha256": "..." }` entry. Put team-specific IoCs in `.security-guardrails.signatures.json`.

## Preferred CLI

When the package is available, prefer:

```sh
npx --yes security-guardrails init
npx --yes security-guardrails scan
```

## Final Report

Report files changed, commands wired, detections covered, verification results, and remaining runtime/credential risks.
