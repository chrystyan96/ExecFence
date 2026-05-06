# ExecFence

Guard npm/pnpm/yarn/Bun installs, dependency changes, CI, and agent-run commands before suspicious project code executes.

ExecFence is a local execution and supply-chain guardrail for JavaScript projects, CI pipelines, package releases, and coding agents. It puts a reviewable fence in front of risky commands such as dependency installs, tests, builds, package scripts, publish steps, and agent-driven tool execution.

## Quick Start

Run a scan without installing globally:

```sh
npx --yes execfence scan
```

Guard a command before it runs:

```sh
npx --yes execfence run -- npm test
```

Enable project-local guardrails:

```sh
npx --yes execfence guard enable
npx --yes execfence guard enable --apply
```

Enable global package-manager interception for terminal and agent-run commands:

```sh
npx --yes execfence guard global-enable
```

## What Version 4 Adds

ExecFence v4 focuses on npm supply-chain attacks and package-manager execution:

- global shims for `npm`, `npx`, `pnpm`, `yarn`, `yarnpkg`, `bun`, and `bunx`
- lifecycle-script suppression for install-like commands
- dependency metadata and reputation review for changed packages
- OSV advisory checks without npm tokens or user credentials
- tarball integrity/content audit and tarball delta against the previous version
- `supplyChain.mode: "strict"` for CI/release workflows
- runtime dependency behavior audit with helper-backed enforcement when available

Install-like commands such as `npm install`, `npm ci`, `pnpm add`, `yarn install`, and `bun add` run through ExecFence first. When they are allowed, ExecFence delegates to the real package manager with lifecycle scripts disabled. Script-running commands such as `npm run`, `npm test`, `yarn start`, `bun test`, `pack`, and `publish` keep their main command semantics after the preflight scan passes.

## Common Commands

```sh
npx --yes execfence --help
npx --yes execfence scan
npx --yes execfence run -- npm test
npx --yes execfence ci
npx --yes execfence deps review
npx --yes execfence coverage
npx --yes execfence pack-audit
npx --yes execfence agent-report
npx --yes execfence sandbox doctor
```

## Strict Supply-Chain Mode

For security-sensitive CI, release, or package-publishing workflows:

```json
{
  "supplyChain": {
    "mode": "strict"
  }
}
```

`strict` blocks unavailable metadata/reputation/tarball signals, missing integrity/provenance signals, release cooldowns, new package age windows, uncovered package-manager surfaces, and dependency runtime audits that lack helper-backed containment.

## When ExecFence Blocks

Do not rerun the command outside ExecFence just to bypass the block. Start with the report:

```sh
npx --yes execfence reports latest
npx --yes execfence incident bundle --from-report .execfence/reports/<report>.json
```

If the finding is legitimate and must be allowed, create a narrow reviewed baseline with owner, reason, expiry, and hash.

## Documentation

The npm README is intentionally short. Full documentation lives here:

- [Full documentation](https://chrystyan96.github.io/ExecFence/)
- [Source docs](docs/README.md)
- [Detection model](docs/detection.md)
- [Release cadence](docs/release-cadence.md)
- [OpenAI Skills catalog PR](https://github.com/openai/skills/pull/385)

## Non-Claims

ExecFence does not replace antivirus, EDR, secret scanning, dependency vulnerability management, or human review. It does not prove that arbitrary library code is benign. It blocks and records the execution paths and supply-chain signals it can observe: scripts, lockfiles, package metadata, reputation feeds, tarballs, runtime evidence, workflows, binaries, archives, and agent/tool configuration.

## License

Apache-2.0
