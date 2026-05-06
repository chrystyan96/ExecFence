# npm Supply Chain Assessment

Date: 2026-05-06

Scope: public, high-confidence npm supply-chain incidents and campaigns reported from 2025-05-06 through 2026-05-06. Campaigns that affected many packages are grouped by campaign rather than listed package by package.

## Executive Summary

ExecFence is strongest against npm malware that becomes active through install-time or command-time execution: `preinstall`, `install`, `postinstall`, `prepare`, npm script hooks, package scripts, suspicious lockfile source changes, risky workflow changes, unexpected binaries, and agent-driven command execution.

The new global package-manager guard makes that protection less dependent on the user remembering to type `execfence run --`. After `execfence guard global-enable`, terminal and agent-run `npm`/`npx`/`pnpm`/`yarn`/`yarnpkg`/`bun`/`bunx` commands resolve through ExecFence shims first. Install-like commands (`install`, `ci`, `add`, `update`, `rebuild`) get a preflight scan, guarded dependency metadata/reputation/tarball review, and lifecycle-script suppression, which directly targets the lifecycle behavior used in many recent npm attacks.

ExecFence is not a formal proof that every dependency is safe. The current guard checks install/lifecycle execution, changed lockfiles, guarded registry metadata, package reputation feeds, tarball integrity/content, tarball delta against the previous resolved version, strict supply-chain coverage, and helper-backed runtime containment when a verified helper is installed. A payload that is intentionally indistinguishable from ordinary library logic can still evade static, metadata, tarball, runtime, and feed checks, so the control is layered risk reduction rather than a semantic safety proof.

## npm Behavior That Matters

npm lifecycle scripts run automatically for several package manager operations. The npm scripts documentation lists install-related lifecycle events such as `preinstall`, `install`, `postinstall`, `prepublish`, `prepare`, and related hooks for `npm ci`, `npm install`, `npm rebuild`, `npm pack`, and `npm publish`. The npm install documentation also defines `ignore-scripts`; when true, npm does not run scripts from package manifests, while explicit script commands such as `npm run`, `npm test`, and `npm start` still run the intended script but skip pre/post scripts.

ExecFence uses that behavior intentionally:

- install-like commands are guarded and delegated with lifecycle scripts disabled for npm, pnpm, Yarn, and Bun
- script-running commands are scanned first, then delegated without changing the primary script semantics
- project and CI paths still use `execfence run --`, `ci`, `manifest diff`, `deps diff`, `deps review`, `pack-audit`, and reports because global shell interception is not a replacement for CI policy

References: [npm scripts](https://docs.npmjs.com/cli/v11/using-npm/scripts/), [npm install ignore-scripts](https://docs.npmjs.com/cli/v11/commands/npm-install/).

## Incident Mapping

| Date | Incident or campaign | Public reporting | Attack shape | ExecFence help |
| --- | --- | --- | --- | --- |
| May 2025 | Typosquat/network reconnaissance packages | Reporting described 60 npm packages uploaded from May 12 onward, using `postinstall` to exfiltrate hostnames, internal IPs, home directories, working directories, usernames, and DNS servers. | Direct install-time lifecycle execution. | Strong: global npm guard blocks lifecycle scripts for install-like commands; scanner lifecycle audit can flag suspicious exfiltration/download/shell behavior when package metadata is present in the project. |
| July 2025 | `eslint-config-prettier`, `eslint-plugin-prettier`, `synckit`, `@pkgr/core`, `napi-postinstall`, related packages | Snyk reported maintainer phishing against npm credentials and affected packages. JFrog documented the `eslint-config-prettier` hijack and clarified affected versions. | Maintainer/account compromise with malicious package releases and install script payloads, especially Windows-oriented payload execution. | Strong when the malicious release depends on install scripts. For dependency drift, `deps diff`, `deps review`, metadata/reputation, tarball audit, tarball delta, and strict CI coverage make the version movement and artifact changes reviewable. |
| September 2025 | `chalk`, `debug`, `ansi-styles`, `color-convert`, `strip-ansi`, `wrap-ansi`, and related packages | StepSecurity reported a phishing-driven maintainer account compromise affecting 20+ high-traffic packages. The malicious code targeted browser/Web3 cryptocurrency flows rather than only install hooks. | Maintainer account compromise with malicious library code. Payload impact depended on where the package was used and executed. | Partial: lockfile/dependency drift, `deps diff`, package cooldown-style review, and runtime/script guarding help identify risky upgrades. ExecFence cannot guarantee prevention if the malicious code only runs later when bundled/imported by an app. |
| September 2025 | Shai-Hulud token theft and propagation | IMDA advisory describes `bundle.js` downloading and executing TruffleHog, collecting developer and CI/CD tokens, using GitHub tokens to enumerate repositories, and creating unauthorized GitHub workflow files. Unit 42 identifies Shai-Hulud as an inflection point for wormable npm compromises. | Credential theft, npm/GitHub token abuse, GitHub workflow persistence, and package republishing propagation. | Strong for install lifecycle entrypoints and suspicious workflow/task changes. Helpful for incident response through `agent-report`, report evidence, `incident bundle`, token-rotation guidance, workflow hardening, metadata/reputation review, and strict CI checks. |
| November 2025 | Shai-Hulud follow-on campaigns | Public threat reporting described follow-on Shai-Hulud activity with preinstall hooks, Bun bootstrapping, credential theft, and large-scale GitHub repository impact. | Worm-style package infection and CI/developer credential theft. | Strong for `preinstall`, Bun-triggered lifecycle paths, suspicious loader/script behavior, global npm/pnpm/yarn/bun guard, and strict runtime containment when a helper is available. Partial only for payloads that execute later as ordinary library code without detectable signals. |
| March 2026 | Axios plus `plain-crypto-js` | Datadog and SafeDep reported malicious `axios` releases that added `plain-crypto-js`, whose `postinstall` payload contacted C2 and downloaded platform-specific second stages. | Maintainer account/package release compromise with dependency injection and `postinstall` RAT delivery. | Strong: `--ignore-scripts=true` on install-like commands blocks the automatic `postinstall`; `deps diff` and lockfile audit can highlight sudden introduction of `plain-crypto-js`; reports preserve evidence for incident handling. |
| April 2026 | Bitwarden CLI npm distribution compromise | Bitwarden stated that `@bitwarden/cli@2026.4.0` was briefly distributed through the npm path between 5:57 PM and 7:30 PM ET on 2026-04-22, tied to a broader Checkmarx supply-chain incident. | Trusted tool distribution path compromise, aimed at developer/automation environments. | Helpful but not complete: global guard and scans reduce risk around install/execution, `deps diff` shows unexpected version movement, `deps review` checks metadata/reputation/tarball signals, and strict mode can block missing/unavailable signals in CI. If the exposed artifact has no detectable metadata, tarball, runtime, or feed signal, ExecFence documents that as a non-claim rather than pretending proof. |
| April 2026 | SAP CAP / Mini Shai-Hulud | Socket reported SAP ecosystem packages with injected `preinstall` scripts that downloaded Bun from GitHub Releases, extracted it, and executed an obfuscated payload. | Install-time bootstrapper and large obfuscated payload execution. | Strong: global npm guard blocks install lifecycle execution by default; scanner lifecycle rules can flag `preinstall`, binary download, PowerShell execution-policy bypass, and suspicious execution chains. |

## Control Coverage By Attack Type

### Lifecycle and install-script malware

Coverage is strong. This includes the May 2025 typosquat/exfiltration packages, Axios/`plain-crypto-js`, SAP CAP/Mini Shai-Hulud, and Shai-Hulud-style variants that rely on `preinstall` or `postinstall`.

Relevant controls:

- `execfence guard global-enable` installs npm/npx/pnpm/yarn/yarnpkg shims for terminal and agent-run commands
- install-like commands run the real package manager with lifecycle scripts disabled
- lifecycle script audit flags download/eval/pipe-to-shell/PowerShell/LOLBins
- `scan --mode block`, `ci`, reports, and incident bundles preserve evidence

### Maintainer compromise with malicious releases

Coverage is mixed. If the malicious release uses lifecycle hooks, suspicious scripts, unexpected binaries, lockfile source drift, or CI/agent execution changes, ExecFence helps meaningfully. If the malicious code sits in ordinary library files and only runs after application import or browser bundling, ExecFence can flag surrounding drift but cannot prove the library behavior is safe.

Relevant controls:

- `deps diff [--base-ref <ref>]`
- `deps review [--base-ref <ref>] [--package-manager auto|npm|pnpm|yarn]`
- lockfile source audit
- `manifest diff`
- `pack-audit`
- report comparison and regression checks

Implemented controls:

- package release age/cooldown warnings and deprecation/security metadata in `deps review`
- guarded live package metadata for changed packages and explicit install specs
- package reputation signals from npm registry metadata, OSV advisory queries, no-auth GitHub Advisory status when available, package age, recent metadata changes, maintainer count, integrity, and provenance/signature availability
- package tarball integrity/content review for newly introduced or upgraded packages
- tarball delta comparison against the previous resolved package version for changed dependencies
- code-level tarball audit for obfuscation, executable artifacts, process/network APIs, and credential-sensitive references
- `strict` mode that blocks unavailable signals, cooldowns, missing integrity/provenance, uncovered package-manager surfaces, and runtime dependency behavior audits without helper enforcement

### Token theft and propagation campaigns

Coverage is strong at the initial lifecycle/script execution boundary and useful for post-block investigation, but incomplete for registry-wide propagation and already-stolen credentials.

Relevant controls:

- global npm/pnpm/yarn guard for lifecycle blocking
- `agent-report` for agent/MCP/tool and instruction-file exposure
- workflow hardening checks for suspicious GitHub Actions changes
- reports, `incident bundle`, and `incident timeline`
- baseline/trust policy to avoid normalizing high-severity findings

Implemented controls:

- package install review reports that summarize newly introduced package versions, release age, lifecycle hints, integrity, and registry source
- helper-backed sandbox/network/process/filesystem policy for package scripts when scripts are intentionally re-enabled; without the helper, audit mode is evidence only
- first-class guidance for token rotation and cache purge after a block
- optional monitoring of suspicious package publish metadata in release workflows
- `execfence run --dependency-behavior-audit` to attach changed-dependency review and sandbox containment status to runtime evidence

## What ExecFence Would Have Done

For a developer or agent running `npm install` after global guard was enabled:

1. The shell resolves `npm` to `<home>/.execfence/shims/npm`.
2. The shim calls `execfence npm-guard npm ...`.
3. ExecFence performs a preflight scan in the current project.
4. If findings are blocking, npm is not started.
5. If the command is install-like, ExecFence reviews explicit package metadata when available and delegates to the real package manager with lifecycle scripts disabled.
6. The user sees output explaining that lifecycle scripts were blocked and should only be run after reviewing dependency reports.

For CI and repository-shared workflows:

1. Keep `execfence ci` and `execfence run -- <command>` in workflows.
2. Use `deps diff`, `deps review`, `manifest diff`, `pack-audit`, and `trust audit` to make risky package and execution-surface changes reviewable.
3. Store reports as local evidence and build incident bundles when a block happens.

## Controls Implemented

1. `deps review` expands release/deprecation metadata into package reputation signals: package age, recent package metadata modification, maintainer count, integrity presence, and provenance/signature availability.
2. `deps review` queries no-token reputation feeds for changed or explicit public npm packages, including OSV package advisories and npm registry metadata, with private-scope and private-registry skips by default.
3. Reputation results cache under `.execfence/cache/supply-chain-reputation/`; metadata and tarball results remain capped, timed out, and fail-open in `guarded`.
4. `deps review` performs guarded tarball integrity/content review when registry metadata exposes a tarball URL.
5. Changed dependencies get real tarball delta against the previous resolved version, including added, removed, and changed files, hashes, size, type, and findings for new executable artifacts, obfuscation, process/network APIs, and credential-sensitive references.
6. Added dependencies with no prior version keep single-tarball audit and are marked with `baseline: none`.
7. `guard global-enable` installs reversible shims for `npm`, `npx`, `pnpm`, `yarn`, `yarnpkg`, `bun`, and `bunx`.
8. Install-like npm/pnpm/Yarn/Bun commands run with lifecycle scripts disabled; script-running commands keep their primary command semantics after preflight.
9. `guard global-status` reports current-shell PATH state, real package-manager paths, recursion guard, updated profiles, and gaps for CI, containers, IDE integrations, Corepack, Volta, nvm/asdf, and local wrappers.
10. `coverage` and `ci` treat uncovered JS package-manager execution surfaces as findings in `strict` mode when a matching lockfile or package-manager command exists.
11. `supplyChain.mode: "strict"` blocks unavailable metadata, reputation, or tarball signals, missing integrity/provenance signals, release cooldowns, new package age windows, uncovered package-manager surfaces, and runtime dependency behavior audits without helper enforcement.
12. The sandbox helper contract requires declared capabilities for outbound network blocking, sensitive path reads, child-process supervision, and new executable/archive blocking. Without those capabilities, enforce mode blocks and audit mode is evidence only.
13. `execfence run --dependency-behavior-audit` attaches changed-dependency review and sandbox containment status to runtime evidence; in `strict`, commands likely to import changed dependencies block unless containment is helper-enforced.
14. Token-theft response guidance covers report preservation, incident bundles, token rotation, cache purge, workflow review, dependency review, and package rollback.

## Non-Claims

ExecFence does not claim that every npm dependency is safe.

The remaining limitation is factual rather than actionable inside ExecFence alone: ExecFence cannot semantically prove that arbitrary library code is benign if the package has no suspicious lifecycle behavior, metadata signal, reputation-feed signal, tarball/delta artifact, runtime side effect under audited execution, lockfile/source drift, or known indicator. Closing that class of risk requires external containment or telemetry such as a verified enforcement helper, EDR, network controls, human code review, or application-specific runtime tests.

## References

- npm: [scripts lifecycle behavior](https://docs.npmjs.com/cli/v11/using-npm/scripts/)
- npm: [`ignore-scripts` configuration](https://docs.npmjs.com/cli/v11/commands/npm-install/)
- pnpm: [`--ignore-scripts`](https://pnpm.io/cli/install)
- Yarn: [`enableScripts`](https://yarnpkg.com/configuration/yarnrc#enableScripts)
- TechRadar/Socket reporting: [60 malicious npm packages using postinstall exfiltration](https://www.techradar.com/pro/security/npm-users-warned-dozens-of-malicious-packages-aim-to-steal-host-and-network-data)
- Snyk: [ESLint/Prettier npm malware via maintainer compromise](https://snyk.io/blog/maintainers-of-eslint-prettier-plugin-attacked-via-npm-supply-chain-malware/)
- JFrog: [`eslint-config-prettier` hijack analysis](https://research.jfrog.com/post/eslint-config-prettier-hijack-10-1-6-safe/)
- StepSecurity: [Chalk, Debug, Strip-ANSI, Color-Convert, Wrap-ANSI compromise](https://www.stepsecurity.io/blog/20-popular-npm-packages-compromised-chalk-debug-strip-ansi-color-convert-wrap-ansi)
- IMDA: [npm supply-chain attack advisory](https://www.imda.gov.sg/-/media/imda/files/regulations-and-licensing/regulations/advisories/infocomm-media-cyber-security/npm-supply-chain-attack.pdf)
- Unit 42: [npm threat landscape and Shai-Hulud follow-on campaigns](https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/)
- Datadog Security Labs: [Axios npm compromise](https://securitylabs.datadoghq.com/articles/axios-npm-supply-chain-compromise/)
- SafeDep: [Axios compromise via `plain-crypto-js`](https://safedep.io/axios-npm-supply-chain-compromise/)
- Bitwarden: [statement on Checkmarx supply-chain incident](https://community.bitwarden.com/t/bitwarden-statement-on-checkmarx-supply-chain-incident/96127)
- Socket: [SAP CAP npm package compromise](https://socket.dev/blog/sap-cap-npm-packages-supply-chain-attack)
