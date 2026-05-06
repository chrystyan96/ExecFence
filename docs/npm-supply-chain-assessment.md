# npm Supply Chain Assessment

Date: 2026-05-06

Scope: public, high-confidence npm supply-chain incidents and campaigns reported from 2025-05-06 through 2026-05-06. Campaigns that affected many packages are grouped by campaign rather than listed package by package.

## Executive Summary

ExecFence is strongest against npm malware that becomes active through install-time or command-time execution: `preinstall`, `install`, `postinstall`, `prepare`, npm script hooks, package scripts, suspicious lockfile source changes, risky workflow changes, unexpected binaries, and agent-driven command execution.

The new global package-manager guard makes that protection less dependent on the user remembering to type `execfence run --`. After `execfence guard global-enable`, terminal and agent-run `npm`/`npx`/`pnpm`/`yarn`/`yarnpkg` commands resolve through ExecFence shims first. Install-like commands (`install`, `ci`, `add`, `update`, `rebuild`) get a preflight scan, guarded dependency metadata review, and lifecycle-script suppression, which directly targets the lifecycle behavior used in many recent npm attacks.

ExecFence is not a formal proof that every dependency is safe. The current guard now checks install/lifecycle execution, changed lockfiles, guarded registry metadata, package reputation signals, tarball integrity/content, and optional runtime behavior containment. A payload that is intentionally indistinguishable from ordinary library logic can still evade static and metadata checks, so the control is layered risk reduction rather than a safety proof.

## npm Behavior That Matters

npm lifecycle scripts run automatically for several package manager operations. The npm scripts documentation lists install-related lifecycle events such as `preinstall`, `install`, `postinstall`, `prepublish`, `prepare`, and related hooks for `npm ci`, `npm install`, `npm rebuild`, `npm pack`, and `npm publish`. The npm install documentation also defines `ignore-scripts`; when true, npm does not run scripts from package manifests, while explicit script commands such as `npm run`, `npm test`, and `npm start` still run the intended script but skip pre/post scripts.

ExecFence uses that behavior intentionally:

- install-like commands are guarded and delegated with lifecycle scripts disabled
- script-running commands are scanned first, then delegated without changing the primary script semantics
- project and CI paths still use `execfence run --`, `ci`, `manifest diff`, `deps diff`, `deps review`, `pack-audit`, and reports because global shell interception is not a replacement for CI policy

References: [npm scripts](https://docs.npmjs.com/cli/v11/using-npm/scripts/), [npm install ignore-scripts](https://docs.npmjs.com/cli/v11/commands/npm-install/).

## Incident Mapping

| Date | Incident or campaign | Public reporting | Attack shape | ExecFence help |
| --- | --- | --- | --- | --- |
| May 2025 | Typosquat/network reconnaissance packages | Reporting described 60 npm packages uploaded from May 12 onward, using `postinstall` to exfiltrate hostnames, internal IPs, home directories, working directories, usernames, and DNS servers. | Direct install-time lifecycle execution. | Strong: global npm guard blocks lifecycle scripts for install-like commands; scanner lifecycle audit can flag suspicious exfiltration/download/shell behavior when package metadata is present in the project. |
| July 2025 | `eslint-config-prettier`, `eslint-plugin-prettier`, `synckit`, `@pkgr/core`, `napi-postinstall`, related packages | Snyk reported maintainer phishing against npm credentials and affected packages. JFrog documented the `eslint-config-prettier` hijack and clarified affected versions. | Maintainer/account compromise with malicious package releases and install script payloads, especially Windows-oriented payload execution. | Strong when the malicious release depends on install scripts. Partial when only dependency drift is visible: `deps diff`, lockfile audit, and reports can highlight the changed package/version, but package reputation is not live by default. |
| September 2025 | `chalk`, `debug`, `ansi-styles`, `color-convert`, `strip-ansi`, `wrap-ansi`, and related packages | StepSecurity reported a phishing-driven maintainer account compromise affecting 20+ high-traffic packages. The malicious code targeted browser/Web3 cryptocurrency flows rather than only install hooks. | Maintainer account compromise with malicious library code. Payload impact depended on where the package was used and executed. | Partial: lockfile/dependency drift, `deps diff`, package cooldown-style review, and runtime/script guarding help identify risky upgrades. ExecFence cannot guarantee prevention if the malicious code only runs later when bundled/imported by an app. |
| September 2025 | Shai-Hulud token theft and propagation | IMDA advisory describes `bundle.js` downloading and executing TruffleHog, collecting developer and CI/CD tokens, using GitHub tokens to enumerate repositories, and creating unauthorized GitHub workflow files. Unit 42 identifies Shai-Hulud as an inflection point for wormable npm compromises. | Credential theft, npm/GitHub token abuse, GitHub workflow persistence, and package republishing propagation. | Strong for install lifecycle entrypoints and suspicious workflow/task changes. Helpful for incident response through `agent-report`, report evidence, `incident bundle`, and workflow hardening checks. Gap: stolen-token propagation and external registry events still require token rotation, registry monitoring, and optional future live metadata/reputation checks. |
| November 2025 | Shai-Hulud follow-on campaigns | Public threat reporting described follow-on Shai-Hulud activity with preinstall hooks, Bun bootstrapping, credential theft, and large-scale GitHub repository impact. | Worm-style package infection and CI/developer credential theft. | Strong for `preinstall` and suspicious loader/script behavior when installing under global npm guard. Partial for already-installed payloads or compromised packages that execute only during later application runtime. |
| March 2026 | Axios plus `plain-crypto-js` | Datadog and SafeDep reported malicious `axios` releases that added `plain-crypto-js`, whose `postinstall` payload contacted C2 and downloaded platform-specific second stages. | Maintainer account/package release compromise with dependency injection and `postinstall` RAT delivery. | Strong: `--ignore-scripts=true` on install-like commands blocks the automatic `postinstall`; `deps diff` and lockfile audit can highlight sudden introduction of `plain-crypto-js`; reports preserve evidence for incident handling. |
| April 2026 | Bitwarden CLI npm distribution compromise | Bitwarden stated that `@bitwarden/cli@2026.4.0` was briefly distributed through the npm path between 5:57 PM and 7:30 PM ET on 2026-04-22, tied to a broader Checkmarx supply-chain incident. | Trusted tool distribution path compromise, aimed at developer/automation environments. | Helpful but not complete: global npm guard and scans can reduce risk around install/execution, `deps diff` can show unexpected version movement, and `pack-audit`/manifest review can catch package-content mismatches when artifacts are available. If a legitimate package name/version is pulled during the exposure window and malicious behavior is not visible until execution, live metadata/reputation and release-channel verification remain roadmap items. |
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

Implemented and roadmap fit:

- package release age/cooldown warnings and deprecation/security metadata in `deps review`
- guarded live package metadata for changed packages and explicit install specs
- package reputation signals for package age, recent metadata changes, maintainer count, integrity, and provenance/signature availability
- package tarball integrity/content review for newly introduced or upgraded packages
- code-level tarball audit for obfuscation, executable artifacts, process/network APIs, and credential-sensitive references

### Token theft and propagation campaigns

Coverage is strong at the initial lifecycle/script execution boundary and useful for post-block investigation, but incomplete for registry-wide propagation and already-stolen credentials.

Relevant controls:

- global npm/pnpm/yarn guard for lifecycle blocking
- `agent-report` for agent/MCP/tool and instruction-file exposure
- workflow hardening checks for suspicious GitHub Actions changes
- reports, `incident bundle`, and `incident timeline`
- baseline/trust policy to avoid normalizing high-severity findings

Implemented and roadmap fit:

- package install review reports that summarize newly introduced package versions, release age, lifecycle hints, integrity, and registry source
- optional sandbox/network policy for package scripts when scripts are intentionally re-enabled
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

## Gaps And Non-Claims

ExecFence does not claim that every npm dependency is safe.

Known gaps:

- malicious code that is intentionally shaped like normal library behavior can still evade static, metadata, and tarball heuristics
- compromised packages with no suspicious metadata, scripts, artifacts, lockfile source drift, runtime side effects, or known indicators may not be detected
- global package-manager guard protects the current shell PATH; CI, containers, IDE-integrated package managers, bun, and package manager wrappers still need explicit project/CI guardrails
- release age, deprecation, maintainer, provenance, integrity, and tarball signals are guarded for changed packages, but maintainer account risk is still inferred from public package metadata rather than verified identity telemetry
- once credentials have already been stolen, ExecFence reports help investigation but cannot undo exposure

## Implemented Residual-Risk Controls

1. `deps review` now expands release/deprecation metadata into package reputation signals: package age, recent package metadata modification, maintainer count, integrity presence, and provenance/signature availability.
2. `deps review` now performs guarded tarball integrity/content review for changed packages when registry metadata exposes a tarball URL.
3. Tarball content audit flags executable artifacts, obfuscated code, process/network APIs, and credential-sensitive references before install, bundle, or runtime import.
4. `guard global-status` now reports coverage gaps for current-shell PATH, bun, CI, containers, IDE-integrated package managers, and package-manager wrappers.
5. Lifecycle re-enable guidance uses `deps review`, `pack-audit`, and `execfence run --sandbox-mode audit -- npm|pnpm|yarn rebuild ...` rather than a raw reinstall with scripts enabled.
6. `execfence run --dependency-behavior-audit` attaches changed-dependency review and sandbox containment status to runtime evidence, warning when commands likely to import changed dependencies run without behavior containment.

## Remaining Roadmap

1. Add deeper tarball delta comparison against the previous resolved package version, not only single-version tarball inspection.
2. Add optional external reputation feeds for takedowns, compromised maintainer reports, and package ecosystem advisories.
3. Add real helper-backed runtime enforcement for dependency behavior: outbound network blocking, sensitive file read blocking, and child-process supervision.

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
