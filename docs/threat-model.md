# ExecFence threat model and guarantee contract

## Security objective

ExecFence reduces the chance that repository-controlled code, dependency changes, build metadata, IDE tasks, CI workflows, or agent configuration execute without a reviewable security decision. It protects the transition from **code at rest** to **code executing with developer or CI authority**.

An ExecFence pass means that the configured checks found no unapproved blocking evidence. It does not prove that source code or a dependency is benign.

## Assets

- developer files, credentials, SSH keys, browser/session data, wallets, and cloud credentials
- repository source, Git history, release tokens, signing keys, and package-publishing authority
- CI tokens, artifacts, caches, deployment credentials, and protected environments
- policy, manifest, approval, trust, and report integrity

## Adversaries and entry paths

The model includes:

- a malicious or compromised repository contributor
- a compromised package, maintainer, registry artifact, action, build plugin, or transitive dependency
- social engineering that persuades a developer or agent to clone, open, install, build, test, or run a project
- repository-controlled configuration that attempts to narrow scanning, lower severity floors, self-approve a manifest, disable runtime evidence, or broaden sandbox policy
- a pull request that changes code and its supposed approval or policy baseline together

The model does not assume protection after an attacker already controls the user account, OS kernel, trusted helper binary, trusted signing key, or ExecFence installation.

## Trust boundaries

1. Repository content is untrusted until scanned and decided.
2. Repository configuration can narrow permissions but cannot remove mandatory security floors.
3. Baselines are legacy reviewed exceptions; signed approvals are the stronger authorization mechanism.
4. Approval signatures are valid only when their public key is in the local trusted-approver store, unexpired, and a distinct-signer quorum is met.
5. A helper capability counts as enforced only after binary hash, provenance metadata, platform/architecture, protocol, and self-test proof are verified.
6. Registry requests are limited to explicit HTTPS endpoints and bounded responses. Registry metadata is evidence, not proof of package safety.
7. Cache entries are reusable analysis results only for identical content hash, policy fingerprint, and ExecFence version. A cache hit is not an approval.
8. CI and release workflows perform a shell-level bootstrap integrity check on the executable shim and CLI module before loading project JavaScript, then scan source before `npm ci --ignore-scripts`.

## Finding contract

Every decision-capable finding separates:

- `severity`: potential impact (`critical`, `high`, `medium`, `low`)
- `confidence`: certainty of the detection (`high`, `medium`, `low`)
- `decision`: policy result (`block`, `review`, `allow`)
- `enforcement`: what happened (`block`, `review`, `allow`, or `reported` in audit mode)
- `decisionReason`: the effective-policy explanation

Coverage, a manifest entry, and a clean postflight snapshot are evidence dimensions, not safety claims.

## Mode guarantees

### Block

Mandatory critical/high findings stop guarded execution. Scan scope and blocking floors cannot be reduced by repository configuration.

### Audit

The policy decision is preserved, but a would-block finding has `enforcement: reported`. Audit provides evidence and does not claim containment.

### Sandbox enforce

The command starts only if the verified helper proves every required capability for the selected policy. Missing filesystem, sensitive-read, process-tree, network, or executable-creation enforcement blocks before execution.

### Degraded execution

Degradation from enforce to audit:

- requires the explicit CLI flag and a justification
- cannot be enabled in repository configuration
- is forbidden in CI
- is recorded in the runtime trace and report

## Runtime prevention matrix

| Control | Built-in audit | Verified Windows helper | Verified Linux helper |
| --- | --- | --- | --- |
| Preflight and postflight scan | Evidence | Evidence | Evidence |
| Root-process supervision | Root process only | Enforced | Enforced |
| Descendant cleanup | Not claimed | Windows Job Object enforcement | Best-effort process-group cleanup; not claimed as complete |
| New executable/archive creation | Postflight detection | Polled during runtime; supervised tree terminated on detection | Polled during runtime; process group terminated on detection |
| Arbitrary filesystem write prevention | Not claimed | Requires a helper/backend that proves it | Requires a helper/backend that proves it |
| Sensitive-read prevention | Not claimed | Requires a helper/backend that proves it | Requires a helper/backend that proves it |
| Outbound network prevention | Not claimed | Requires an elevated/proven backend | Requires a namespace/firewall backend that proves it |

Runtime polling reduces exposure but is not atomic kernel mediation: a write can occur before the poll observes it. Therefore it is reported as the `newExecutables` capability, not as general filesystem enforcement.

The bootstrap check catches the appended-loader patterns it declares; it is not a proof that an already-compromised ExecFence checkout is benign. Release authority still requires reviewed source, pinned CI actions, protected credentials, and the tag-sourced provenance workflow.

## Supply-chain guarantees

ExecFence can:

- detect source/registry drift, dependency-confusion and typosquatting signals
- review age, cooldown, maintainer presence, advisories, integrity, and provenance hints
- bound and inspect tar/ZIP artifacts, verify supported integrity formats, and compare archive deltas
- detect lifecycle scripts, executable entrypoints, native artifacts, obfuscation, and runtime-sensitive APIs
- compare two explicit versions with `execfence deps compare`

It does not replace a vulnerability-management program, reproduce every upstream build, or prove that an attestation issuer is trustworthy. Provenance evidence and cryptographic artifact integrity are separate checks.

## Approval guarantees

An active approval is narrow by type and subject, may be bound to file/package/integrity/hash, can be scoped to branch/commit/command/environment, expires, and requires a configurable number of distinct trusted signatures.

Embedding a public key in an approval does not make it trusted. Trust is established separately with `execfence approval key-add`.

## Known non-goals

ExecFence is not:

- antivirus, EDR, secret scanning, or full SCA
- a proof that arbitrary application/library code is benign
- a system-wide sandbox without a verified platform backend
- protection against a compromised kernel, trusted helper, signing key, or ExecFence binary
- a substitute for human review of high-impact changes

## Failure policy

- mandatory local analysis fails closed
- sandbox enforce fails closed when capability proof is incomplete
- strict supply-chain mode fails closed on configured unavailable evidence
- guarded/audit network metadata failures remain visible and follow the configured failure policy
- invalid or expired approvals never suppress findings
- an unavailable explicit CI base ref blocks instead of silently comparing against the current commit
