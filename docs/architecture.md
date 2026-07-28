# ExecFence architecture

ExecFence is organized around a small set of security boundaries instead of command-specific policy copies.

## Layers

1. **Domain and decision layer**
   - `lib/decision-engine.js` is the single severity/mode decision point.
   - Findings use independent severity, confidence, decision, enforcement, and decision-reason fields.
   - `lib/contracts.js` versions public domain/report/manifest/helper/approval contracts.
   - `lib/approvals.js` verifies narrow, expiring, quorum-signed authorization without trusting embedded keys.
   - `lib/policy.js` resolves built-in or custom policy packs and applies the non-negotiable security floor.
   - Findings remain plain, serializable domain objects so scan, CI, runtime, SARIF, and reports share the same evidence.
2. **Discovery and adapters**
   - `lib/ecosystems.js` and `lib/command-parser.js` identify tools, value-taking options, risky commands, and package-manager semantics.
   - `lib/deps.js` recursively discovers monorepo manifests and lockfiles and preserves dependency identity by ecosystem, lockfile, and install slot.
   - `lib/workflow-parser.js` models workflow job/step order so coverage is inherited only from an earlier gate in the same job.
3. **Analysis services**
   - `lib/scanner.js`, `lib/deps-review.js`, `lib/coverage.js`, and `lib/manifest.js` produce evidence without approving baselines.
   - Registry metadata, reputation, and archive inspection are independent signals. Failure or disabling of one does not silently disable the others.
4. **Application orchestration**
   - `lib/runtime.js` owns preflight, optional helper delegation, timeout, filesystem snapshots, postflight, and trace assembly.
   - `lib/ci.js` aggregates read-only checks. It never writes the approved execution manifest.
   - `lib/cli.js` maps commands and explicit mutation verbs such as `manifest approve` to application services.
   - `lib/api.js` is the stable programmatic facade used by future IDE and UI adapters.
5. **Infrastructure**
   - Filesystem, Git, registry HTTP, reports, shims, and the Go sandbox helper are isolated behind their respective modules.
   - The Go helper claims only capabilities demonstrated by its self-test. Audit mode is evidence; enforce mode requires verified capability proof.
   - `lib/ci-adapters.js` projects shared results into SARIF, GitHub annotations, and step summaries.
   - `lib/scan-cache.js` keys reusable analysis by content hash, policy fingerprint, and tool version.

## Security invariants

- Repository-controlled configuration cannot switch the default scan to audit, remove critical/high blocking, narrow the default scan, disable postflight inspection, mandatory dependency checks, or mandatory CI checks.
- Configured files and output directories must stay inside the project root, including after symbolic-link resolution.
- A sandbox policy can only narrow a profile's filesystem, process, and network allowances; it cannot broaden them.
- Executable exceptions require path, SHA-256, and reason.
- A global shim is coverage only when it is installed **and active in the current `PATH`**.
- Workflow coverage never flows backward or across jobs.
- Sandbox degradation is represented as effective `audit` mode and emits a finding.
- Manifest generation and diff are read-only; only `manifest approve` mutates the approved baseline. CI compares against the base-ref version so a same-change manifest rewrite cannot self-approve new execution surfaces.
- Dependency identity includes its occurrence, so nested packages and multiple workspaces do not overwrite one another.
- Degraded enforce-to-audit execution is forbidden in CI.
- A signed approval is accepted only from a separately trusted, unexpired public key and only after distinct-signer quorum.
- An explicit CI base ref must exist; ExecFence does not silently self-compare a pull request against its own HEAD.

The formal adversary, trust-boundary, mode, runtime, approval, and non-claim contract is in [Threat model](threat-model.md).

## Extension points

- Add ecosystems through `lib/ecosystems.js` plus a parser in `lib/deps.js`.
- Add detections as finding producers; use `lib/decision-engine.js` for policy outcomes.
- Add output formats as projections of existing domain results rather than new analysis paths.
- Add helper capabilities only with a self-test, platform implementation, CLI capability mapping, and Go/Node integration tests.
