# Additional functionality implementation plan

This plan covers the product features intentionally left after the current security-core work. Each item must reuse the versioned public API and finding/approval contracts; no interface may invent a second decision engine.

## Delivery principles

- Every UI is a projection of the same findings, decisions, capabilities, and approvals.
- A feature cannot claim prevention without a capability probe and an adversarial test.
- Mutations require an explicit action, justification, and audit event.
- Local-only workflows remain useful without a hosted service.
- Remote policy and evidence are signed, versioned, cached safely, and fail according to an explicit policy.

## Phase 1 — Developer visibility

### VS Code extension

Scope:

- run scan-on-open and scan-on-save through the public API
- display findings, severity, confidence, decision, and exact remediation inline
- show the effective capability matrix before running tasks
- provide explicit commands for report viewing and approval-request generation

Dependencies:

- stable JSON/RPC bridge over `lib/api.js`
- finding location and schema compatibility tests
- cancellation and debounce support

Acceptance criteria:

- the extension never auto-approves or silently changes policy
- VS Code tasks use the same `execfence run` decision path
- workspace configuration cannot disable organization floors
- Windows, Linux, remote containers, and WSL are covered by integration tests

### Local dashboard

Scope:

- localhost-only dashboard for findings, reports, manifests, capabilities, and approvals
- filters by repository, decision, confidence, surface, package, and time
- read-only by default; mutations use CSRF protection and explicit confirmation

Dependencies:

- local authenticated session token
- report index and pagination API
- safe HTML escaping and path redaction

Acceptance criteria:

- binds to loopback only unless explicitly configured
- never renders untrusted report content as active HTML
- supports at least 10,000 findings without loading all records in memory

### Evidence export for audit

Scope:

- deterministic JSON, SARIF, Markdown, and signed evidence bundles
- include policy hash, manifest hash, capability proof, approval quorum, Git identity, and SBOM references
- optional redaction profiles

Acceptance criteria:

- repeated export of identical evidence has a stable content hash
- verification works offline
- missing/invalid signatures are visible and machine-readable

## Phase 2 — Governance and simulation

### Approval history

Scope:

- append-only local audit log for creation, signing, use, expiry, revocation, and failed verification
- answer “who approved this execution surface, why, and under which commit/policy?”
- support export to SIEM without requiring it

Design:

- hash-chained JSONL events
- periodic signed checkpoints
- approval IDs remain immutable; corrections create new events

Acceptance criteria:

- deletion or reordering of events is detected
- report generation links every suppression to its approval-use event
- revocation is effective immediately

### Policy simulation

Scope:

- `execfence policy simulate --policy <file> [--base-ref <ref>]`
- compare current and proposed decisions without mutation
- show newly blocked, newly allowed, unchanged, and capability-dependent outcomes
- estimate CI and developer impact using recent reports

Acceptance criteria:

- simulation cannot write policy, trust, manifest, or approvals
- output identifies every security-floor conflict
- results are reproducible from an exported evidence bundle

### Official profiles

Profiles:

- `personal`: low-friction local evidence with critical/high blocking
- `team`: signed exceptions, manifest review, CI annotations
- `ci-strict`: no degraded execution, strict supply-chain failure policy
- `high-assurance`: two-person approvals, signed policy/manifest, full proven containment

Acceptance criteria:

- profiles only add restrictions over the built-in floor
- capability requirements and failure policy are documented per profile
- profile migrations are versioned and backwards-compatible

### Signed remote organization policy

Scope:

- fetch organization policy over HTTPS from an allowlisted endpoint
- verify signature, issuer/key ID, version, expiry, rollback protection, and minimum ExecFence version
- cache the last valid policy for offline work

Acceptance criteria:

- an unsigned, expired, downgraded, or rollback policy is rejected
- repository config cannot replace the organization endpoint/key
- offline behavior is explicit (`cached-allow`, `cached-block`, or `fail-closed`)
- policy merge explains which organization rule produced each decision

## Phase 3 — Integrations and behavioral analysis

### IDE and tool API

Scope:

- documented Node API plus versioned JSON-RPC subprocess protocol
- scan, decide, explain, capability probe, dependency review, and approval-request methods
- streaming progress and cancellation

Acceptance criteria:

- compatibility suite for at least two API versions
- consumers cannot bypass policy resolution by submitting a pre-decided finding
- untrusted paths are resolved through the project-safe path boundary

### Install-versus-runtime behavior comparison

Scope:

- run dependency install/build/import phases in isolated, disposable workspaces
- compare process, filesystem, executable, and network events by phase
- identify code that is dormant during install but activates on import/test

Dependencies:

- platform event backends
- deterministic environment capture
- package-manager adapters and network-domain normalization

Acceptance criteria:

- event provenance identifies package, phase, process tree, and policy decision
- ephemeral events are retained even if a package deletes traces
- no host credentials are exposed to the disposable workspace

### Dependency quarantine

Scope:

- materialize a package and its minimal dependency graph into a disposable workspace
- deny access to the real repository, user home, credentials, and non-allowlisted network
- produce archive delta, runtime behavior, SBOM fragment, and approval request

Acceptance criteria:

- quarantine refuses to start without the required proven platform capabilities
- all outputs are copied out through a reviewed artifact boundary
- teardown is deterministic and leaves an auditable result
- hostile archive, fork bomb, disk exhaustion, process escape, and network bypass tests pass

## Suggested milestones

1. **M1 — Visibility:** JSON-RPC bridge, VS Code extension MVP, deterministic evidence export.
2. **M2 — Local operations:** dashboard, indexed report history, approval audit log.
3. **M3 — Governance:** simulation, official profiles, signed remote policy.
4. **M4 — Behavioral security:** OS event backends and install/runtime comparison.
5. **M5 — High assurance:** disposable dependency quarantine with proven containment.

Each milestone requires schema migration notes, threat-model update, cross-platform tests, performance budgets, and documentation before release.
