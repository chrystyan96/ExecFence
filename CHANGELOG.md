# Changelog

## v3.1.0 - 2026-05-01

- Added `execfence guard status|plan|enable|disable|global-status|global-enable` for dry-run-first automatic project guardrail setup.
- Added project guard mode orchestration for init, coverage, wiring, local agent rules, CI status, and conservative rollback.
- Expanded wiring and coverage for npm lifecycle scripts, pack/publish scripts, Makefile pack/publish targets, and common CI commands for Node, Go, Python, Rust, and Make.
- Documented the recommended automatic setup path and the non-invasive global mode that installs only skill/defaults and agent rules.

## v3.0.0 - 2026-05-01

- Added sandbox policy layout with `.execfence/config/sandbox.json`, `execfence sandbox init|doctor|plan|explain`, helper metadata auditing, and deterministic capability reports.
- Added `execfence run --sandbox` / `--sandbox-mode enforce` blocking when filesystem, process, or network enforcement is unavailable, with explicit audit/degraded downgrade controls.
- Added `execfence run --sandbox-mode audit` to execute with sandbox policy evidence, capability matrix, blocked-operation plan, and V3 report sandbox sections.
- Hardened agent/MCP reporting for broad shell, filesystem, network, credential access, and instructions that try to disable ExecFence.

## v2.5.0 - 2026-05-01

- Added low-noise adoption mode with `execfence adopt`, correction plans, wiring suggestions, and optional suggested baselines for existing projects.
- Added Markdown report export, report regression scoring, redaction preview for enrichment, richer incident timelines, and report analysis fields with why-it-matters and exact next actions.
- Added custom policy pack loading from `.execfence/config/policies/`, plus `policy explain` and `policy test` for local organization controls and baseline validation.
- Hardened runtime tracing with file snapshots, created/modified/deleted/renamed file evidence, local trace-tool availability, and stronger new-executable artifact detection without adding a daemon or sandbox.

## v2.1.0 - 2026-05-01

- Added `execfence ci` as the aggregate operational gate for scan, manifest diff, dependency diff, pack audit, trust audit, and automatic report generation.
- Added `execfence deps diff` with dedicated parsers for npm/pnpm/yarn/bun, Cargo, Go, Poetry, and uv lockfiles plus registry drift, suspicious source, lifecycle/bin, dependency-confusion, and typosquatting findings.
- Added `execfence wire --dry-run|--apply`, coverage fix suggestions, manifest-gate findings, richer trust stores, baseline creation from reports, report latest/open/compare/prune, incident bundles/timelines, and actionable PR comments.
- Expanded runtime tracing with artifact metadata and `--deny-on-new-executable`, and expanded config/schema/docs for V2.1 `ci`, `wire`, `deps`, `trustStore`, `htmlReport`, and `reports.retention`.

## v2.0.0 - 2026-05-01

- Added `execfence run -- <command>` as the primary local runtime gate for dev/build/test with preflight scan, blocking, lightweight trace, post-run rescan, and automatic V2 evidence reports.
- Added execution manifests, manifest diffing, coverage enforcement for `execfence run`, report list/show/diff, HTML report generation, incident checklists, and PR-comment output.
- Added public-source enrichment plumbing, local enrichment cache, quarantine metadata, trust store commands, package-content audit, lockfile drift checks, and agent-sensitive surface reports.
- Expanded config, schema, skill, and docs around `.execfence/` layout, runtime trace, manifest policy, trust stores, report retention, and redaction settings.

## v1.0.0 - 2026-05-01

- Renamed the package and CLI to ExecFence (`execfence`) and moved project-owned config, signatures, baselines, and reports under `.execfence/`.
- Added automatic timestamped JSON evidence reports for scan, diff-scan, scan-history, and doctor commands, including local analysis and research queries.
- Added operational build/dev/test coverage analysis, evidence reports, doctor checks, baseline suppression, policy packs, workflow hardening, archive audits, expanded stack detection, and OpenSSF Scorecard workflow.
- Added explicit exit policy controls, changed-file scanning, full-IoC scanning, agent rule verification, and 1.0 taxonomy-facing output fields.

## v0.1.0 - 2026-05-01

- Initial reusable security guardrails CLI, Codex skill, and portable agent rules.
