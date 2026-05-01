# Changelog

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
