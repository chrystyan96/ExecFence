# Changelog

## Unreleased

- Extended `execfence scan` to audit committed MCP/tool configs and agent instructions that try to bypass ExecFence or security scans.

## v5.0.0 - 2026-05-07

- Expanded ExecFence from npm-centric guardrails to JavaScript, Python, Rust, Go, JVM, .NET, PHP, and Ruby package-manager surfaces.
- Added the Windows/Linux sandbox helper contract with helper self-test proof, verified helper execution, deny-event reporting, and no silent enforce-to-audit downgrade.
- Added shared `covered` and `directGuarded` evidence across coverage, manifest, CI, and reports so release review can distinguish operational coverage from direct wrappers.
- Added stricter config validation, blocking summaries, multi-ecosystem fixtures, helper smoke evidence, and tag-sourced npm release gates.
- Documented that the npm package ships helper source for review/build, not a prebuilt trusted helper binary; enforce mode still requires a reviewed local helper registered with `sandbox install-helper --binary`.

## v4.0.1 - 2026-05-06

- Kept the release workflow compatible with branch protection by requiring version metadata to be updated in a PR before publishing, then publishing and tagging without pushing release metadata back to `master`.

## v4.0.0 - 2026-05-06

- Improved `execfence --help` and `execfence help` with grouped public command descriptions while keeping bare `execfence` as the default scan command.
- Changed `execfence guard global-enable` to install reversible npm/pnpm/yarn shims and marked shell-profile PATH blocks, so terminal and agent-run package-manager commands preflight through ExecFence before the real tool starts.
- Added `execfence guard global-disable` to remove global package-manager shims and PATH profile blocks while preserving evidence and project configuration.
- Added package-manager guard behavior that delegates install-like commands with lifecycle scripts disabled after a clean preflight scan.
- Added `execfence deps review` for npm/pnpm/yarn lockfile changes with guarded metadata checks, privacy-safe registry lookup, release cooldown blocking, deprecation/security messaging, local cache, and JSON/text output.
- Expanded `deps review` with package reputation feeds, OSV advisory checks, provenance/integrity policy gates, guarded tarball integrity/content auditing, and tarball delta comparison for changed packages.
- Added `supplyChain.mode: "strict"` to block unavailable metadata/reputation/tarball signals, missing integrity/provenance, release cooldowns, new package age windows, uncovered package-manager surfaces, and dependency runtime audits without helper enforcement.
- Added `execfence run --dependency-behavior-audit` to attach changed-dependency review and sandbox containment status to runtime evidence.
- Expanded global guard status with coverage-gap warnings for CI/containers, IDE-integrated package managers, version managers, wrappers, and current-shell PATH.
- Extended global guard shims to `pnpm`, `yarn`, `yarnpkg`, `bun`, and `bunx`; install-like commands now suppress lifecycle scripts across npm, pnpm, Yarn 1, Yarn 2+, and Bun.
- Strengthened sandbox helper metadata with explicit network, filesystem, sensitive-read, child-process, and new-executable enforcement capabilities.
- Added supply-chain metadata config/schema under `supplyChain.metadata` and wired guarded dependency metadata into `deps diff`, `ci`, and global install-like package-manager commands.
- Added supply-chain playbooks for dependency metadata blocks/warnings, safe lifecycle-script re-enable, and token-theft response.
- Expanded package lifecycle script detection to flag Windows LOLBins and script hosts such as `bitsadmin`, `Start-BitsTransfer`, `mshta`, `rundll32`, and `regsvr32`.

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

## v3.1.1 - 2026-05-05

- Merge pull request #6 from chrystyan96/codex/fix-trusted-publish-node24 (35f153b)
- Use Node 24 for trusted npm publishing (3b32134)
- Merge pull request #5 from chrystyan96/codex/fix-release-workflow (016ac89)
- Avoid incompatible npm latest in release workflow (f454df6)
- Merge pull request #4 from chrystyan96/codex/full-worktree-snapshot (4915e07)
- Keep generated ExecFence state out of git (7206b6d)
- Keep OMX runtime state out of git (e2a2325)
- Include full local worktree snapshot (6e43079)
- Merge pull request #3 from chrystyan96/codex/windows-lolbin-lifecycle-detection (81d2026)
- Catch Windows LOLBins in package lifecycle hooks (4007af3)
- Merge pull request #2 from chrystyan96/codex/guard-mode (db8aa97)
- Clarify npm package description (a85ffd1)
- Add automatic guard mode (34d5e75)
- Merge pull request #1 from chrystyan96/codex/document-openai-skills-pr (22f864c)
- Document OpenAI Skills submission (e25f87b)
- Use canonical repository metadata for npm (165d15e)
- Point npm package homepage at GitHub Pages (fa805c5)
- Make README a concise setup guide (e3f92e1)
- Tighten navigation and baseline guidance (d2ec170)
- Split detection details from the ExecFence article (7e3de74)
- Improve ExecFence article hierarchy and agent examples (b944b22)
- Clarify ExecFence CLI and skill installation paths (a14b0ba)
- Make ExecFence article more technical (a60dcb2)
- Add standalone ExecFence article (41d9cd5)
- Expand published ExecFence documentation (b8522c4)
- Publish ExecFence docs as a GitHub Pages entrypoint (b6368b4)
- Explain why ExecFence exists and how to use the skill (3c0418a)
- Block unsafe sandbox enforcement before local execution (a8c7690)
- Carry ExecFence through the V2.5 hardening line (a4ab73f)
- Make ExecFence enforce deep operational guardrails (1d69f48)
- Make ExecFence a runtime gate for development execution (c147c7b)
- Make ExecFence the operational guardrail surface (c06811a)
- Clarify guardrail configuration surfaces (cecfa1e)
- Promote guardrails to operational 1.0 (3300788)
- Harden releases and broaden guardrail coverage (db35758)
- Publish guardrails on existing Apache master (1342d71)
- Expand guardrails into CI, history, and agent workflows (cbd3e5d)
- Make guardrail instructions portable across agents (5e09f08)
- Keep Codex guardrails active after skill install (7c13724)
- Establish reusable guardrails before project builds (aef6992)
- Initial commit (790a5c8)
