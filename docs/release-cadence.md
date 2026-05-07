# Weekly Release Cadence

ExecFence ships on a weekly SemVer rhythm. The goal is to make one user-visible release every Friday afternoon, supported by two smaller planning checkpoints during the week.

## Weekly Rhythm

| Day | Time | Output |
| --- | --- | --- |
| Tuesday | 15:30 BRT | Plan one small PR focused on detection, examples, fixtures, rules, reports, or diagnostics. |
| Thursday | 15:30 BRT | Plan one small stabilization PR focused on docs, tests, CLI usability, compatibility, or release risk reduction. |
| Friday | 15:30 BRT | Prepare the weekly SemVer release checklist, changelog notes, verification evidence, and tag-ready release commit. |

The priority order for weekly work is:

1. Detection and guardrails.
2. Adoption and onboarding.
3. Platform, release, CI, and compatibility.

## Weekly Release Definition

A weekly release is relevant when it contains:

- at least one detection or protection improvement;
- at least one adoption, documentation, or onboarding improvement;
- regression coverage for the changed behavior;
- an updated changelog entry or release-note draft;
- passing release verification.

Public changes to CLI commands, config, schemas, reports, or documented behavior must update the matching user-facing docs and tests in the same PR.

Release review must compare `coverage`, `manifest`, and `ci` using the shared evidence fields. `covered` is the operational gate; `directGuarded` is release-review evidence that shows which entrypoints invoke ExecFence directly versus relying on a workflow gate, package prehook, inherited guard, or global shim.

## Documentation Policy

Every PR or update must explicitly review documentation impact. Public changes to CLI commands, config, schemas, reports, workflows, skills, agent rules, or documented behavior must update the matching docs in the same PR.

Before release, run `execfence config validate --strict` and review the latest report `blockingSummary`. Do not ship a command that says OK while another report shows an unexplained uncovered surface.

For v5 sandbox releases, also build and smoke-test the Go helper for Windows and Linux with `npm run helper:smoke`. Enforce mode is releasable only when every claimed helper capability is backed by self-test evidence; unsupported capabilities must appear in `sandbox doctor`, reports, and strict-mode blocks rather than being documented as protection.

`README.md` is the primary GitHub and npm entrypoint. Review it for every update, and update it whenever a change adds or changes a user-visible feature, command, workflow, positioning, or usage path. If `README.md` does not change, the PR or release checklist must state why: either the change has no public behavior impact, or the existing README already covers it.

Documentation priority:

1. `README.md`: high priority; keep it aligned with the full current user-facing functionality.
2. `docs/README.md` and GitHub Pages: medium priority; update during Friday release readiness, or immediately when a smaller update changes an important workflow, concept, or feature.
3. `docs/detection.md`: update when detection rules, signatures, taxonomy, severity, false-positive guidance, or the detection model changes.
4. `package.json` description and keywords: lower priority; review during Friday release readiness and update only when product positioning, category, or a central capability changes.
5. `CHANGELOG.md` or release-note draft: required for every weekly release.

## Branch And PR Policy

Every implemented update must finish on a dedicated branch and pull request. Do not finish user-visible work directly on `master`.

Use the `codex/` branch prefix for agent-created branches unless a task specifies another naming convention. The PR must include:

- user-visible summary;
- documentation impact;
- verification evidence;
- release impact and recommended SemVer level when applicable;
- known risks or explicit "none known".

Planning automations should not create branches or pull requests by themselves. They must include a suggested branch name, PR title, and PR body outline so the implementation step can finish with a branch and PR.

## Automation Runtime Profiles

Use these Codex automation profiles for the weekly planning cadence:

| Automation | Model | Reasoning effort |
| --- | --- | --- |
| `execfence-tuesday-detection-pr-plan` | `gpt-5.5` | `medium` |
| `execfence-thursday-stabilization-pr-plan` | `gpt-5.5` | `high` |
| `execfence-friday-weekly-release-readiness` | `gpt-5.5` | `xhigh` |

## Automation Priority Order

Automations must evaluate and rank work in this priority order before proposing a PR or release:

1. Security and release blockers: failing tests, failing scans, failing ExecFence CI, failing package audit, incorrect SemVer, missing required docs, missing changelog, or any risk of publishing an inconsistent release.
2. Detection and guardrails: new rules, signatures, fixtures, low-noise false-positive handling, clearer finding explanations, and protection for workflows, scripts, and agents.
3. User-visible impact: commands, workflows, CLI UX, messages, reports, config, schemas, skills, agent rules, or anything that changes how users understand or use the project.
4. README and required documentation: `README.md` review, detection docs when detection changes, GitHub Pages/docs for important workflow or concept changes, npm metadata when positioning or central capability changes.
5. Tests and evidence: expected tests, exact verification commands, and evidence needed to prove the update is ready.
6. Branch and PR: suggested `codex/...` branch, PR title, and PR body outline.
7. Release and SemVer: `patch`, `minor`, `major`, or "no release", with Friday consolidating changelog, release notes, blockers, and readiness.
8. Platform and maintenance: CI, compatibility, schemas, cleanup, documentation polish, and internal improvements, unless they are blockers above.

Automation output must order proposals and blockers by this priority. Friday release readiness must not mark a release ready if any blocker exists in priorities 1, 4, or 5.

## Checkpoints

Use the Tuesday checkpoint to pick the smallest detection-first PR that can be reviewed and verified quickly. Good candidates include a new suspicious fixture, a cleaner finding explanation, a low-noise signature, a report field improvement, or a guardrail coverage gap.

Use the Thursday checkpoint to reduce release risk. Good candidates include docs cleanup, command help alignment, fixture cleanup, CI hardening, schema examples, and compatibility fixes discovered during the week.

Use the Friday checkpoint to prepare the release without making unrelated feature changes. Review commits since the latest tag, choose `patch`, `minor`, or `major`, prepare changelog notes, and run the full verification command before creating the matching `vX.Y.Z` tag from `master`.

## Verification Commands

Small PRs:

```sh
npm run pr:check
```

Weekly release readiness:

```sh
npm run release:weekly-check
```

The weekly check expands to:

```sh
npm run check
npm run helper:smoke
node bin/execfence.js run -- npm test
node bin/execfence.js ci
node bin/execfence.js manifest
node bin/execfence.js pack-audit
npm pack --dry-run
```

Do not publish a release if tests fail, the helper smoke fails on Windows or Linux, the ExecFence CI bundle fails, package audit fails, or the changelog/release notes do not describe the user-visible changes.

The npm release workflow is tag-sourced. It starts only when a `v*` tag is pushed, verifies that the tag points at the current `origin/master` commit, verifies that the tag version matches `package.json`, checks that the same package version is not already present on npm, then publishes with provenance. Do not use manual workflow dispatch or a post-publish tag for npm releases.

## Automation Contract

Codex automations should plan PRs and release checklists only. They should not edit files, publish packages, tag releases, or dispatch workflows automatically.

Each automation output should include:

- proposed scope;
- suggested branch name, PR title, and PR body outline;
- likely files or subsystems;
- expected user impact;
- documentation impact for `README.md`, GitHub Pages/docs, npm metadata, and changelog/release notes;
- risk level;
- verification commands;
- justification for any documentation surface that does not need an update;
- whether the work likely requires `patch`, `minor`, or `major` if released.
