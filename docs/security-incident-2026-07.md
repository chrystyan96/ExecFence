# Repository source-integrity incident — July 2026

## Summary

ExecFence's Git history contained obfuscated JavaScript appended to executable entrypoints. The active source tree and every npm release artifact were verified clean, but the default branch reached a compromised intermediate commit.

The primary affected commit was `65fcbf54d9fec47858defccf0ea520d79e40f2e9`. It preserved the author date and message of the clean `v5.0.2` release commit while changing the committer date and adding compromised blobs to `bin/execfence.js` and `lib/cli.js`.

## Timeline

- 2026-05-20: an earlier injected CLI loader was removed in commit `92b7eaa95bcb24ea7393db09ffddd5099e7ee12e`.
- 2026-05-23: clean `v5.0.2` commit `534342cac3fe418283333d5a4c8b3d85df3c7ade` was created and published.
- 2026-06-01: altered sibling commits were recreated with preserved author metadata and new, unsigned committer metadata.
- 2026-07-01: GitHub recorded an authenticated push from the repository owner that changed `master` from `230c84e117da3df50743fd5d7cbae5b88dc24eda` to `65fcbf54d9fec47858defccf0ea520d79e40f2e9`.
- 2026-07-15: a second contaminated release branch was pushed.
- 2026-07-28: the executable source was sanitized before `v6.0.0` was published; permanent bootstrap checks were added.

Git and GitHub attribute the commits and pushes to the repository owner's configured identity. They do not record which local program created the rewritten commits, so the evidence cannot attribute the incident to Codex, a terminal, or another process.

## Impact

- The compromised commit was reachable from `master` between 2026-07-01 and 2026-07-28.
- A checkout of that branch could execute the appended loader when invoking the CLI.
- No npm version used any known compromised commit as its `gitHead`.
- The npm tarballs for `5.0.0`, `5.0.1`, `5.0.2`, and `6.0.0` have clean entrypoints and registry provenance.
- The current Codex binaries are store-installed/signed, and no matching executable source, Git hook, scheduled persistence, startup item, or unknown project Node process was found in the local audit.

The local audit cannot prove that the historical payload never ran. Credentials available on systems that executed an affected checkout should be rotated according to their exposure window.

## Remediation

- Remove compromised commits from all normal Git branch and tag reachability through a controlled history rewrite.
- Delete contaminated remote branches.
- Validate the current entrypoints and every entrypoint blob reachable from `HEAD`.
- Run source-integrity validation before executing repository JavaScript in CI and release workflows.
- Use a base-controlled `pull_request_target` workflow with read-only permissions and no persisted GitHub credentials.
- Block non-fast-forward updates to `master` and require the source-integrity status.

GitHub may retain unreachable objects and pull-request refs after branch history is rewritten. Permanent server-side purging of an object by SHA requires GitHub Support; history rewriting removes it from normal clones and refs but cannot promise immediate physical deletion from GitHub storage.
