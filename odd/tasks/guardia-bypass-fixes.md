# guardia-bypass-fixes

## Objective
Fix the two critical guardia.sh bypasses found in the PR #3 security review (issue #2), with regression tests, before the PR can be re-reviewed and merged.

## Problem / Why
`revisor-seguridad` found that `.claude/hooks/guardia.sh` (the PreToolUse guard that enforces "no `--no-verify`", "no commits on `main`", "no push to `main`/`--force`") could be bypassed:
1. `git commit -n -m x` — `-n` is the short form of `--no-verify`; the hook only matched the literal `--no-verify` string.
2. `git switch main && git commit -am x` — the hook reads the current branch *before* the compound command runs, so a commit that switches to `main` mid-command slips through.

## Scope
- In scope: the two bypasses above, a regression test suite, a defense-in-depth `pre-commit` hook (`no-commit-to-branch`), and documenting the fixes.
- Out of scope (moved to issue #1): `git push -uf`, `git -C <path>`/absolute-path git invocations, `-c core.hooksPath=...`, false positive on branch names containing "main", CODEOWNERS, SHA pinning of pre-commit hooks, broken images in `docs/PROJECT_CONTEXT.md`.
- Out of scope for this agent: fixing the PR #3 body / pushing (remote operations, user's decision).

## Constraints
- Mode: IMPLEMENTACIÓN LOCAL, branch `chore/2-configuracion-inicial`. Local commits only, no push.
- Conventional Commits, no AI attribution lines.
- Strict TDD: observed RED before modifying `guardia.sh`, then GREEN.
- No new dependency without verifying source, license, maintenance status first (AGENTS.md §3).

## TDD
- Mode: STRICT (source: user global config, "Strict TDD Mode: enabled").
- Runner: `bash tests/hooks/guardia_test.sh`.
- RED observed before T2: 7/16 cases failing (the 6 new bypass cases + the documented false-positive case, which is expected to start failing/blocking only after the fix).
- GREEN observed after T3: 16/16 cases passing.

## Route
Delegated writer (writer trigger: 2+ non-trivial files — `.claude/hooks/guardia.sh` and `.pre-commit-config.yaml`, plus new test file and docs). Single bounded writer per the approved plan `/home/h4tt3r_xplo1t/.claude/plans/pr-3-zazzy-zebra.md`.

## Tasks

- [x] **T1** — Add `tests/hooks/guardia_test.sh`: 16-case regression suite (10 block cases, 5 allow cases, 1 documented accepted false positive). Confirmed RED (7 failing) before touching `guardia.sh`.
  Commit: `ee76611` — `test(hooks): add guardia.sh bypass regression suite (#2)`
- [x] **T2** — `.claude/hooks/guardia.sh`: block any `git commit` command containing a short-flag token with `n` (regex `-[a-zA-Z]*n[a-zA-Z]*`), covering `-n`, `-nm`, `-an`, etc. Accepted false positive: `-n` inside a quoted commit message also blocks (fail-closed).
  Commit: `742b7a1` — `fix(hooks): block short n-flag on git commit (#2)`
  (Commit message avoids the literal `-n` token to not self-trigger the new guard rule.)
- [x] **T3** — `.claude/hooks/guardia.sh`: block any command containing `git switch main`/`git checkout main` together with `git commit`/`git merge`, regardless of the branch read at evaluation time. Added `no-commit-to-branch` (`--branch main`) from `pre-commit/pre-commit-hooks` `v6.0.0` to `.pre-commit-config.yaml` as defense in depth (verified: MIT license, not archived, v6.0.0 published 2025-08-09, hook id exists).
  Commit: `32465ff` — `fix(hooks): block commits to main via compound commands (#2)`
- [x] **T4** — Documented the fixes in `docs/BITACORA.md` (dated section, Spanish, neutral tone) and this task file.
  Commit: pending in this same task (docs commit below).

## Acceptance criteria
- `bash tests/hooks/guardia_test.sh` passes 16/16 after the fix, failed 7/16 before it.
- `pre-commit run --all-files` passes (`gitleaks`, `no-commit-to-branch`).
- No file outside the authorized set touched: `.claude/hooks/guardia.sh`, `tests/hooks/guardia_test.sh`, `.pre-commit-config.yaml`, `docs/BITACORA.md`, `odd/tasks/guardia-bypass-fixes.md`.
- No push, no branch switch away from `chore/2-configuracion-inicial`.

## Verification evidence
- `bash tests/hooks/guardia_test.sh` — RED (before T2/T3): 7 of 16 cases failing (the two bypasses plus the FP case). GREEN (after T3): 16 of 16 cases passing.
- `pre-commit run --all-files` — `Detect hardcoded secrets`: Passed. `don't commit to branch`: Passed.
- `git log --oneline main..HEAD` — shows the 3 fix/test commits ahead of `main` (plus prior branch history); see report for exact hashes.
- `git status` — clean except this task's own files and the pre-existing untracked `.atl/` directory (not part of this PR's scope).

## Next step
- Re-run `revisor-seguridad` against the updated diff before proposing the PR again.
- User to fix the PR #3 body (checklist) and push when ready — remote operations remain the user's explicit decision.
- Track remaining bypasses and hardening items under issue #1 (see `docs/BITACORA.md` pendientes list).

## Engram mirror
Mirrored to Engram topic `odd/guardia-bypass-fixes/tasks` (project-scoped). If the mirror write is unavailable, this local file is the source of truth; reconcile on next resume.
