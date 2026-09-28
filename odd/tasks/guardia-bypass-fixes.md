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

## Second review (2026-09-28)

A follow-up review found three more `guardia.sh` bypasses, verified directly (exit 0 = allowed) before any fix:
- A) `git commit -q -m t --no-verif` — git accepts unique abbreviations of long options, so `--no-verif`/`--no-veri`/etc. also skip hooks; the rule only matched the exact `--no-verify` string.
- B) `git switch -c main && git commit -m x` / `git checkout -B main && git commit -m x` — flags between the subcommand and `main` (`-c`, `-B`, `--create`) evaded the literal `git switch main`/`git checkout main` match.
- C) `git  switch  main && git commit -am x` (double space) / tab-separated variant — repeated whitespace broke the single-space literal match.
- D) `git commit -m y && git log -n 5` — accepted false positive (fail-closed), not a new bypass: the short `-n`-flag rule scans the whole command, not just the `commit` segment, so a trailing `git log -n 5` also triggers it.

- [x] **T5** — Fix bypasses A–C with regression tests; document D as an accepted false positive; route: delegated writer (writer trigger: 2 non-trivial files — `.claude/hooks/guardia.sh` and `tests/hooks/guardia_test.sh` — plus docs).
  - `tests/hooks/guardia_test.sh`: added 8 new block cases (A: 3, B: 3, C: 2), 4 new allow cases (`--verbose`, `--no-verbose`, `switch -c feat/main-page`, `checkout feat/x`), and 1 new documented-FP case (D). Kept all 16 existing cases unchanged. 29 cases total.
    Commit: `08eda53` — `test(hooks): cover abbreviated flag and create-main bypasses (#2)`
  - `.claude/hooks/guardia.sh`: (1) normalize `CMD` whitespace once after reading it (`tr -s '[:space:]' ' '`), fixing C generically; (2) replace the exact `--no-verify` match with a prefix-abbreviation regex `--no-ve?r?i?f?y?([^a-z-]|$)`, fixing A while still excluding `--no-verbose`; (3) replace the switch/checkout-main rule with a segment-scoped regex `git (switch|checkout)[^;&|]* main([ ;&|]|$)` combined with the existing commit/merge check, fixing B without matching `git switch -c feat/main-page`.
    Commit: `9815bd4` — `fix(hooks): block abbreviated no-verify and create-main compound commits (#2)`
  - RED (before fix): 8 of 29 cases failing (exactly the A/B/C cases). GREEN (after fix): 29/29 passing.
  - Side effect: fixing B's segment-scoped regex also resolves the previously pending "branch name containing main" false positive (`feature/main-page` no longer falsely blocked), since the regex requires a literal space before `main`, not `/` or `-`.
  - Documented in `docs/BITACORA.md` under "Segunda revisión" (2026-09-28 section) and here.
    Commit: docs commit (see below, same run as this task-file update).

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

### Second review evidence
- `bash tests/hooks/guardia_test.sh` — RED (before fix): 8 of 29 cases failing. GREEN (after fix): 29 of 29 cases passing.
- `pre-commit run --all-files` — see report for this run's exact result.
- `git log --oneline -4` — see report for exact hashes of this round's 3 commits.
- `git status --short` — see report; only this task's authorized files plus the pre-existing untracked `.atl/` directory expected.

## Next step
- Re-run `revisor-seguridad` against the updated diff before proposing the PR again.
- User to fix the PR #3 body (checklist) and push when ready — remote operations remain the user's explicit decision.
- Track remaining bypasses and hardening items under issue #1 (see `docs/BITACORA.md` pendientes list).

## Engram mirror
Mirrored to Engram topic `odd/guardia-bypass-fixes/tasks` (project-scoped). If the mirror write is unavailable, this local file is the source of truth; reconcile on next resume.
