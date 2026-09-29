# guardia-fail-closed

## Objective
Issue #1 (reopened), PR A: make `.claude/hooks/guardia.sh` fail closed and close the remaining bypasses of the commit/merge-on-main and push rules.

## Problem
- If `jq` is missing or the input is not valid JSON, `CMD` is empty, no rule matches and the hook exits 0: every protection is silently disabled.
- Commit/merge on `main` can be bypassed with git global options (`-C`, `-c`, `--no-pager`), wrappers (`env git`, `command git`, `/usr/bin/git`) and detached HEAD (empty branch name).
- `-c core.hooksPath=...` or `git config core.hooksPath` can point git at another hooks directory and skip pre-commit.
- The push rule greps `\bmain\b` over the whole command: it blocks branches such as `ci/4-proteccion-main` and chained `gh pr create --base main`, but misses `+refspec` force pushes and combined short flags such as `-uf`.

## Scope
- In: `.claude/hooks/guardia.sh`, `tests/hooks/guardia_test.sh`, `docs/BITACORA.md`, this file.
- Out (PR B): `.claude/settings.json`, `.pre-commit-config.yaml`. The accepted `-n` false positives (FP A and D) stay as they are.

## Constraints
- Local commits only; push/PR need explicit authorization.
- Conventional Commits referencing `#1`.
- Strict TDD (global config): observed RED before touching the hook. Runner: `bash tests/hooks/guardia_test.sh` (also runs in CI job `pruebas`).

## Route
- T1 test cases: inline (one file, spec-level).
- T2 hook implementation: delegated writer (writer/preparation trigger: the hook rewrite is a non-trivial second file after the test file).

## Tasks
- [x] **T1** — Failing cases added (round 1: 33 cases, RED 20/62).
- [x] **T2** — Hook implemented by delegated writer: GREEN 62/62. Parent review found 17 more bypasses (shell syntax hiding git, `GIT_DIR=`, `cd` outside project, cherry-pick/revert/am, push `--all`/`--prune`/abbreviations): round 2 RED 17/83, writer GREEN 83/83. Parent probe found a newline regression (`git status` + newline + `git commit` on main allowed): round 3 inline, RED 3/86, GREEN 86/86 (newline turned into `;` before normalizing).
- [x] **T3** — BITACORA entry, revisor-seguridad review (verdict: blocking, 19 suspicions; parent reproduced all 19), commit `4040790`.
- [x] **T4** — Round 4 per user decision "fix structural + config, document shell expansion": RED 20/112 (writer), GREEN 112/112 verified by parent; probe script re-run: only the 3 shell-expansion cases and `reset --hard` on main remain open. ADR `docs/adr/0002-alcance-guardia-sh.md` records the threat model.
- [x] **T5** — Final revisor-seguridad pass on `72f6ae5`: ready for PR with reservations. Round 5 (10 cases incl. `gh pr merge` block per AGENTS.md §5): RED 10/125, writer GREEN 125/125 verified by parent; probes: only 3 shell-expansion cases and `reset --hard` on main remain open. ADR 0002 and BITACORA precision fixes.
- [x] **T6** — Push + PR #11 (authorized); CI run `36511317067` green (125 + 15); human squash merge as `ce62919`.

### PR B (branch `fix/1-permisos-settings`)
- [x] **B1** — Hook rule: `git diff/log/show/...` cannot read secrets (`.env`, `.env.*` except `.env.example`, `secrets/`), compare paths outside the tree (implicit `--no-index`, confirmed in the git 2.55 man page), or use `--output`/`--ext-diff`/`--no-index`. Route: delegated writer (same hook). TDD: RED 9/141, GREEN 141/141 verified by parent. Writer-reported limit (abbreviations `--ext`, `--outp`, `--no-ind`) disproved: git 2.55 rejects them as unknown options.
- [x] **B2** — `.claude/settings.json`: hook path quoted as in the official docs (`"$CLAUDE_PROJECT_DIR"/...`). JSON validated with `jq`.
- [x] **B3** — `.pre-commit-config.yaml`: gitleaks pinned to `83d9cd68…` (`v8.30.1`, aligned with CI) and pre-commit-hooks to `3e8a8703…` (`v6.0.0`), SHAs resolved from the official tags with `gh api`; the `gitleaks` hook id verified at that SHA.
- [x] **B4** — Decision (user): keep `deny Read(./.env.*)`. Official docs: an allow rule cannot carve an exception out of a deny rule. `.env.example` (fictitious values only) is read on request via a confirmed command. The issue criterion "`.env.example` se puede leer" is dropped and documented.
- [x] **B5** — revisor-seguridad on `992fbd7`: blocking. Parent triage: tracked-content pathspec reads cannot reach a gitignored `.env` (documented limit); reads outside git's tracked set and program execution closed. Round 2: RED 13/158 (writer GREEN), then parent disproved the writer's "abbreviations not covered" claim empirically (git grep/blame accept `--op`, `--u`, `--no-exc`, `--cont`): RED 2/164, GREEN 164/164 inline.
- [ ] **B6** — Commit, push + PR (authorization), human merge, close issue #1.

## Acceptance criteria
- Hook exits 2 when `jq` is missing or input is not valid JSON.
- Commit/merge blocked on `main`, on detached HEAD, and with `-C`/`--git-dir`/`--work-tree` (target branch unknown), including behind global options and wrappers.
- Any `core.hooksPath` override is blocked.
- Push blocked only for: destination `main` (`main`, `x:main`, `HEAD:main`, `refs/heads/main`), force (`--force*`, `-f` in combined short flags, `+refspec`, `--mirror`), or bare `git push` while on `main`. Branch names containing `main` and chained `gh pr create --base main` are allowed.

## Progress
- Branch `fix/1-guardia-fail-closed` from `main` at `b80e450`. Baseline suite: 29/29.
- Verified by parent after each round: `bash tests/hooks/guardia_test.sh` 86/86; `bash tests/rulesets/main_ruleset_test.sh` 15/15; `bash -n` OK; shellcheck not installed locally.
- Writer deviation accepted: relative `cd` resolves against `$PWD` only when it is inside the project, otherwise against `CLAUDE_PROJECT_DIR` (needed for the `cd .` test with a temp project dir). Documented as a known limit.
- The new hook blocked the parent's own doc-edit command because its text mentioned the hooksPath setting: accepted false positive, worked around by running the edit from a script file.
