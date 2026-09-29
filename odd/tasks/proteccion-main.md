# proteccion-main

## Objective
Issue #4: protect `main` on GitHub's side and add a stack-agnostic security CI, so controls apply even when working from Claude Code web/mobile, where `guardia.sh` and pre-commit do not run.

## Scope
- Phase 1 (this branch `ci/4-proteccion-main`): `.github/workflows/seguridad.yml` (jobs `secretos`, `workflows`, `pruebas`), `.github/dependabot.yml`, ADR `docs/adr/0001-proteccion-rama-main.md`, BITACORA entry.
- Phase 2 (after Phase 1 merge, separate branch/PR): `.github/rulesets/main.json`, applied by `PUT` over the existing ruleset `protege` (id 24097824), and disabling merge-commit/rebase merges. Remote operations only with explicit user authorization.
- Out of scope: CodeQL, dependency review, native secret scanning, stack-specific checks.

## Constraints
- Mode: IMPLEMENTACIÓN LOCAL. Local commits only; push/PR/ruleset changes need explicit authorization.
- Conventional Commits referencing `#4`, no AI attribution lines.
- `permissions: contents: read` globally, third-party actions pinned by commit SHA with version comment, no `pull_request_target`, `timeout-minutes` on every job.

## Verified dependencies (2026-09-28, official GitHub releases)
| Component | Version | Pin | License |
|---|---|---|---|
| actions/checkout | v7.0.1 | `3d3c42e5aac5ba805825da76410c181273ba90b1` | MIT |
| gitleaks (binary) | v8.30.1 | sha256 `551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb` (`gitleaks_8.30.1_linux_x64.tar.gz`) | MIT |
| actionlint (binary) | v1.7.12 | sha256 `8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8` (`actionlint_1.7.12_linux_amd64.tar.gz`) | MIT |

Decision: use the official gitleaks and actionlint release binaries with pinned sha256 instead of `gitleaks/gitleaks-action` (v3.0.0, custom non-SPDX license, needs `GITHUB_TOKEN`). This means fewer third-party actions, no extra token permissions, and the same tool version as local.

## TDD / checks
- Strict TDD configured globally, but there is no unit-test runner for CI YAML. Honest checks instead: `actionlint` (v1.7.12, local binary) on the workflow; `gitleaks git` baseline on the full history; the first CI run on the PR.
- Baseline observed: `gitleaks git --redact .` → 11 commits, no leaks found (exit 0).

## Route
Delegated writer (writer trigger: 2+ non-trivial files, workflow + ADR).

## Tasks
- [x] **T1** — `.github/workflows/seguridad.yml` (`9fb5766`) + `.github/dependabot.yml` (`bd6e25a`), validated with actionlint.
- [x] **T2** — ADR `docs/adr/0001-proteccion-rama-main.md` (`9438209`).
- [x] **T3** — BITACORA entry (issue #4, `protege` finding, PR #3 cleanup done, issue #1 closed-vs-pending discrepancy).
- [x] **T4** — Phase 2 on branch `ci/4-ruleset-como-codigo` (name avoids the guardia `-main` push false positive).
  - [x] **T4a** — `.github/rulesets/main.json` + `tests/rulesets/main_ruleset_test.sh` + ADR "Aplicación (Fase 2)". Route: inline (1 JSON + 1 test, already-understood). TDD: RED (file missing; live `protege` 10/15 failing) → GREEN 15/15.
  - [x] **T4b** — push + PR #6 (authorized); CI run `36501247990` green; human squash merge as `b8ff3af`.
  - [x] **T4c** — `gh api -X PUT .../rulesets/24097824 --input .github/rulesets/main.json` (authorized). Drift check against an independent GET: 15/15. Effective rules on `main`: deletion, non_fast_forward, required_linear_history, pull_request, required_status_checks.
  - [x] **T4d** — `PATCH` repo (authorized): `allow_merge_commit=false`, `allow_rebase_merge=false`, `allow_squash_merge=true`, confirmed by GET.
  - [x] **T4e** — verification (authorized): direct push rejected (GH013); PR #7 squash before checks rejected; merge commit and rebase rejected with checks green; PR #7 closed unmerged. Force-push rule only verified indirectly (see Progress).
- [ ] **T5** — open an issue for M2: make the `pruebas` job run `tests/hooks/guardia_test.sh` and `tests/rulesets/main_ruleset_test.sh`.

## Progress
- Issue #4 created (authorized). Branch `ci/4-proteccion-main` from `main` at `0fad25e`. Guardia suite on main: 29/29.
- T1 commits: `9fb5766` (`ci: add security workflow with gitleaks and actionlint (#4)`), `bd6e25a` (`ci: add dependabot for github actions (#4)`).
  - `actionlint -color` (v1.7.12, local binary) on `.github/workflows/seguridad.yml`: exit 0, no findings, after fixing two YAML quoting issues (an unquoted `"$RUNNER_TEMP/..."` scalar with trailing tokens, and an unquoted `run:` string containing a `:`).
  - `python3 -c "import yaml..."` over both YAML files: parsed without error.
- T2 commit: `9438209` (`docs(adr): record main branch protection decision (#4)`).
- T3 commit: pending in this same task run (`docs: log issue 4 phase 1 in bitacora (#4)`), covering `docs/BITACORA.md` and this file.
- PR #5 opened (push run by the user because guardia.sh false-positive on `-main` in the branch name; `gh` token needed the `workflow` scope).
- First CI run red: YAML treated ` #4)"` as a comment in the `pruebas` echo. Fixed in `c639e94` (`run: |`). CI run `36480098678`: `secretos`, `workflows`, `pruebas` all pass.
- revisor-seguridad review of `main...HEAD`: ready for push, no critical/high/medium findings. B3 fixed (`cancel-in-progress` only on pull requests, so pushes to `main` always finish their secrets scan). B1 (drop `gh` `workflow` scope after push), B2 (`integration_id` for required checks, Phase 2) and I1 (compare sha256 pins with official `checksums.txt`) tracked in BITACORA. B1 done (scope removed after push of `4fd87eb`, CI run `36496048552` green). I1 verified: gitleaks, actionlint and checkout pins match official checksums/tag.
- PR #5 squash-merged as `a85401a`; branch deleted local+remote.
- Phase 2 facts: live `protege` still has Admin + 3 integrations bypass `always`, and `creation`/`update`/`required_signatures`/code_* rules. Repo allows merge commit, squash and rebase. GitHub Actions app id 15368 (check runs on `a85401a`). Schema verified against GitHub REST OpenAPI (pull_request.allowed_merge_methods, required_status_checks[].integration_id).
- T4b-T4e done on 2026-09-28 local time, UTC-5 (see Tasks). Force-push check: the `--force` push of a commit on top of `main` was rejected by the pull-request rule, so `non_fast_forward` was not exercised in isolation. A real non-fast-forward attempt was skipped on purpose: if protection failed it would rewrite `main`. The rule is confirmed active via the ruleset API and `rules/branches/main`.
- Next: T5 (M2 issue), then close issue #4.
