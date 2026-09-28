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
- [ ] **T4** — (Phase 2, later) ruleset as code + PUT + repo merge settings + 4 verification scenarios.

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
- Next: human review and squash merge of PR #5, then T4 (Phase 2) on a new branch.
