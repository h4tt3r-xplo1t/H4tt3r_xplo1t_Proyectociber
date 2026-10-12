# seguimiento-revision-45

## Objective
Issue #47: close the non-blocking findings of the Gentle AI review of PR #46 (lineage `review-574db0b2d3b6c9a8`) and two documentation leftovers of #45. No user-facing behavior change except the bootstrap message for an uncertain destroy outcome.

## Scope
- Allowed: `services/gateway/**`; `scripts/openbao-dev-init.sh`; `docs/BITACORA.md` and `docs/bitacora/**`; `odd/tasks/administracion-gateway.md`; this file.
- Forbidden: `.claude/**`, `.github/**`, `docs/adr/**`, E5 manifests, real secrets.
- Out of scope: A3b2, risks L1, L2, I1, I2 of #45. If the seed guard needs a `.github/**` change, stop and ask.

## Acceptance criteria (issue #47)
1. Verification read failing after an applied delete gives a fixed message other than `DESTROY_FAILED` that does not promise the secret is intact; tested.
2. Any `BUSY_SQLSTATES` code while locking the user row in `mfa_confirm` gives 503; tested; a single helper translates busy errors.
3. `scripts/openbao-dev-init.sh` does not create `bootstrap-seed` unless a dev/CI environment is explicit; CI keeps working.
4. Real concurrency test deterministic, or explicitly accepts both valid outcomes; 10/10 local runs.
5. No tautological assertion in bootstrap tests.
6. `change_password` final recheck has a test; mutation check.
7. Readability/docs items 7-12 applied without weakening assertions.
8. TDD with observed RED for items 1-6; pytest and ruff green locally and in CI.

## TDD
Mode: strict, enabled (global user configuration). Runner: `uv run --locked pytest` in `services/gateway` against `gw45-test-pg` (127.0.0.1:55432, CI credentials) and the compose OpenBao (`DOCKER_CONTEXT=default`), CI values for `GATEWAY_JWT_*` and `GATEWAY_ALLOWED_ORIGIN`. Baseline on `main` (`8ab9ce6`): 621 passed.

## Delivery
Forecast ~400-600 authored changed lines (mostly tests). `single-pr`. Low-churn review: one docs commit at the end, revisor-seguridad, one Gentle AI review, no commits after approval.

## Route
- T1-T3: one delegated writer (writer trigger: several non-trivial files in `services/gateway` and `scripts/`).
- T4: inline docs, one commit.
- T5: `revisor-seguridad`, fix round if needed, Gentle AI review.

## Tasks
- [x] **T1** (`631c0c9`; RED: missing `EXIT_DESTROY_UNCERTAIN` and old DESTROY_FAILED text; race test deterministic with a barrier, 10/10, not RED-able) bootstrap: uncertain destroy outcome (R4, item 1) + module docstring; real race test determinism (item 4); tautological assert (item 5); stale test docstring (item 11).
- [x] **T2** (`707361d`; RED: 40P01/40001 gave 500; recheck tests passed first, mutation check proves them) gateway auth/admin: single busy-translation helper (item 2); `change_password` recheck test (item 6); comment fix (item 7); `_locked_usernames` (item 8); shared `FrozenClock` (item 9); placeholder case (item 10).
- [x] **T3** (`279a1b6`; guard `CI=true` or `OPENBAO_DEV_BOOTSTRAP_SEED=1`; no `.github` change; truth table only, end-to-end with a recreated volume NOT VERIFIED) `bootstrap-seed` only with an explicit dev/CI environment (item 3).
- [x] **T4** (this docs commit) docs: remove duplicated #37 entry from BITACORA, #45 review record in `odd/tasks/administracion-gateway.md`, #47 BITACORA entry. One docs commit.
- [ ] **T5** revisor-seguridad, Gentle AI review.
- [ ] **T6** push and PR (person request only).

## Progress
- 2026-10-12: issue #47 created by Claude at the person's request (the person's attempts #47/#48 were not found in the repo; GitHub assigned #47). Branch `fix/47-seguimiento-revision-45` from `8ab9ce6`.
- 2026-10-12: writer T1-T3 (3 commits), 626 passed; parent spot check 626 passed; ruff clean. Decisions: distinct exit code 5 for uncertain destroy; shared `busy_guard` (rollback only when a session is passed). Out of scope, added to Pendientes: login counter lock still translates only `LOCK_NOT_AVAILABLE`. T4 docs inline. Next: revisor-seguridad, Gentle AI.
