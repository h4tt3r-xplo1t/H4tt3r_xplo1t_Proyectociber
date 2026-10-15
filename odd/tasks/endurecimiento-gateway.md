# endurecimiento-gateway

## Objective
Issue #49: close the gateway pending items that do not depend on E5 or other services: login lock hardening, exact token invalidation, readiness, CSRF coverage proof, I2 decision and the advisory findings of the #47 Gentle AI review.

## Scope
- Allowed: `services/gateway/**`; `docs/BITACORA.md`, `docs/bitacora/**`; `docs/threat-model.md` and `docs/architecture/threat-model.json` (only if a threat's controls change); `odd/tasks/**`.
- Forbidden: `.claude/**`, `.github/**`, `docs/adr/**`, real secrets.
- Out of scope: rate limits, Ingress, body size (E5); A3b2; MFA management.

## Design decisions
- **L2 (person, 2026-10-12): generation counter.** New `users.token_generation` (int, not null, default 0) and a required `gen` claim in every JWT (access and scoped). A token is valid only if `gen` equals the current value. Every place that bumps `tokens_valid_since` also increments the generation in the same transaction; tokens issued after the bump (reissue, login after confirm) read the new value. `tokens_valid_since` stays for the refresh family check. Existing tokens without `gen` are rejected once (one relogin). The test that pins same-second survival (`test_logout.py:290`) is inverted on purpose: that behavior is the defect.
- **Login short transaction (Claude, from the map):** unlocked pre-check of `locked_until`; verify the password with no row lock; then `_lock_attempt`, reload the user, recheck `locked_until` and that `password_hash` did not change; only then count the failure or reset. Concurrent guesses are all counted under the lock; in-flight guesses that pass the pre-check before the lockout are bounded by the Argon2 semaphore (4). Recorded as accepted.
- **`_lock_attempt` uses `busy_guard`** (40P01 and 40001 give 503, not 500).
- **CSRF (#35):** the map shows every post-login state-changing route already checks the sid-bound CSRF (refresh and logout inline, the rest through dependencies). Deliverable: a guard test that enumerates the app routes and fails if a state-changing post-login route accepts a request without a valid CSRF. No refactor.
- **I2 (Claude, low consequence):** keep the advisory lock. The only other way to create an administrator (`assign_role`) requires an existing administrator, so the advisory lock already serializes the only race (two bootstraps). A marker table would change the semantics ("bootstrap ran once" instead of "no administrator exists"). Documented in BITACORA.
- **CI check of `bootstrap-seed`: dropped.** The `seed_files` fixture fails (not skips) when the files are missing, and the real tests passed in the PR #48 CI, so a workflow step would duplicate it. No `.github` change.

## Acceptance criteria (issue #49)
1. Observed RED for each behavior change; tests that pass unchanged carry a mutation check.
2. No existing test weakened (the inverted L2 test is a deliberate behavior change).
3. Login does not hold the counter row lock during the hash; a test proves it (probe `FOR UPDATE NOWAIT` from another connection during the hash).
4. A token issued in the same second as a `tokens_valid_since` change is rejected.
5. Every post-login state-changing route rejects a request without a valid sid-bound CSRF (guard test).
6. `readyz` answers 503 when the database is unavailable.
7. pytest and ruff green locally and in CI; revisor-seguridad with no critical or high.

## TDD
Mode: strict, enabled (global user configuration). Runner: `uv run --locked pytest` in `services/gateway` against `gw45-test-pg` (127.0.0.1:55432, CI credentials) and the compose OpenBao (`DOCKER_CONTEXT=default`), CI values for `GATEWAY_JWT_*` and `GATEWAY_ALLOWED_ORIGIN`. Baseline on `main` (`dd6c3f7`): 631 passed.

## Delivery
Forecast ~900-1300 authored changed lines (about half tests). `single-pr`, following the #39 and #45 precedent. Low-churn review: docs commit at the end, revisor-seguridad, one fix round, one Gentle AI review, no commits after approval.

## Route
- T1-T5: one delegated writer (writer trigger: several non-trivial files in `services/gateway`), task by task, one commit each.
- T6: inline docs, one commit.
- T7: revisor-seguridad, fix round, Gentle AI.

## Tasks
- [x] **T0** (`6ee40f4`): commit the #47 review record (issue item 8).
- [x] **T1** (`86fce06`; tests/refactor over correct code, not RED-able; loops real 10/10, fake 30/30; helpers in `tests/helpers.py`; `DestroyError` base; `end_sessions` passes the session) #47 advisory: read barrier in the fake race test; shared test helpers out of `test_mfa.py`; `DestroyUncertain`/`DestroyFailed` as siblings; constant-compare assert and 5xx-vs-timeout comment; transport-error case for the verification read and `logged_out` in the parametrized test; barrier failure mode in the real test; `busy_guard` docstring vs `end_sessions`.
- [x] **T2** (`965554e`; RED: 40P01/40001 gave 500; NOWAIT probes during verify_password and verify_dummy; hash-changed returned 200; mutation checks; hash changed or user gone during the hash = counted failure 401; locked during the hash = 401 not counted; one concurrency test moved its pause to `_start_session`) login: `busy_guard` in `_lock_attempt`; short transaction separate from the hash.
- [x] **T3** (`d3c6e67`; RED: 9 tests; `invalidate_tokens` at mfa_confirm, change_password, assign_role, end_sessions; refresh does not compare generation (residual: same-second family before an assign_role bump survives a refresh, harmless because role is read from the DB); `test_two_administrators_cannot_remove_each_other` also accepts 401 for the loser) token generation counter (migration `0006`, `gen` claim, every bump site, reissue and login).
- [x] **T4** (`4608d0b`; RED: 6 tests; 503 fixed body and log) `GET /readyz` with a database check.
- [x] **T5** (`78f362b`; passed first, mutation checks on every route; enumerates OpenAPI paths, misses `include_in_schema=False`) CSRF guard test over every post-login state-changing route.
- [x] **T6** (this docs commit) docs: BITACORA entry (L2 decision, I2 decision, CI seed check dropped, accepted parallel guesses), Pendientes, threat model if controls change. One docs commit.
- [x] **T7** revisor-seguridad, fix round, Gentle AI review. revisor-seguridad: ready, 0 critical/high/medium; L1 fixed in `8fc2eb7` (RED probe, mutation check); L2 to E5 Pendientes; L3 accepted. Gentle AI: high risk, consent granted by the person, 4 lenses approved, acknowledged (`review-ca8a02d675d18253`); 3 advisory suggestions.
- [ ] **T8** push and PR (person request only).

## Progress
- 2026-10-12: issue #49 created by Claude at the person's request; branch `chore/49-endurecimiento-gateway` from `dd6c3f7`; T0 committed. Map delegated (read-only). Person chose the generation counter for L2.
- 2026-10-12: writer T1-T5 (5 commits), 672 passed; parent spot check 672 passed; ruff clean. revisor-seguridad next, then fix round, T6 docs, Gentle AI.
- 2026-10-12: revisor-seguridad fix round (`8fc2eb7`) and T6 docs; 673 passed; parent spot check 673.
- 2026-10-12: Gentle AI approved and acknowledged. Advisory follow-ups: refresh issuing with generation > 0 not covered by a test; busy error on the login user-row lock (503, nothing counted) not covered; comment on the CSRF guard control request. Next: T8 push/PR on request.
