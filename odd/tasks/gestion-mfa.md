# gestion-mfa

## Objective
Issue #51: let each user manage their second factor safely (disable for readers, regenerate recovery codes) and rate-limit MFA enrollment (pending item of #39); fold in the 3 Gentle AI suggestions of #49.

## Scope
- Allowed: `services/gateway/**`; `docs/BITACORA.md`, `docs/bitacora/**`; `docs/threat-model.md`, `docs/architecture/threat-model.json`; `odd/tasks/**`.
- Forbidden: `.claude/**`, `.github/**`, `docs/adr/**`, real secrets.
- Out of scope: A3b2 (admin MFA reset), transit key rotation, per-IP rate limits (E5).

## Design decisions (from the issue, approved by the person)
- `/mfa/enroll` per-user limit stored in the database (5 per rolling hour); the 6th answers 429 before any transit call. Exact storage (columns on `users` or a table) chosen by the writer, with a migration.
- `POST /api/auth/mfa/disable`: readers only (privileged roles 403, ADR 0004); current password plus a TOTP or a recovery code; clears secret, pending secret and recovery codes; `invalidate_tokens` and closes the other sessions; failures count in the progressive lockout.
- `POST /api/auth/mfa/recovery-codes`: current password plus a TOTP; replaces the 10 codes (old ones invalid), shows the new ones once; failures count in the lockout.
- Same patterns as the existing MFA routes: sid-bound CSRF, slow work (transit, Argon2) outside row locks with a final compare-and-set under the counter lock then the user row lock, fixed security events, `NO_STORE`.

## Acceptance criteria (issue #51)
1. 6th enrollment within an hour: 429, no transit call.
2. Disable without a valid second factor fails and counts in the lockout; privileged role: 403.
3. After regeneration, old codes fail and new ones are single-use.
4. The CSRF guard test covers the new routes.
5. Observed RED per behavior change; pytest and ruff green locally and in CI; revisor-seguridad with no critical or high; threat model updated.

## TDD
Mode: strict, enabled (global user configuration). Runner: `uv run --locked pytest` in `services/gateway` against `gw45-test-pg` (127.0.0.1:55432, CI credentials) and the compose OpenBao (`DOCKER_CONTEXT=default`), CI values for `GATEWAY_JWT_*` and `GATEWAY_ALLOWED_ORIGIN`. Baseline on `main` (`8388f2f`): 673 passed.

## Delivery
Forecast ~700-1000 authored changed lines (mostly tests). `single-pr` (precedent #45, #49). Low-churn review: revisor-seguridad, one fix round, docs commit, one Gentle AI review, no commits after approval.

## Route
- T1-T4: one delegated writer (writer trigger: several non-trivial files in `services/gateway`), one commit per task.
- T5: delegated docs writer (threat model md + json + BITACORA), one commit.
- T6: revisor-seguridad, fix round, Gentle AI.

## Tasks
- [x] **T0** (`f49c1e2`): commit the #49 review record (issue item 6).
- [x] **T1** (`42d127f`) #49 suggestions: refresh with generation > 0 test; busy error on the login user-row lock test (503, nothing counted, counter lock released); CSRF guard control comment.
- [x] **T2** (`3d4bf67`) `/mfa/enroll` per-user rate limit (migration 0007, table `mfa_enrollment_attempts`).
- [x] **T3** (`9d68f37`) `POST /api/auth/mfa/disable`.
- [x] **T4** (`6ca5041`) `POST /api/auth/mfa/recovery-codes`; CSRF guard cases for the new routes.
- [x] **T5** (docs commit that also adds this file) docs: BITACORA entry and Pendientes (#39 item), threat model. One commit.
- [x] **T6** revisor-seguridad (done), fix round (`8dba8dd`), Gentle AI review (approved and acknowledged, lineage `review-74f173ba4273a70e`).
- [x] **T7** push and PR #55 (2026-10-15, person request via approved plan); CI run 38781024086 green, 763 passed.

## Progress
- 2026-10-12: issue #51 created by Claude at the person's request; branch `feat/51-gestion-mfa` from `8388f2f`; T0 committed.
- 2026-10-12: T1 done (`42d127f`), route delegated (writer trigger). Characterization tests, passed on first run (no behavior change, no RED expected): refresh with gen 7, login user-row busy error x3 sqlstates (503, nothing counted, counter lock released), CSRF guard control comment. Writer: pytest 677 passed, ruff check and format green; parent spot check: ruff check and format green. RDD: review deferred to T6 (single Gentle AI review per delivery plan).
- 2026-10-12: T2 done (`3d4bf67`), route delegated (writer trigger). RED observed (9 failed: missing `ENROLL_LIMIT`, `UndefinedTable`; maintenance import error), then GREEN: pytest 687 passed, ruff check and format green, hooks green. Design: `_reserve_enrollment` counts and inserts under the user row lock (after the counter lock on the full-session path), commits before transit; 429 `mfa_enroll_rate_limited`; purge removes rows older than the window. Parent spot check: diff read. Residual for T6: no concurrency test of the parallel-enrollment race (mechanism: user row lock); periodic purge still depends on the E5 CronJob.
- 2026-10-12: T3 done (`9d68f37`), route delegated (writer trigger). RED observed (35 failed: route 404 and the CSRF guard coverage test), then GREEN: pytest 721 passed, ruff check and format green, hooks green. Design: `disable_mfa_actor` (full session only), `_check_can_disable_mfa` (403 privileged, 409 without MFA, not counted) before and under the locks, password and factor verified without locks, under the locks `token_generation` recheck (401), password-hash compare and `_consume_second_factor`; failures counted (`mfa_failure`). Success clears the MFA columns and recovery codes, ends every session and reopens the current one. Helpers `_end_every_session` and `_open_session` extracted and reused by `change_password` (same behavior, suite green). CSRF guard case added. Residual for T6: a logout between authentication and the lock is not rechecked (ms window); no lock-probe test for the slow work.
- 2026-10-12: T4 done (`6ca5041`), route delegated (writer trigger). RED observed (36 failed: route 404 and the CSRF guard coverage test), then GREEN: pytest 756 passed, ruff check and format green, hooks green. Design: `RecoveryCodesRequest` accepts only a 6-digit TOTP (a recovery code is a 422 by schema, not counted, so a leaked code cannot mint a new list); reuses `disable_mfa_actor` (any role with MFA), slow work (decrypt, Argon2 of the 10 codes) outside the locks, generation and password-hash rechecks plus TOTP compare-and-set under the locks; replaces every code in one commit; sessions are not ended (`relogin_required=False`); event `recovery_codes_regenerated`. `_require_mfa_enabled` extracted. Residual for T6: same as T3; the 422 is distinguishable (input shape only); a small helper duplication between the two new test files.
- 2026-10-12: T6 revisor-seguridad (read-only, tests not run by it): ready for PR, no critical, high or medium. L1 a logout between authentication and the lock is not rechecked and `/mfa/disable` would mint a new session: fix. L2 a replayed TOTP step costs 10 Argon2 hashes before rejection in `/mfa/recovery-codes`: fix. L3 the 10 hashes take one semaphore slot each (up to 10 x 5 s of thread time): accepted, E5 pending (same class as L6 of #33). L4 a stolen cookie can lock the login through the new routes: accepted (ADR 0004, until the E5 IP limit). Info: authorization and TOCTOU sound; the enroll race is closed by the row lock; migration 0007 safe; quota consumed even if transit fails (fail-conservative). Fix round for L1 and L2 delegated.
- 2026-10-12: T6 fix round done (`8dba8dd`), delegated. L1 and L2 confirmed in code. `_session_still_valid` (generation, denied jti, revoked family; uncounted 401) under the locks in `/mfa/disable` and `/mfa/recovery-codes`; replayed TOTP step rejected in `_prepare_second_factor` before any hashing (under-lock check kept). RED observed (7 failed: 6 logout cases 200 != 401, replay test saw hash calls), then GREEN: pytest 763 passed, ruff green, hooks green. Next: T5 docs, then Gentle AI review.
- 2026-10-12: T5 done, delegated docs writer, parent structural readback (diff read, JSON valid, BITACORA 18.7 kB under the 20 kB rule) and one wording fix (L4 is covered by the existing targeted-lockout pending item). BITACORA entry #51, #39 item closed, E5 items (L3, enroll race test), purge item extended; threat model: 44 and 35 updated, new threat 48 (48 total). Next: Gentle AI review over the branch; no commits after approval.
- 2026-10-12: T6 Gentle AI review over `main...1c36ca5` (high risk, consent granted by the person, 4 lenses): approved, acknowledged (authority burned). First capture attempt failed before any mutation (zsh lacks `mapfile`, empty arguments); the bound STATUS re-offered the same 4 slots and the relaunch with bash succeeded. Non-blocking advisory findings (later work, not this candidate): R2-001 rename `disable_mfa_actor` to a neutral name (it also guards `/mfa/recovery-codes` for every role); R2-002 extract the duplicated lock/recheck/consume block of `mfa_disable` and `mfa_recovery_codes`; R2-003 the comment near `_reserve_enrollment` names the counter lock but the race is closed by the user row lock; R2-004 move duplicated test helpers to `tests/helpers.py`; R3 no busy-error test for the enroll reservation lock (and no parallel enrollment test). This record stays uncommitted (no commits after approval); commit it as T0 of the next issue. Next: T7 push and PR only on the person's request.
- 2026-10-15: T7 done. Pushed `feat/51-gestion-mfa` (`1c36ca5`) and opened PR #55 against main (Closes #51). CI run 38781024086 green: gateway 763 passed (migration 0007), pruebas, secretos, workflows. PR body without AI attribution; the AI-use checkbox is left for the person. Next: human review and squash merge; then Dependabot PRs #52-#54.
