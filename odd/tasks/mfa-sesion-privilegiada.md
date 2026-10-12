# mfa-sesion-privilegiada

## Objective
Issue #43 (E3, closure of A3a, ADR 0004 decision 4): no full session of a privileged role (editor, auditor, administrador) works without MFA, including sessions that already exist. Also close the #39 review findings that could not be fixed in PR #42.

## Why
#39 (PR #42, `28f63e8`) enforces MFA only at password login. `current_user` and `POST /api/auth/refresh` do not check `mfa_enabled_at`, so a session opened before the deploy, or a lector promoted to editor, keeps working and is renewed up to the 8 h limit without a second factor (Gentle AI R1/R3 on `review-bf87463d9b279c73` and `review-62cff8bff0bcf3d3`).

## Scope
- Allowed: `services/gateway/**`; `docs/adr/0006-cifrado-secreto-totp.md`; `docs/threat-model.md` and `docs/architecture/threat-model.json` (threats 1, 43, 44); `docs/BITACORA.md` and `docs/bitacora/**`; `odd/tasks/mfa-gateway.md`; this file.
- Forbidden: `.claude/**`, `.github/**`, `scripts/**`, `deploy/**`, other ADRs, real secrets.
- Out of scope: lockout on deploy of existing privileged users without MFA (A3b, pending role assignment), assisted recovery, first admin, break-glass, password change, MFA disable/regenerate, `/mfa/enroll` rate limit, `rewrap`, frontend.

## Design decisions
- Reject in both `current_user` and `refresh` (person reviewed this choice when the issue was drafted): the session dies on the next request instead of living until the access JWT expires; `current_user` already loads the user, so the cost is negligible.
- `refresh` for a privileged user without MFA: generic 401 and revoke the family. `current_user`: generic 401 (the family is revoked by the next refresh or logout).
- Row lock: transit and the recovery Argon2 loop run outside `SELECT ... FOR UPDATE`; single use of the TOTP step and of each recovery code is kept by a recheck under the lock (compare-and-set), proven by concurrency tests.

## Verified versions
No new dependency.

## TDD
Mode: strict, enabled (global user configuration). Runner: `uv run --locked pytest` in `services/gateway` against a throwaway PostgreSQL container (`gw43-test-pg`, 127.0.0.1:55432, test-only credentials) and the compose OpenBao (`DOCKER_CONTEXT=default`, `scripts/openbao-dev-init.sh`), with the CI values for `GATEWAY_JWT_*` and `GATEWAY_ALLOWED_ORIGIN`. Baseline on `main` (`28f63e8`): 462 passed.

## Delivery
Forecast ~600 authored changed lines (about half tests). `single-pr`. Low-churn review workflow (feedback/rdd-stop-hook-churn): one docs commit at the end, one combined fix round, one Gentle AI review, no commits after approval.

## Route
- T1-T3: one delegated writer (writer trigger: 2+ non-trivial files in `services/gateway`; preparation trigger).
- T4: inline docs, one commit.
- T5: `revisor-seguridad`, one fix round, one Gentle AI review.

## Tasks
- [x] **T1** (`274995a`): privileged session without MFA: `current_user` and `refresh` reject it (401; refresh revokes the family). RED: 8 of 12 new tests in `test_privileged_session_mfa.py` (200 instead of 401); GREEN: 474 passed. Seven existing tests that promote a user now also set `mfa_enabled_at` (no assertion weakened).
- [x] **T2** (`415369f`): transit and recovery Argon2 out of the row lock in `login_mfa` and `mfa_confirm`; compare-and-set under the lock. RED: 3 lock-probe tests (`LockNotAvailable` with `FOR UPDATE NOWAIT`) and 2 concurrency tests; GREEN: 479 passed. Mutation check: without the CAS both concurrency tests give `[200, 200]`.
- [x] **T3** (`3187341`, `5faf4eb`, `474adbc`, `60b7deb`, `a9d360a`): fixed `transit_failed` cause (RED observed); slow-OpenBao test was vacuous without settings, now uses `openbao_env` and fails without the timeout (`assert 5.0065 < 3`); `secrets.login_from_env` and `revoke` public; shared recovery format; `_no_enrollment()` explained. Writer final: 480 passed, ruff clean; parent spot check 480 passed. Original item: transit error security event with fixed cause (`main.py:55-58`); remove dead timeout monkeypatch (`test_transit_openbao.py:70`); make the slow-OpenBao test fail without the timeout (`:113-128`); dedupe recovery code format (`mfa.py:53-79`); explain or unify the duplicate 409 (`auth.py:1079-1094`); public interface instead of private coupling in `transit.py:33-40`.
- [x] **T4** (this docs commit): ADR 0006 derived key and `context`; threat 43 without "por decidir" and the new control; `odd/tasks/mfa-gateway.md` T3/T4 closed; BITACORA entry and pendings. One docs commit.
- [ ] **T5**: `revisor-seguridad` ready (0 critical/high/medium; 3 low, 4 info). One fix round: `975d205` L2 enroll encrypts outside the lock (RED LockProbe + 409 test), `feef070` L3 eligibility recheck under the lock at confirm (RED 2 tests), `906a911` I1 tests for every CAS branch (mutation check each). L1 accepted (BITACORA pending, E5 rate limit). Writer 488 passed; parent spot check 488 passed. Gentle AI review: pending.
- [ ] **T6**: push and PR (person request only).

## Progress
- 2026-10-11: branch `fix/43-mfa-sesion-privilegiada` from `28f63e8`; test environment ready; baseline 462 passed.
- 2026-10-11: T1-T3 done by the delegated writer (7 commits); parent spot check `uv run --locked pytest -q`: 480 passed; ruff clean. Writer gap: `mfa_enroll` (lector full-session path) still encrypts with transit under the counter lock.
- 2026-10-11: revisor-seguridad fix round done (488 passed); T4 docs committed; Gentle AI review next.
