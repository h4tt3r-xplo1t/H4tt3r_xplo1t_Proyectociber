# sesion-gateway

## Objective
Issue #35 (E3, auth A2b, ADR 0004): opaque refresh token with rotation and reuse detection, logout with revocation and `jti` denylist, and `tokens_valid_since` / denylist checks in `current_user`. Also two #33 follow-ups: reset the failure counter only after tokens are issued, and check the minimum password length after NFC.

## Why
#33 (PR #34, `51aa0e4`) left a 15-minute access JWT that can be neither renewed nor revoked (threat 35). `refresh_families` exists since #29 and is unused.

## Scope
- Allowed: `services/gateway/**`; `docs/BITACORA.md`; `docs/threat-model.md` and `docs/architecture/threat-model.json` (threats 1, 35); this file.
- Forbidden: `.claude/**`, `docs/adr/**`, `.github/**`, real secrets.
- Out of scope: MFA/TOTP (A3), `login_attempts` purge, per-IP limit (E5), `kid` rotation, frontend renewal.

## Design decisions
- `sid` = `refresh_families.id` (UUID string). Login creates the family; the access JWT `sid` and the session CSRF binding use it. No new column on the family.
- New migration `0003` (0001 and 0002 are merged): table `refresh_tokens` (id, `family_id` FK cascade, `token_hash` unique SHA-256 hex of a 256-bit CSPRNG token, `created_at`, `used_at` nullable) and table `revoked_jtis` (`jti` pk, `expires_at`). SHA-256 (not Argon2) is enough because the token is high-entropy random.
- Refresh: look the token up without a lock to get its family, then lock the family `FOR UPDATE`, then the token `FOR UPDATE` (one fixed order, so logout, which locks only the family, cannot deadlock with it); used token -> revoke family + 401 (reuse); revoked/idle/absolute-expired family -> 401; else mark used, insert new token, bump `last_used_at`, issue new access JWT (same `sid`) and new session CSRF. CSRF is checked against the family's `sid` (the access cookie may be expired). Limits by DB role: lector idle 24 h / absolute 7 d; others 30 min / 8 h. Refresh cookie `Max-Age` = absolute limit.
- Logout: decode the access JWT with signature, `iss`, `aud` verified and `exp` not enforced; revoke the family by `sid`; deny the `jti` until `exp` (skip if already past); clear the three cookies. Requires session CSRF + same origin.
- `current_user`: one query joining user, `tokens_valid_since` and denylist. Compare `iat` against `tokens_valid_since` truncated to the second (JWT `iat` is whole seconds; `now()` has microseconds, so a token issued in the same second must not be rejected).

## Verified versions
No new dependency expected (PyJWT 2.15.1 already verified in #33).

## TDD
Mode: strict, enabled (global user configuration). Runner: `uv run --locked pytest` in `services/gateway` against PostgreSQL and OpenBao (`DOCKER_CONTEXT=default`, disposable local credentials, `scripts/openbao-dev-init.sh`).

## Delivery
Forecast ~1500 authored changed lines (about half tests). Strategy: `single-pr` (precedent #29, #31, #33). No `.github/**` change, so an HTTPS push is possible if the person asks.

## Route
- T1 delegated writer (writer + preparation triggers: migration, models, tokens, auth, tests).
- T2 inline: BITACORA and threat-model evidence (1, 35).
- T3 delegated: `revisor-seguridad`; Gentle AI review once implementation is complete.

## Tasks
- [x] **T0**: issue #35 created (person authorized), branch, design, #33 closure in BITACORA.
- [x] **T1a** (`e292670`): migration `0003` + models `RefreshToken`, `RevokedJti`; conftest TRUNCATE. RED: `NoSuchTableError: refresh_tokens` / `UndefinedTable`; GREEN: 250 passed.
- [x] **T1b** (`272c1e3`): login issues the refresh token and family (`sid` = family id); counter reset only after tokens are issued; length check after NFC in register. RED: `ImportError: cannot import name 'hash_refresh_token'`, `AttributeError` on `auth.session_limits`, counter reset before issuing; GREEN: 259 passed.
- [x] **T1c** (`e29120a`): `POST /api/auth/refresh` with rotation, reuse detection and role limits. RED: 26 failed (`404 == 200`, route absent); GREEN: 286 passed.
- [x] **T1d** (`1c09412`): `POST /api/auth/logout`, `jti` denylist, `current_user` checks (`tokens_valid_since`, denylist). RED: `AttributeError: ... no attribute 'decode_access_token_allow_expired'`, `404 == 204`; GREEN: 304 passed.
- [x] **T1e** (`2677af5`): `current_user` also requires the `sid` family to exist and not be revoked (same single query; non-UUID sid is 401); failed refreshes log `event=refresh_failed reason=...`. Two existing tests that forged tokens with random sids now create a family first. RED: 9 failed (`assert 200 == 401` for revoked/missing/non-UUID sid; `ValueError: not enough values to unpack` for the missing failure logs); GREEN: 314 passed.
- [x] **T3a review fixes** (revisor-seguridad), one commit each:
  - M2 (`d66df45`): two threads, same refresh token, held family-row lock + `pg_stat_activity` poll; exactly one 200 and one 401, family revoked, winner's new token dead. Characterization test (passes on the existing code, so no RED); 20/20 runs passed.
  - L2 (`271c8a9`): `LoginBusy.cause`; refresh logs `refresh_row_locked`, login keeps `attempt_row_locked`. RED: log said `cause=attempt_row_locked`.
  - L1 (`886f284`): lookup without lock, then family `FOR UPDATE`, then token `FOR UPDATE`; 55P03/40P01/40001 map to busy 503. RED: token-first single joined `FOR UPDATE`, 40P01 and 40001 re-raised.
  - L3 (`0a10259`): logout does `SET LOCAL lock_timeout`, busy 503 with `cause=logout_row_locked`. RED: `assert 204 == 503` (logout waited on the lock).
  - L4 (`e4216c8`): refresh rejects `family.created_at < date_trunc('second', tokens_valid_since)` with `reason=invalidated`. RED: `assert 200 == 401`. Two absolute-limit tests now also move `tokens_valid_since` back.
  - L6 (`472fe82`): `current_user` and logout also catch `TypeError`/`AttributeError`. RED: `AttributeError: 'int' object has no attribute 'replace'` (int and list `sid`).
  - Final run from an empty test DB: ruff check, ruff format --check, 333 passed.
- [x] **T2** (`828ece5`, `f160105`): BITACORA entry and threat evidence (1, 35).
- [x] **T3** (revisor-seguridad and Gentle AI review `review-3a4bb0b52adcc031` approved, with the T3a and T3b fixes): reviews and fixes.
- [x] **T3b advisory fixes** (Gentle AI review), one commit each:
  - Access cookie Max-Age (`34999b7`): `__Host-access` now lives as long as the session (role absolute limit) so logout can still find it after the 15-minute JWT expired. RED: `max-age=900` instead of 604800/28800. Login assertion updated.
  - Non-numeric `exp` on logout (`3e786d2`): `exp` type checked inside the claim try (bool, str, list, null rejected). RED: `TypeError: argument must be int or float, not str` (500).
  - Test name (`380bad9`): the rotated-token test now presents the old token and asserts 401 plus the revoked family (presenting it is reuse by policy, explained in the docstring). Test only.
  - Rename (`6e3d6c1`): `LoginBusy` is `ServiceBusy`, `cause` now required. No RED (rename).
  - Constant (`c43e3b1`): single `PASSWORD_MIN_LENGTH`. No RED (refactor).
  - Design and status lines of this document updated (T2, T3 checked).
  - Pending, not changed: unbounded growth of `refresh_tokens`; comparison of `tokens_valid_since` across two clocks.
- [ ] **T4**: push and PR (person request only).

## Progress
- 2026-10-03: T0 done.
- 2026-10-03: T1a-T1e done (writer). Final run from an empty test DB: ruff check, ruff format --check and 314 tests pass. Open gap: nothing purges expired rows of `revoked_jtis`.
