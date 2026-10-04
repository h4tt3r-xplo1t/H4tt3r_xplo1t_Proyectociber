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
- Refresh: lock the presented token row `FOR UPDATE`; used token -> revoke family + 401 (reuse); revoked/idle/absolute-expired family -> 401; else mark used, insert new token, bump `last_used_at`, issue new access JWT (same `sid`) and new session CSRF. CSRF is checked against the family's `sid` (the access cookie may be expired). Limits by DB role: lector idle 24 h / absolute 7 d; others 30 min / 8 h. Refresh cookie `Max-Age` = absolute limit.
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
- [ ] **T1a**: migration `0003` + models `RefreshToken`, `RevokedJti`; conftest TRUNCATE.
- [ ] **T1b**: login issues the refresh token and family (`sid` = family id); counter reset only after tokens are issued; length check after NFC in register.
- [ ] **T1c**: `POST /api/auth/refresh` with rotation, reuse detection and role limits.
- [ ] **T1d**: `POST /api/auth/logout`, `jti` denylist, `current_user` checks (`tokens_valid_since`, denylist).
- [ ] **T2**: BITACORA entry and threat evidence (1, 35).
- [ ] **T3**: reviews and fixes.
- [ ] **T4**: push and PR (person request only).

## Progress
- 2026-10-03: T0 done.
