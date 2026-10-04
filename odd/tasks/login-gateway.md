# login-gateway

## Objective
Issue #33 (E3, auth A2a, ADR 0004): `POST /api/auth/login` with an HS256 access JWT in `__Host-access`, signed double-submit CSRF (including pre-session), `Sec-Fetch-Site`/`Origin` check, progressive lockout, `current_user` + `GET /api/auth/me`, password Unicode normalization, and a bounded wait on the Argon2id semaphore.

## Why
Registration (#29) and OpenBao keys (#31) exist; login is the next step of ADR 0004. A2 is split: A2a (this) and A2b (refresh rotation/reuse detection, logout, `jti` denylist, `tokens_valid_since`). Until A2b, login issues only the 15-minute access JWT (accepted interim state).

## Scope
- Allowed: `services/gateway/**`; `.github/workflows/seguridad.yml` (`env` of the `gateway` job only); `docs/BITACORA.md`; `docs/threat-model.md` (status of threats 1, 8, 36); this file.
- Forbidden: `.claude/**`, `docs/adr/**`, other `.github/**`, real secrets.
- Out of scope: refresh/logout/denylist (A2b), MFA/TOTP and `enroll-mfa` scope (A3), first admin, per-IP rate limit (Ingress, E5).

## Constraints and decisions
- IMPLEMENTACIÓN LOCAL on `feat/33-login-gateway`; Conventional Commits referencing `#33`; no AI attribution lines; no push/PR until the person asks.
- Normalization: **NFC** (person decision 2026-10-03). NIST SP 800-63B rev. 4 (2025-08-26): "the verifier SHOULD apply the normalization process for stabilized strings using ... (NFC) ... before hashing". The issue text says NFKC (based on rev. 3); corrected here and to be noted in BITACORA and the PR.
- Semaphore: `acquire(timeout=5)`; on timeout respond 503 without hashing.
- Identical 401 body ("Login failed; Invalid user ID or password") for wrong password, unknown user and locked account; dummy hash verification for unknown users.
- Lockout: after 3 failures waits of 1, 5, 15, 30 min (cap 30); reset on success; counters also for unknown usernames.
- JWT: `algorithms=["HS256"]`, options built per call, leeway 30 s, fixed `iss`/`aud`, `kid` header; claims `sub`, `role`, `sid`, `jti`, `iat`, `exp` (15 min), `iss`, `aud`.
- New settings without insecure defaults: `GATEWAY_JWT_ISSUER`, `GATEWAY_JWT_AUDIENCE`, `GATEWAY_ALLOWED_ORIGIN`.

## Verified versions (2026-10-03)
- PyJWT 2.15.1 (PyPI JSON): license MIT, author Jose Padilla, homepage `github.com/jpadilla/pyjwt`, uploaded 2026-09-28, `requires_python >=3.9`, no runtime deps on Python >= 3.11 (`cryptography` only with extra `crypto`, not used), no vulnerabilities listed in the PyPI JSON.

## TDD
Mode: strict, enabled (global user configuration). Runner: `uv run --locked pytest` in `services/gateway`, with PostgreSQL and OpenBao from `docker compose up -d --wait postgres openbao` and `scripts/openbao-dev-init.sh`.

## Delivery
Forecast ~900 authored changed lines. Strategy: `single-pr` (precedent: #29 and #31 merged as single PRs of ~1100 lines; the issue itself is already the A2a slice). The person may switch to a chain.

## Route
- T1 delegated writer (writer + preparation triggers: dependency, migration, passwords, tokens, endpoints, tests, CI env).
- T2 inline: BITACORA, threat-model status (docs).
- T3 delegated: `revisor-seguridad`; Gentle AI review per commit assessment.

## Tasks
- [x] **T0**: issue #33 created (person authorized), branch, PyJWT and NIST verified, NFC decided.
- [x] **T1a**: PyJWT dependency (c5ca1cb) + migration `0002_login_attempts` + model + conftest TRUNCATE. Commit b2dddab. RED: `NoSuchTableError`/missing table (2 failed, 4 errors); GREEN: 108 passed.
- [x] **T1b**: NFC normalization (inside `hash_password`/`verify_password`, so register and login both get it), semaphore timeout (`HASH_WAIT_SECONDS = 5`) -> `HashingBusy` -> 503 via app handler, `verify_dummy`. Commit 0fbb87f. RED: `ImportError: cannot import name 'HashingBusy'` and register 503 test failing with `HashingBusy`; GREEN: 116 passed.
- [x] **T1c**: `tokens.py`: issue/decode access JWT, CSRF make/check. Commit a91216e. RED: `ImportError: cannot import name 'tokens' from 'gateway'`; GREEN: 168 passed. `decode_access_token` takes no `now` (PyJWT uses the real clock); tests forge times instead.
- [x] **T1d**: `auth.py`: `GET /api/auth/csrf`, `POST /api/auth/login` with lockout, `current_user`, `GET /api/auth/me`, origin check; security-event logs without secrets. Commit 140152e. RED: `AttributeError: module 'gateway.auth' has no attribute 'get_keys'` (+13 register origin failures); GREEN: 220 passed. Register also gets the origin check (no CSRF token); register tests send `Sec-Fetch-Site: same-origin`. When `Sec-Fetch-Site` is present and not `same-origin` the request is refused even if `Origin` matches (ADR text).
- [x] **T1e**: `settings.py` (`GATEWAY_JWT_ISSUER`, `GATEWAY_JWT_AUDIENCE`, `GATEWAY_ALLOWED_ORIGIN`, no defaults) + CI `env` of the `gateway` job. Commit aa2f977 (done before T1c because tokens need issuer/audience). RED: `AttributeError: ... no attribute 'get_jwt_issuer'`; GREEN: 126 passed.
- [ ] **T2**: BITACORA entry and threat-model status (1, 8, 36).
- [ ] **T3**: `revisor-seguridad` and Gentle AI review; fixes.
- [ ] **T4**: push and PR (person request only).

## Progress
- 2026-10-03: T0 done.
- 2026-10-04: T1a-T1e done by the delegated writer.
- Known gaps: `login_attempts` rows for unknown usernames have no TTL purge yet and a stale counter never decays; `tokens_valid_since` is not checked in `current_user` (A2b).
