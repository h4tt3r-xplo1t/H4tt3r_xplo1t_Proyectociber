# mfa-gateway

## Objective
Issue #39 (E3, A3a, ADR 0004 decisions 4, 8 and 11): TOTP MFA mandatory for privileged roles and optional for lector, with the TOTP secret encrypted by the OpenBao transit engine (ADR 0006).

## Scope
- Allowed: `services/gateway/**`; `scripts/openbao-dev-init.sh`; `deploy/openbao/**`; `docs/adr/0006-*.md`; `docs/BITACORA.md` and `docs/bitacora/**`; `docs/threat-model.md` and its JSON (threats 1, 8, 43, 44); this file.
- Forbidden: `.claude/**`, `.github/**`, other ADRs, real secrets.
- Out of scope (A3b or later): assisted recovery, first admin bootstrap, break-glass, pending role assignment, password change, MFA disable/regenerate, frontend, purge follow-ups.

## Design decisions
- Person decision 2026-10-05: OpenBao transit for the TOTP secret (key `totp`, gateway policy `encrypt`/`decrypt` only on that key). Recorded in ADR 0006.
- Transit calls use a short-lived AppRole token per operation (login, call, revoke), like the existing key read; failures fail closed with a fixed 503.
- Scoped JWTs: `enroll-mfa` (10 min, privileged user without MFA, also lector enrolling from a full session uses the normal session) and `mfa-pending` (short, password ok and MFA active). `current_user` rejects any scoped token; enrollment and second-factor endpoints accept only their own scope.
- Enrollment window: column with the deadline (24 h from role assignment, bootstrap or break-glass). Without a deadline or past it, a privileged user without MFA gets the generic 401.
- TOTP: ±1 step, last used step stored, MFA failures count in the progressive lockout. Recovery codes: 10, base32 `XXXX-XXXX-XXXX`, Argon2id, single use.
- Local dev: transit is configured only on first setup (root is revoked afterwards), so the local OpenBao volume and `.local/openbao` credentials are recreated; CI always starts fresh.

## Verified versions (2026-10-05)
- pyotp 2.10.0 (PyPI JSON): MIT, Andrey Kislyuk, `pyauth/pyotp`, uploaded 2026-06-14, no runtime deps, no vulnerabilities listed. `uv audit`: 41 packages, none known. Commit `d53e530`.

## TDD
Mode: strict, enabled (global user configuration). Runner: `uv run --locked pytest` in `services/gateway` against PostgreSQL and OpenBao with transit.

## Delivery
Forecast ~1500 lines. `single-pr`. Low-churn review workflow: single docs commit at the end, one combined fix round, one Gentle AI review, no commits after approval.

## Route
- T1 delegated writer (writer + preparation triggers).
- T2 inline: ADR 0006, BITACORA (#37 closure, count fix, rotation), threat evidence; one docs commit.
- T3: `revisor-seguridad`, one fix round, one Gentle AI review.

## Tasks
- [x] **T0**: issue #39 (person authorized), branch, pyotp verified and added (`d53e530`).
- [x] **T1a** (`04862a0`): transit in the init script and policy; `transit.py`. RED: `ImportError: cannot import name 'transit'`; GREEN: 370 passed.
- [x] **T1b** (`427b563`): migration `0004`, models, conftest TRUNCATE. RED: missing columns; GREEN: 375 passed.
- [x] **T1c + T1d** (`911d25d`, one commit: shared `auth.py` and fixtures): enrollment and second factor. RED: 67 failed; GREEN: 448 passed.
- [x] **T2**: ADR 0006, BITACORA (rotation to `docs/bitacora/2026-10-03_05.md`, #37 closure, count fix, #39 entry), threats 43 and 44; one docs commit.
- [ ] **T3**: `revisor-seguridad` ready (2 medium, 5 low); one fix round: `f225baf` transit timeout, `143da9a` enrollment window on every call, `51a11e1` password to enroll and end all sessions on confirm, `b778443` pending token single use under concurrency (20/20), `715109d` ciphertext bound to user (derived key). 462 passed, ruff clean. L2 and L5 documented. Gentle AI review: pending.
- [ ] **T4**: push and PR (person request only).

## Progress
- 2026-10-05: T0 done.
- 2026-10-05: T1, T2 and the revisor-seguridad fix round done; parent spot check 462 passed.
