# mantenimiento-sesion

## Objective
Issue #37 (E3): close the session debt left by #33 and #35 before A3: purge command for `login_attempts`, `revoked_jtis` and refresh families; a single clock for `tokens_valid_since`; logout that always clears cookies; shared test fixtures.

## Why
The tables grow without bound; `tokens_valid_since` (PostgreSQL `now()`) is compared with app-clock values (`iat`, `family.created_at`); A3 will be the first code to bump `tokens_valid_since`.

## Scope
- Allowed: `services/gateway/**`; `docs/BITACORA.md`; this file.
- Forbidden: `.claude/**`, `docs/adr/**`, `.github/**`, real secrets.
- Out of scope: A3, CronJob/deployment (E5), per-IP limit (E5).

## Design decisions
- `gateway.maintenance` module with `purge(session, now) -> dict[str, int]` and a `python -m gateway.maintenance purge` entry point printing only table names and counts.
- `login_attempts`: delete rows with `updated_at < now - 24 h` and (`locked_until` is null or `< now`). Constant `ATTEMPT_TTL`.
- `revoked_jtis`: delete rows with `expires_at < now`.
- Refresh families: delete families with `revoked_at` not null, or `created_at` older than the absolute limit of the owner's current role (join users). `refresh_tokens` go by FK cascade.
- `tokens_valid_since`: set explicitly from `get_now` at registration; documented rule that any future change uses the app clock.
- Logout: on invalid/missing access cookie still return 401 but clear the three cookies.

## TDD
Mode: strict, enabled (global user configuration). Runner: `uv run --locked pytest` in `services/gateway` against PostgreSQL and OpenBao (`DOCKER_CONTEXT=default`, disposable local credentials).

## Delivery
Forecast 500-700 authored changed lines. Strategy: `single-pr`. Workflow to limit review-hook churn: a single docs commit at the end before review, one combined fix round, no commits after an approved review.

## Route
- T1 delegated writer (writer + preparation triggers).
- T2 inline: BITACORA (+ #35 closure) and this document, one commit.
- T3: `revisor-seguridad` + one combined fix round, then one Gentle AI review.

## Tasks
- [x] **T0**: issue #37 created (person authorized), branch, design.
- [x] **T1a** (`ecb7a9a`): purge + CLI. RED: `ImportError: cannot import name 'maintenance'`; GREEN: 12 new tests.
- [x] **T1b** (`c903321`): `tokens_valid_since` from `get_now`. RED: DB `now()` != injected instant, `/me` 401; GREEN: 350 passed.
- [x] **T1c** (`c6bb8f6`): logout clears the three cookies on 401; 403s (origin/CSRF) do not, so a forged cross-site request cannot wipe them. RED: no Set-Cookie; GREEN: 354 passed.
- [x] **T1d** (`08071ca`): shared fixtures in conftest; unused parameter removed (refactor, suite green).
- [x] **T2**: BITACORA (#35 closure, #37 entry, pendings, NTP requirement) and this document in one docs commit.
- [ ] **T3**: `revisor-seguridad` ready (0 crit/high/med, 4 low) fixed in one round: `f2bf21d` jti kept through leeway, `bfd1782` DELETE ... RETURNING count, `2cacc7e` login retries vanished counter row then 503, `d40ca2a` CLI fixed error message exit 1 (each RED then GREEN; 360 passed, ruff clean). Gentle AI review: pending.
- [ ] **T4**: push and PR (person request only).

## Progress
- 2026-10-04: T0 done.
- 2026-10-05: T1, T2 and the revisor-seguridad fix round done; parent spot check 360 passed.
