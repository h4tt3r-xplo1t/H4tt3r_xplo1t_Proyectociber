# registro-usuarios

## Objective
Issue #29 (E3, auth A1): PostgreSQL data layer with Alembic migrations and user registration with Argon2id passwords in the `gateway` (ADR 0004). Login, JWT, cookies, CSRF, refresh and logout are issue A2.

## Scope
- `services/gateway/**`: settings, DB engine/session, models, initial migration (`users`, `refresh_families`), password hashing, `POST /api/auth/register`, tests against real PostgreSQL.
- `docker-compose.yml` (dev PostgreSQL), `.env.example`, `.github/workflows/seguridad.yml` (`gateway` job only: PostgreSQL service container), `.claude/settings.json` (exact test commands).
- `docs/BITACORA.md` (ruleset applied 2026-09-30, #29 entry), `docs/adr/0001-proteccion-rama-main.md` (four required checks).
- Out of scope: login and sessions (A2), breached-password list (ASVS 6.2.12), MFA/roles/recovery/bootstrap, Vault.

## Constraints
- IMPLEMENTACIÓN LOCAL on `feat/29-registro-usuarios`; Conventional Commits with `#29`; no AI attribution lines.
- Person decisions (2026-09-30): SQLAlchemy 2 + Alembic (sync, psycopg 3); PostgreSQL via Docker Compose locally and a GitHub Actions service container in CI.
- Username identifier, no email (data minimization; admin-assisted recovery, ADR 0004 decision 10).
- DB credentials from environment only, no defaults in code; fake placeholder values marked unusable.
- The workflow changes, so the person pushes via SSH.

## Verified versions (2026-09-30)
GitHub releases/tags via `gh api`; PyPI via WebFetch summaries (second-hand).
- SQLAlchemy 2.1.1 (MIT, Mike Bayer, requires-python >=3.11), Alembic 1.20.0 (MIT, Mike Bayer).
- psycopg 3.3.6 and psycopg-binary 3.3.6 (LGPL-3.0-only, Daniele Varrazzo, github.com/psycopg/psycopg). LGPL: used as an imported library, compatible with Apache-2.0 distribution; recorded as a license note.
- argon2-cffi 25.1.0 (MIT, Hynek Schlawack), already verified in ADR 0004.
- PostgreSQL 18.6 (latest `REL_18_6` tag); image `postgres:18.6-alpine@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873` (Docker Hub API and `docker buildx imagetools inspect` agree).
- NOT VERIFIED: advisories beyond PyPI's empty vulnerability field; psycopg-binary upload date (summarizer printed 2024-12-19, inconsistent with 3.3.6).

## TDD
Mode: strict, enabled (global user configuration). Runners: `uv run --locked pytest` in `services/gateway` with PostgreSQL from `docker compose up -d postgres`.

## Route
- T1 delegated writer (writer trigger: 2+ non-trivial files; preparation trigger).
- T2 inline: bitacora and ADR 0001 (mechanical docs).
- T3 delegated: `revisor-seguridad`.

## Tasks
- [x] **T0**: issue #29 created (person authorized), branch, versions verified.
- [x] **T1**: delegated writer, commits `3120548`..`c47969a`. RED: Alembic `CommandError`, `ModuleNotFoundError: gateway.passwords`; GREEN: 53 passed. Parent spot check on a fresh database: 53 passed, ruff clean.
- [x] **T2**: BITACORA (#27 closure, ruleset applied, #29 entry) and ADR 0001 four checks.
- [x] **T3**: `revisor-seguridad` (3 medium, 7 low) and Gentle AI review (lineage review-cc06f3b305ce5398, approved, acknowledged). Fixes by delegated writer `9f8fb5d`..`47d778c` plus parent fix for PostgreSQL DETAIL leak (RED: hash in traceback; GREEN: 67 passed). Deferred to pendings: Unicode normalization (before A2), register rate limit and body cap (E5), readyz (E5), LGPL notice in image (E7).
- [ ] **T4**: push (person, SSH) and PR on request.

## Progress
- 2026-09-30: T0 done.
