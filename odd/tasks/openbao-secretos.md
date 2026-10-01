# openbao-secretos

## Objective
Issue #31 (E3, before auth A2): run OpenBao in server mode for development and CI, and have the `gateway` read its JWT signing key (with `kid`) and CSRF HMAC key from it through AppRole with a read-only policy.

## Scope
- `docker-compose.yml` (OpenBao service), `deploy/openbao/**` (server config, gateway policy), `scripts/openbao-dev-init.sh`.
- `services/gateway/**`: settings, OpenBao client module, key validation, tests (unit + integration against real OpenBao).
- `.github/workflows/seguridad.yml` (`gateway` job only), `.gitignore`, `.env.example` (person edits; agent cannot read it).
- Docs: ADR 0005, BITACORA (#29 closure, #31 entry), threat model rows 13, 14 and 42 (status with evidence).
- Out of scope: login/JWT/cookies/CSRF (A2), automatic key rotation, listener TLS, PostgreSQL credentials in OpenBao, k3d.

## Constraints
- IMPLEMENTACIÓN LOCAL on `feat/31-openbao-secretos`; Conventional Commits with `#31`; no AI attribution lines.
- Person decisions (2026-09-30): secrets manager now; OpenBao instead of Vault (Vault >= 1.15 is BSL 1.1; course expects MPL 2.0); server mode, not dev mode (threat 42); storage is single-node raft because OpenBao 2.7 has no `file` backend.
- Workflow changes, so the person pushes via SSH.

## Verified versions (2026-09-30)
- OpenBao 2.7.0 (MPL-2.0, `openbao/openbao`, release 2026-09-23). Image `openbao/openbao:2.7.0@sha256:71156a1c6623a5fa3f5e61b0c6a8ead0faf0df29a778339188443551995d1315`, same digest on ghcr.io, quay.io and docker.io (`docker buildx imagetools inspect`).
- HashiCorp Vault v2.1.1: `LICENSE` is Business Source License 1.1, licensor IBM (read via `gh api`).
- hvac 2.4.0 (Apache-2.0, `hvac/hvac`, release 2025-10-30, depends on `requests`). OpenBao is not in hvac's test matrix (open issue "Add OpenBao to test matrix"): compatibility proven by integration tests.

## TDD
Mode: strict, enabled (global user configuration). Runner: `uv run --locked pytest` in `services/gateway` with PostgreSQL and OpenBao from docker compose and `scripts/openbao-dev-init.sh`.

## Route
- T1 delegated writer (writer and preparation triggers: compose, config, script, client module, tests, CI).
- T2 inline: ADR 0005, BITACORA, threat model rows (docs).
- T3 delegated: `revisor-seguridad`.

## Tasks
- [x] **T0**: issue #31 created (person authorized), branch, versions and licenses verified.
- [x] **T1**: delegated writer `29cd855`..`e18ef57` (raft storage, not file; IPC_LOCK; 86 passed). Parent fix `4e8c793`: root revocation verified by a failing lookup. Parent end-to-end run on a fresh stack: init twice idempotent, 86 passed.
- [x] **T2**: ADR 0005 (raft wording), BITACORA (#29 closure, #31 entry, pendings), threat 42 evidence in md and JSON.
- [x] **T3**: `revisor-seguridad` (3 medium, 5 low) and Gentle AI (lineage review-8e784195174a15e6, approved, acknowledged). Fixes by delegated writer `9344824`, `1ab0c67`, `1d4622c` (the writer hit a rate limit at the end; parent verified the result itself: fresh stack, script x3 incl. after restart, 103 passed, ruff, audit, guardia, ruleset).
- [ ] **T4**: push (person, SSH) and PR on request.

## Progress
- 2026-09-30: T0 done.
