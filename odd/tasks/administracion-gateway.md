# administracion-gateway

## Objective
Issue #45 (E3, A3b1, ADR 0004 decisions 5 and 11): create the first administrator safely and let administrators manage users (role assignment, pending when the user has no MFA; reissue of the MFA window; unlock; end sessions). Every user can change their password.

## Why
The gateway has no administration endpoints. A privileged user that already existed without MFA and without an enrollment window cannot sign in (risk noted in #43); the pending role assignment fixes it. A3b is split: this issue (A3b1) and A3b2 (assisted recovery, MFA reset with two administrators, break-glass).

## Scope
- Allowed: `services/gateway/**`; `scripts/openbao-dev-init.sh`; `deploy/openbao/**`; `docs/threat-model.md` and `docs/architecture/threat-model.json` (threats 1, 43, 47); `docs/BITACORA.md` and `docs/bitacora/**`; this file.
- Forbidden: `.claude/**`, `.github/**`, `docs/adr/**`, real secrets.
- Out of scope: A3b2 (assisted recovery, MFA reset, break-glass, reset notice), disabling accounts, MFA enrollment rate limit, Kubernetes Job manifests (E5), frontend.

## Design decisions
- Separate OpenBao AppRole `bootstrap` with a policy limited to `read` on `secret/data/bootstrap/admin` and `delete` on `secret/metadata/bootstrap/admin`; the gateway policy never gets `secret/bootstrap/*`. Person reviewed this choice in the issue draft.
- `python -m gateway.bootstrap --username <name>`: the password comes only from OpenBao, never the command line. Refuses if any administrator exists; a database lock blocks concurrent runs; destroys every version of the secret after creating the user; fixed messages and non-zero exit on failure.
- No new ADR: everything follows ADR 0004 decisions 5 and 11. Any forced deviation stops the work and goes to the person.
- Admin endpoints under `/api/admin/...`: administrator with a full session (which already requires MFA, #43), role rechecked in the database on every request.

## Verified versions
No new dependency expected.

## TDD
Mode: strict, enabled (global user configuration). Runner: `uv run --locked pytest` in `services/gateway` against a throwaway PostgreSQL container (`gw45-test-pg`, 127.0.0.1:55432, test-only credentials) and the compose OpenBao (`DOCKER_CONTEXT=default`, `scripts/openbao-dev-init.sh`), with the CI values for `GATEWAY_JWT_*` and `GATEWAY_ALLOWED_ORIGIN`. Baseline on `main` (`edb69c6`): 488 passed.

## Delivery
Forecast ~1500-2000 authored changed lines (about half tests). `single-pr`, following the precedent of #39 (similar size). Low-churn review workflow: one docs commit at the end, one combined fix round, one Gentle AI review, no commits after approval.

## Route
- T1-T4: one delegated writer (writer trigger: several non-trivial files in `services/gateway` and `scripts/`; preparation trigger), task by task.
- T5: inline docs, one commit.
- T6: `revisor-seguridad`, one fix round, one Gentle AI review.

## Tasks
- [x] **T1** (`7175b67`; RED: 4 migration tests, 5 bootstrap-role tests): migration `0005` (`must_change_password`, `pending_role`); `bootstrap` AppRole and policy in `scripts/openbao-dev-init.sh` and `deploy/openbao/`.
- [x] **T2** (`492456b` + `fee74c6`: person approved a dev/CI-only `bootstrap-seed` AppRole with only create/update on `secret/data/bootstrap/admin`; 6 real-OpenBao tests with RED observed per test (missing seed files); success path, refusal, concurrency and invalid secret run against the real OpenBao; destroy failure stays fake-based; order: create under advisory lock, destroy, confirm 404, then commit): `python -m gateway.bootstrap` (read, create, destroy, refuse if an admin exists, concurrency lock, fixed errors).
- [x] **T3** (`43005e2`; RED: 30 of 33 new tests with 404): `POST /api/auth/password` (current password, policy, close other sessions); `enroll-mfa` scope also allows only this endpoint while `must_change_password`; both gates before any other endpoint.
- [x] **T4** (`c7684dd`): `/api/admin/...` (list, assign role with pending, reissue window, unlock, end sessions, separation of duties, last admin); pending role applied on MFA confirm; security events; #43 advisory (current_user event, refresh event test, docstring).
- [x] **T5** (this docs commit; route: delegated writer, writer trigger: threat model md + json + BITACORA): threats 1, 43, 47; BITACORA; how to run the bootstrap in dev. One docs commit.
- [x] **T6a** (`4493982`; delegated writer; RED: user row not held during confirm, GREEN, mutation check): fix round M1 (`_lock_user_row` in `mfa_confirm`, order counter row then user row, no admin path takes the reverse) and L3 (loser exit code and fixed message). 621 passed; parent spot check 621 passed; ruff clean.
- [x] **T6b**: Gentle AI review, high risk, consent granted by the person; 4 lenses, approved with no blocking findings; acknowledged (lineage `review-574db0b2d3b6c9a8`). 13 advisory findings recorded as follow-up work (no commits after approval).
- [ ] **T7**: push and PR (person request only).

## Progress
- 2026-10-11: branch `feat/45-administracion-gateway` from `edb69c6`; test environment ready; baseline 488 passed.
- 2026-10-11: writer T1-T4 (4 commits), 613 passed, ruff clean; parent spot check 613 passed; gateway policy unchanged. Local OpenBao recreated as authorized. Open decision for the person: dev/CI-only `bootstrap-seed` AppRole (create/update on `secret/data/bootstrap/admin`) to run the real bootstrap destroy in tests. Interpretations to confirm: admin cannot become auditor = 403 when the target currently is administrador; last-admin rule counts only administrators with MFA active.
- 2026-10-11: `fee74c6` closes the T2 gap (local OpenBao recreated again as authorized); 620 passed, parent spot check 620 passed. revisor-seguridad next.
- 2026-10-11: revisor-seguridad: ready for PR, 0 critical/high. Fix round pending: M1 (medium-low) race between `mfa_confirm` applying `pending_role` and `assign_role` (lock the user row FOR UPDATE in mfa_confirm before applying, Barrier test); L3 tautological assert in `test_real_simultaneous_runs_create_one_administrator` (check loser exit code). Document only: L1 bootstrap admin stuck if the 24 h window lapses (depends on A3b2 break-glass), L2 same-second `tokens_valid_since` for scoped tokens, I1 refused bootstrap leaves the seeded secret (runbook note), I2 advisory lock instead of a unique constraint, bootstrap-seed must stay out of E5 manifests. Next: fix round -> T5 docs commit -> Gentle AI.
- 2026-10-12: fix round `4493982` (M1, L3); 621 passed, parent spot check 621 passed. Next: T5 docs commit, then Gentle AI.
- 2026-10-12: docs `c52f6b4`; Gentle AI approved and acknowledged. Advisory follow-ups: R4 ambiguous bootstrap destroy outcome; R3 flaky real bootstrap race test; R3 password-change recheck untested; R2/R3 tautological race assert in test_bootstrap.py:149; R2 password-change lock comment; minor readability suggestions. Next: T7 push and PR on the person's request.
