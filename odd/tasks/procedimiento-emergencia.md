# procedimiento-emergencia

## Objective
Issue #58 (A3b2b): operator-only break-glass command to recover accounts that are or were privileged when two administrators are not available (ADR 0004, decision 11; threats 46 and 47). Closes R4-001 of #56 and L1 of #45; folds in the Gentle AI suggestions of #56 and updates ADR 0004.

## Scope
- Allowed: `services/gateway/**`; `deploy/openbao/**`; `scripts/openbao-dev-init.sh`; `docs/adr/0004-autenticacion.md`; `docs/BITACORA.md`, `docs/bitacora/**`; `docs/threat-model.md`, `docs/architecture/threat-model.json`; `odd/tasks/**`.
- Forbidden: `.claude/**`, `.github/**` (CI picks up new AppRole files through the init script; no workflow change expected), real secrets.
- Out of scope: R1-001 backfill review (before the first deploy, E5), Kubernetes Job manifests, anonymous help form, per-IP limits.

## Decisions
- 2026-10-16 (person): break-glass covers every account that is or was privileged (`needs_two_administrators`: administrators, editors, auditors, pending roles, `privileged_at`), not only administrators (extends ADR 0004 decision 11; closes R4-001).

## Design (from the issue and the code map)
- `gateway.breakglass` mirrors `gateway.bootstrap` (`bootstrap.py`): own AppRole `breakglass` (env `GATEWAY_BREAKGLASS_ROLE_ID_FILE` / `GATEWAY_BREAKGLASS_SECRET_ID_FILE`), policy `deploy/openbao/breakglass-policy.hcl` (read `secret/data/breakglass/account`, delete `secret/metadata/breakglass/account`), seed AppRole `breakglass-seed` only with `CI=true` or `OPENBAO_DEV_BOOTSTRAP_SEED=1`; the seeded secret holds `username` and `password`, and the command refuses unless `--username` matches it (wrong-target guard). Arguments: `--username <name> --break-glass`, exact.
- Effects in one transaction under the target user row lock: new password hash (seeded password, policy checked), `must_change_password = True`, MFA columns cleared and recovery codes deleted, `mfa_enroll_until = now + ENROLL_WINDOW` (24 h), pending recovery requests and reset codes of the target deleted, `invalidate_tokens`, every refresh family revoked; destroy all secret versions before commit (destroy failure -> rollback, exit codes like bootstrap); event `break_glass_reset`. Refuses (exit 3) an unknown account or one that was never privileged. No migration needed.
- Assumption: the login lockout counter is not reset (the CLI has no CSRF key to derive the attempt key); a locked account waits at most 30 min or an administrator unlocks it. Recorded as residual.
- ADR discrepancy to settle in T4: decision 11 says bootstrap refuses if an ACTIVE administrator exists; the code refuses on any `role == "administrador"`.

## Acceptance criteria (issue #58)
1. Refuses without `--break-glass`, with an unknown account or one never privileged; never takes the password from arguments nor logs it.
2. After a run the seeded secret is gone from OpenBao; if destruction fails the reset is rolled back.
3. The account ends with `must_change_password`, no MFA, a 24 h enrollment window and no valid session; the next login requires the password change and the MFA enrollment.
4. Every run leaves a security event without secrets.
5. The #56 suggestions are resolved without changing route behavior.
6. ADR 0004 reflects the decisions of #56 and of this issue.
7. Observed RED per behavior change; pytest and ruff green locally and in CI; revisor-seguridad with no critical or high; threat model updated.

## TDD
Mode: strict, enabled (global user configuration). Runner: `uv run --locked pytest` in `services/gateway` against `gw45-test-pg` (127.0.0.1:55432) and the compose OpenBao (`DOCKER_CONTEXT=default`, `POSTGRES_USER/PASSWORD/DB=unused`, `scripts/openbao-dev-init.sh`; new AppRole files need `CI=true` or `OPENBAO_DEV_BOOTSTRAP_SEED=1` and a fresh OpenBao state or a manual setup), CI test values for `GATEWAY_*`. Lint: `ruff check`, `ruff format --check`. Baseline on `main` (`1da1eb1`): 988 passed in CI.

## Delivery
`single-pr` (precedent). Gentle AI review per task commit right after it closes (the #56 lesson: the whole branch exceeded the reviewer budget). revisor-seguridad before the PR. Do not end a turn while a writer is editing.

## Route
- T1, T2: one delegated writer each (writer trigger: several non-trivial files).
- T3 (ADR) and T4 (docs): one delegated docs writer each.

## Tasks
- [x] **T0** (`08fd6c7`) #56 record and BITACORA count 978 -> 988. Gentle AI: low, approved (`review-cff36e38c7d7e756`).
- [x] **T1** (`473718e`) #56 Gentle AI suggestions: neutral request names (model, table via migration 0012 only if renaming the table; prefer renaming Python names and keeping the table, decide in the brief), shared approval helper for `approve_mfa_reset` / `approve_reset_code`, reset-code expiry computed once, no hash before the two-administrator check in `issue_reset_code`, missing tests (approver demoted under the lock, saturated hasher on approval, `mark_privileged` in `mfa_confirm`), `fail_lock` moved to `tests/helpers.py`, section header fixed.
- [x] **T2** (`9bf60e6`) `gateway.breakglass` command, AppRoles and policies, init script, fixtures and tests (fake store and real OpenBao), including the expired bootstrap-admin window (L1 of #45). Gentle AI: high, four lenses, approved (`review-21632641453f603c`).
- [x] **T3** (`afbba7d`) ADR 0004 decisions 10 and 11. Gentle AI: passive.
- [x] **T4** docs: BITACORA entry and Pendientes, threats 46 and 47.
- [ ] **T5** revisor-seguridad and fix round.
- [ ] **T6** push and PR (person request only).

## Progress
- 2026-10-16: issue #58 created by Claude at the person's request; branch `feat/58-procedimiento-emergencia` from `1da1eb1` (main CI green). T0 committed and reviewed. Code map delegated (read-only). T1 next.
- 2026-10-16: T1 done (`473718e`), delegated writer. Renames `ApprovalRequest`, `ApprovalPendingOut`, `APPROVAL_REQUEST_TTL` (table name kept, commented); shared `_claim_request(...)` for both approve routes; `_store_reset_code` returns `expires_at`; `issue_reset_code` peeks the target and skips the hash when two administrators are needed (recheck under the lock); `fail_lock`/`fail_requester_lock` in `tests/helpers.py`; header fixed; 6 new tests. TDD deviation disclosed: item 4 was implemented before its test, so no pre-change RED; substitute evidence by mutation (forcing the hash made the test fail). Mutation checks for 5a, 5b and 5c each failed and were reverted. GREEN: writer 994 passed, ruff green. Parent: spot check 151 passed (recovery, MFA reset, reset code, CSRF guard).
- 2026-10-16: T1 Gentle AI (`08fd6c7..0253bbc`, medium, reliability lens, person granted) approved and acknowledged (`review-e56d424c59d58206`). Suggestion R3-001: the "unreachable" 409 branch of `issue_reset_code` (`code_hash is None` after the peek) is reachable when a pending role without marker is cleared between the peek and the lock; reword the comment and add a test (409, no code row, no request row). Folded into T2. Next: T2.
- 2026-10-16: T2 closed. Parent full run: 1065 passed in 491 s (local, `gw45-test-pg` + compose OpenBao); ruff check and format green. Gentle AI on `0253bbc..9bf60e6` (high: `scripts/openbao-dev-init.sh`; person granted) approved and acknowledged (`review-21632641453f603c`) with 5 non-blocking suggestions folded into T5: R4-commit-in-doubt (docstring and RESET_FAILED text must say the account may or may not have been reset), R2 unparenthesized `except` at `breakglass.py:251`, `mark_privileged` missing from the docstring list, unused `shared` param of `FakeBao` in `test_breakglass.py`, `OPENBAO_DEV_BOOTSTRAP_SEED` also creates the break-glass writer role (document or rename).
- 2026-10-16: T3 done (`afbba7d`), delegated docs writer; parent verified the reset-code and 409 claims in code and corrected one false claim (the row lock serializes two break-glass runs, it does not prevent a second reset). Gentle AI: passive.
- 2026-10-16: T4 done, delegated docs writer: #56 entry moved unchanged to `docs/bitacora/2026-10-15.md` (diff checked), new #58 entry, Pendientes updated, threats 46 and 47 (md and json, JSON valid; parent aligned the leftover "administrador activo" of threat 47). BITACORA 18266 bytes. Next: T5 (revisor-seguridad plus the T2 suggestions).
