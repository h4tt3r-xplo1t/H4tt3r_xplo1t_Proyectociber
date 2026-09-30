# adr-autenticacion

## Objective
Issue #20: ADR 0004, covering authentication and authorization of the gateway. It closes the auth-related pending decisions of the threat model before E3.

## Scope
- `docs/adr/0004-autenticacion.md` (new).
- `docs/architecture/threat-model.json` and `docs/threat-model.md`: update the mitigations of the affected threats and add the MFA threats.
- `docs/BITACORA.md`: entry and pending items.
- Out of scope: code, CI, infrastructure.

## Constraints
- IMPLEMENTACIÓN LOCAL on `docs/20-adr-autenticacion`; local commits only; Conventional Commits with `#20`; no AI attribution lines.
- Docs in Spanish. Every standard is cited with its version and every library with its verified PyPI data (AGENTS.md §3).

## Decisions (2026-09-29, person)
1. Session token in a `__Host-` cookie with HttpOnly, Secure and SameSite=Strict; anti-CSRF token plus Origin/Sec-Fetch-Site check on state-changing requests; same origin, so no CORS.
2. HS256 with a random key of at least 256 bits held in Vault; `algorithms=["HS256"]` pinned; exp, iss and aud validated; `kid` for rotation.
3. Access JWT lasts 15 min. The refresh token is opaque and random, and only its hash is stored; it is rotated on every use, reuse of an old one revokes the family, and logout deletes it. A jti denylist makes the access token unusable after logout (ASVS 7.4.1).
4. Argon2id (m=19456, t=2, p=1). Password length at least 15 and at most 64 or more, any characters, no composition rules; a local list of common and breached passwords. Progressive lockout: after 3 failures wait 1, 5, 15 and 30 min, with recovery still available; the counter is per account plus a per-IP limit from the Ingress. Generic errors and constant time (ASVS 6.3.8 is L3: reinforcement).
5. Four roles: lector, editor, auditor and administrador. Deny by default; ownership checks per object; UUIDs. The editor can't add domains (egress allowlist, threat 21). An administrator can't also be an auditor, can't self-assign auditor, and can't read or delete the audit log. The first admin is bootstrapped from Vault.
6. Search audit records keep the user UUID, time, action, result, result count and a truncated IP. They don't keep the search text. Retention is 180 days, purged by a dedicated role.
7. ASVS 5.0.0 target: L1 overall, plus L2 in V6, V7, V8 (and V9 for the JWT).
8. MFA with TOTP is mandatory for editor, auditor and administrador and optional for lector. Recovery codes are stored hashed; the TOTP secret is stored encrypted; a privileged role requires MFA.
9. Session timeouts per role: lector has 24 h inactivity and 7 days absolute; privileged roles have 30 min inactivity and 8 h absolute, with re-authentication plus MFA.

## Verified libraries (PyPI, 2026-09-29)
- PyJWT 2.15.1 (2026-09-28, MIT).
- argon2-cffi 25.1.0 (2025-06-03, MIT).
- pyotp 2.10.0 (2026-06-14, MIT).
- Rejected: python-jose (CVE-2024-33663, CVE-2024-33664).

## TDD / checks
There is no test runner for prose. Checks: guardia and ruleset suites, the gitleaks hook, model integrity, and a relative-link check.

## Route
- T1 delegated writer: ADR and BITACORA (preparation and writer triggers).
- T2 inline: threat-model JSON and md, using the established script pattern on one data file.

## Tasks
- [x] **T0**: decisions 1–9 with the person, plus source verification by a research subagent.
- [x] **T1**: `docs/adr/0004-autenticacion.md` and the BITACORA entry (ADR commit e9e8520; BITACORA commit see progress note).
- [x] **T2**: threat-model mitigations 1, 2, 4, 8, 35, 36, 37 and 39 updated; threats 43, 44 and 45 added, for 45 in total (`9247cbb`).
- [x] **T3**: `revisor-seguridad` in three passes. Pass 1: not ready (3 high). Pass 2: not ready (1 high). Pass 3: ready for PR, with its 3 minor observations fixed (bootstrap without an exception, `enroll-mfa` scope covers the password change, logout accepts an expired but valid access token).
- [ ] **T4**: push and PR (person pushes; PR on request).

## Progress
- T1 done 2026-09-29: ADR 0004 committed as e9e8520; BITACORA entry and pendientes in the follow-up commit `docs: log ADR 0004 in bitacora (#20)`. Guardia 164/164 and ruleset 15/15 pass.
- Parent review of T1: the roles table gave the administrador "add domains" and "edit content", which contradicts decision 5. Fixed: nobody adds domains from the app (PR only), only the editor toggles existing sources, and the administrador manages people, not content.
- Security review (revisor-seguridad): NOT ready, 3 high findings. Fixed 2026-09-29 in the ADR: decisions 10 (admin-assisted recovery, person's choice) and 11 (MFA enrollment, first-admin bootstrap) added; decision 6 widened to security events; ASVS IDs corrected against v5.0.0; PyJWT >= 2.15.0. Status set to Propuesto. Next: T3 re-review, then PR.
- Second security review: NOT ready (1 high, 3 medium introduced by the rewrite). Fixed 2026-09-29 in the ADR: break-glass procedure, grace period replaced by single-flight refresh, N3/N4 accepted as residual risks, cookie/CSRF details, destroy of Vault secret versions, traceability of decision 9. Next: threat-model update by the parent, then re-review and PR.
