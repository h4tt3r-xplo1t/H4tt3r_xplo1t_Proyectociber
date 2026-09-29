# ficha-agregador

## Objective
Issue #15 (E0): record the chosen application, H4tt3r_1nf0rm4t1v0, and its project sheet, ADR and written proposal. The application is an aggregator of the top news from Colombian and Spanish-language media plus trends, with topic search.

## Scope
- `docs/PROJECT_CONTEXT.md`: add a "Ficha del proyecto: H4tt3r_1nf0rm4t1v0" section, keeping the course statement intact.
- `docs/adr/0003-agrupacion-microservicios.md`: 4 deployable services instead of the 8 logical ones.
- `docs/propuesta.md`: the written proposal for the professor (course section 2).
- `docs/BITACORA.md`: session entry and updated pending list.
- Out of scope: application code, Dockerfiles, workflows, IaC.

## Constraints
- Mode: IMPLEMENTACIÓN LOCAL on `docs/15-ficha-agregador`. Local commits only; no push or PR without explicit authorization.
- Conventional Commits referencing `#15`, with no AI attribution lines.
- Docs in Spanish (project convention for `docs/`); neutral, professional register.
- Facts that change over time must carry their source URL and the date consulted (2026-09-29), or be marked NO VERIFICADO (AGENTS.md §3).

## Decisions (2026-09-29, user)
1. Hosting: this repo; moving to a branch of the course repo is the last project task.
2. Architecture: 4 services (FastAPI gateway; news worker; trends worker; analysis worker) + PostgreSQL, RabbitMQ, Vault.
3. Sources: RCN and Semana (RSS); Caracol, Blu Radio and Citytv (sitemaps); YouTube (mostPopular CO + keyword search); Google Trends RSS CO (unofficial); Mastodon trends (global). Excluded: Facebook, TikTok, Instagram, X, Reddit, CNN en Español.
4. Defense user story: topic search.
5. License: Apache 2.0 (the pysentimiento model license is declared separately).
6. Orchestration: K3s via k3d; IaC: Terraform (kubernetes + helm providers).
7. Docker Hub: `h4tt3rxplo1tt` (look-alike `h4tt3rxplo1t` is not confirmed as the user's).
- Identix discarded on the same day (OSINT on real people required ownership verification, consent and deletion), so the +1 bonus is given up.

## TDD / checks
- Strict TDD is configured globally, but there is no test runner for prose docs. Honest checks instead: `bash tests/hooks/guardia_test.sh`, `bash tests/rulesets/main_ruleset_test.sh`, the gitleaks pre-commit hook, and a relative-link check of the new docs.

## Route
Delegated writer (writer trigger: 4 non-trivial docs).

## Tasks
- [x] **T0**: restore the broken images of the course statement (`f834b9d`).
- [x] **T1**: sheet section in `docs/PROJECT_CONTEXT.md`.
- [x] **T2**: ADR 0003.
- [x] **T3**: `docs/propuesta.md`.
- [x] **T4**: BITACORA entry and pending list.
- [x] **T5**: `revisor-seguridad` review before proposing the PR (ready for PR; B1 and B3 fixed, B2/B5/B6/B4 moved to pending items).

## Progress
- Issue #15 created and retitled by the user. Branch `docs/15-ficha-agregador` from `main` at `7ba9cae`.
- Source verification: two read-only research subagents (2026-09-29); findings summarized in the sheet.
- T1 done: sheet section appended to `docs/PROJECT_CONTEXT.md` (`6da6016`); course statement untouched.
- T2 done: `docs/adr/0003-agrupacion-microservicios.md` (`221da19`).
- T3 done: `docs/propuesta.md` (`7915f2d`).
- T4 done: BITACORA entry and pending list (commit below); this document updated in the same commit.
- Checks (writer, re-run by parent): `tests/hooks/guardia_test.sh` 164/164, `tests/rulesets/main_ruleset_test.sh` 15/15, relative links resolve, and only the 2 alt-text lines of the course statement changed.
- T5: revisor-seguridad verdict ready for PR, with 0 critical/high/medium and 3 low findings. B1 and B3 fixed in the follow-up commit (Mastodon limited to tags and links; own non-impersonating User-Agent; source content treated as untrusted input). B2/B5/B6/B4 tracked in BITACORA pending items.
