# worker-noticias

## Objective
Issue #60 (E3): the `worker-noticias` service (ADR 0003) periodically reads the RSS of RCN and Semana and the news sitemaps of RCN, Caracol, Blu Radio and Citytv, and stores only headline, link, date, short summary, outlet and author (if published) in PostgreSQL, with the controls of threats 15, 17, 20, 21 and 22 implemented and tested. First link of the topic-search user story (PROJECT_CONTEXT §9).

## Scope
- Allowed: `services/worker-noticias/**`; `.github/workflows/seguridad.yml` (new required job); `.github/rulesets/main.json` (new required check, applying it on GitHub is a remote operation on request only); `.github/dependabot.yml` (uv entry for the new service); `tests/rulesets/main_ruleset_test.sh` (required-check list; authorized by the person on 2026-10-16); `docs/adr/0007-*.md`; `docs/threat-model.md`, `docs/architecture/threat-model.json`; `docs/BITACORA.md`, `docs/bitacora/**`; `odd/tasks/**`.
- Forbidden: `.claude/**` (adding the worker commands to `.claude/settings.json` stays a BITACORA pending), `services/gateway/**`, real secrets, real requests to the outlets in CI.
- Out of scope: RabbitMQ and `worker-analisis`, search API, frontend, `worker-tendencias`, egress proxy and network policy by domain, Kubernetes manifests, credentials in OpenBao (E5), Bandit as a separate tool (E4).

## Decisions
- 2026-10-16 (person): own periodic loop, no Celery; recorded in ADR 0007.
- 2026-10-16 (person): plan approved; delivery `single-pr` (precedent of #56 and #58).
- Assumption (reversible): the worker owns its migrations (Alembic with its own version table) and its table; it does not reuse the gateway migrations.
- Assumption: criterion 2 "Bandit reports nothing" is met with ruff's `S` rules (flake8-bandit), as in the gateway; Bandit itself arrives in E4.

## Dependencies (verified on PyPI, 2026-10-16)
- `urllib3` 2.8.0: MIT; maintainers Seth Michael Larson, Quentin Pradet, Illia Volochii; https://github.com/urllib3/urllib3; requires Python >=3.10; no mandatory dependencies. Chosen over `httpx` because it can connect to an already validated IP while keeping SNI and certificate checks on the hostname (`server_hostname`/`assert_hostname`), the DNS-rebinding defense of threat 21, with no transitive dependencies.
- `defusedxml` 0.7.1: PSFL; Christian Heimes (CPython core developer); https://github.com/tiran/defusedxml; last stable release 2021-03-08 (0.8.0rc2 in 2023). Low activity is an accepted risk: it is pure Python and used only as defense in depth with `forbid_dtd=True`; Python 3.14 docs state Expat >= 2.7.2 already resists billion laughs, quadratic blowup and large tokens, and that Expat never opens files or connections. The worker also checks `pyexpat.EXPAT_VERSION` in a test and caps the decompressed size itself (decompression bomb).
- Dev: `pytest`, `ruff` with the gateway's versions.

## Acceptance criteria (issue #60)
1. Rejects any host outside the list, `http://`, a literal IP, a 3xx to another host or to `127.0.0.1`, and a name that resolves to a private IP; one test per case.
2. A known XXE payload (external entity and billion laughs) is rejected without reading files or expanding; ruff `S` reports no unsafe XML parser.
3. An oversized response or a slow fake server is cut within the timeout; the worker continues with the other sources and logs the failure.
4. With one source down, the others are stored and the log names the failed one.
5. Only headline, link, date, trimmed summary, outlet and author (if any) are stored; reading a source twice does not duplicate rows.
6. If a source's `robots.txt` forbids the path, it is not read; the `User-Agent` is the project's own.
7. The worker's database user cannot read or write the gateway tables; a test proves it.
8. Observed RED per behavior; pytest and ruff green locally and in CI; the new job is required; revisor-seguridad with no critical or high; threat model and BITACORA updated.

## TDD
Mode: strict, enabled (global user configuration). Runner: `uv run --locked pytest` in `services/worker-noticias`, against the local test Postgres `gw45-test-pg` (127.0.0.1:55432, `gateway_ci`, CI throwaway credentials) when the database is needed. Lint: `uv run --locked ruff check`, `uv run --locked ruff format --check`.

## Delivery
`single-pr`; forecast well above 400 authored lines (several tasks of 200-400). Gentle AI review per task commit. revisor-seguridad before the PR. Push and PR only on the person's request.

## Route
- T1-T6: one delegated writer per task (writer trigger: several non-trivial files).
- T7: delegated docs writer plus revisor-seguridad.

## Tasks
- [x] **T1** Skeleton `services/worker-noticias/` (pyproject with ruff `S` and pytest like the gateway, `uv.lock`), smoke test, CI job `worker-noticias` in `seguridad.yml` (pinned uv by sha256 like the gateway job), required check in `.github/rulesets/main.json`, Dependabot uv entry, ADR 0007 (own loop, no Celery).
- [ ] **T2** Hardened HTTP client (threats 21, 22): https only, fixed host list, no cross-host redirects, private/loopback/link-local/metadata IPs blocked after DNS resolution and connection pinned to the validated IP, timeouts, maximum size (decoded), retries with backoff.
- [ ] **T3** RSS and news-sitemap parsing with `defusedxml` (`forbid_dtd=True`) and normalization: plain trimmed text, https link on the outlet's own host, UTC date (threat 20).
- [ ] **T4** `robots.txt` (stdlib `urllib.robotparser`, fetched with the T2 client) and own `User-Agent`; a forbidden source is disabled and logged.
- [ ] **T5** Own Alembic migrations (own version table) and `news_items` table with a unique link; least-privilege DB role (`SELECT`/`INSERT` on its table, purge `DELETE`), test that it cannot reach the gateway tables; retention purge (threats 15, 17).
- [ ] **T6** Periodic loop with per-source isolation, status logs without content, manual command for a live run.
- [ ] **T7** Threat model 15/17/20/21/22, BITACORA, revisor-seguridad and fix round.
- [ ] **T8** Push and PR (person request only).

## Progress
- 2026-10-16: issue #60 created at the person's request; plan approved; branch `feat/60-worker-noticias` from `985b74f`. Dependencies verified on PyPI. T1 next.
- 2026-10-16: T1 done, delegated writer. Files: `services/worker-noticias/` (pyproject like the gateway, `uv.lock` with 10 packages, package docstring, `tests/test_smoke.py`: imports and `pyexpat.EXPAT_VERSION >= 2.7.2`), CI job `worker-noticias` (same pinned uv and checkout as the gateway), required check in `.github/rulesets/main.json`, Dependabot uv entry, ADR 0007. RED: `ModuleNotFoundError: No module named 'worker_noticias'` (1 failed, 1 passed; a first attempt passed because an empty `src/worker_noticias/` was a namespace package, so it was removed and rerun). GREEN: 2 passed; ruff check and format green. The writer found that `tests/rulesets/main_ruleset_test.sh` pins the exact required-check list (15 cases, 1 failed); the person authorized the edit and the parent updated it inline: 15 cases, 0 failed. Parent spot check: pytest 2 passed, ruff green. actionlint not installed locally (the CI `workflows` job runs it). Local uv 0.12.19, CI 0.12.21. Applying the ruleset on GitHub is a remote operation pending the person's request (after the merge, so the new check exists).
