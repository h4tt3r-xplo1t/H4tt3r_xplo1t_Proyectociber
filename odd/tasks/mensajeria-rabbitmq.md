# mensajeria-rabbitmq

## Objective
Issue #67 (E3): deploy RabbitMQ for development and CI and make `worker-noticias` publish one notice per batch of new news items, with a safe message contract (ADR 0008), as the base for `worker-analisis` (#68). Threats 18, 19 and 33.

## Scope
- Allowed: `services/worker-noticias/**`; `docker-compose.yml`; `deploy/rabbitmq/**`; `.github/workflows/seguridad.yml` (RabbitMQ service in the `worker-noticias` job); `docs/adr/0008-*.md`; `docs/threat-model.md`, `docs/architecture/threat-model.json`; `docs/PROJECT_CONTEXT.md` (stack); `docs/BITACORA.md`, `docs/bitacora/**`; `odd/tasks/**`.
- Forbidden: `.claude/**`, `services/gateway/**`, real secrets, real requests to the outlets.
- Out of scope: `worker-analisis` (#68), gateway publication and `worker-tendencias`, in-cluster TLS (own ADR before E5), Kubernetes manifests (E5), Celery (ADR 0007).

## Decisions
- 2026-10-21 (person): split the broker work (#67) from `worker-analisis` (#68).
- 2026-10-21 (person): plan T1-T6 approved; start with the ADR 0008 draft.
- 2026-10-21 (person): after revisor-seguridad on PR 1 (M1 dead-lettering contradiction, B1 wrong Celery claim, B2 second-hand sources), the person approved correcting the ADR text before the push; decisions unchanged.
- 2026-10-21 (person): ADR 0008 accepted as drafted (ids-only payload, `pika` without Celery, PostgreSQL as source of truth with a periodic sweep in `worker-analisis`, per-service users, queue limits, strict JSON schema). The sweep adds scope to #68 (pending: note it on the issue, remote operation on request).

## Dependencies (verified 2026-10-21)
- `pika` 1.4.4 (PyPI JSON API via WebFetch; license, maintainers, Python 3.14 classifier and Production/Stable status re-read on 2026-10-21 from the installed wheel's `METADATA`, whose sha256 `uv.lock` verifies against PyPI): BSD-3-Clause; maintainers Gavin M. Roy, Luke Bakken; https://github.com/pika/pika; Production/Stable; Python 3.7-3.14 classifiers; no mandatory dependencies (gevent/tornado/twisted are extras). Releases 1.4.0 (2026-05-06), 1.4.1, 1.4.2, 1.4.4 (2026-08-06) after a gap since 1.3.2 (2023-05-05). Pure-Python AMQP 0-9-1. File hashes are pinned by `uv.lock` from PyPI when added in T3/T4.
- RabbitMQ `docker.io/library/rabbitmq:4.4.0-alpine` (official image, docker-library, no management plugin to reduce surface): index digest `sha256:61d004549357eff7c90187ebbc9fe6f1280b49c32099e16745b4087bfddf9edf`, confirmed locally with `docker buildx imagetools inspect` (amd64 manifest `sha256:2225c656...`, created 2026-10-21, source docker-library/rabbitmq `4ad2872`). Docker Hub API listed it via WebFetch with the same digest.
- RabbitMQ 4.4 docs (rabbitmq.com/docs/quorum-queues, /definitions; summaries via WebFetch): quorum queues support `drop-head` and `reject-publish` (not `reject-publish-dlx`); at-least-once dead-lettering requires `reject-publish`, so `drop-head` overflow is dead-lettered at-most-once; delivery limit defaults to 20 since 4.0; message TTL supported; boot-time definitions import does not create the default `guest` user or vhost; definitions carry users (password hashes), vhosts, permissions, policies, queues, exchanges, bindings. ADR 0008 updated with these facts (no decision change).

## Acceptance criteria (issue #67)
1. ADR 0008 approved by the person.
2. RabbitMQ starts in compose and CI without `guest`, with development-only credentials marked unusable.
3. A cycle with new items publishes a valid notice; a cycle without new items publishes nothing.
4. With the broker down, the source is reported as `broker_error`, the rest of the cycle continues and the rows are kept.
5. Tests reject a non-JSON message, an invalid-schema message and an oversized one.
6. A test proves publishing with another service's credentials is rejected (threat 18).
7. A test proves that with the queue full the policy applies: `drop-head` keeps the queue at its maximum and the dropped message is dead-lettered at-most-once to the dead-letter queue (threat 19; ADR 0008, reworded after revisor-seguridad M1 on 2026-10-21).
8. Observed RED, CI green, no network access to the outlets in tests (`no_network` guard).

## TDD
Mode: strict, enabled (global user configuration). Runner: `uv run --locked pytest` in `services/worker-noticias`. Lint: `uv run --locked ruff check`, `uv run --locked ruff format --check`. T1 (ADR) is documentation only: no RED applies.

## Delivery
Strategy `ask-on-risk` (default). Forecast: above 400 authored lines (T3-T5 of 150-300 each); the chain strategy is asked once when the running count passes ~400. Gentle AI assessment per task commit. revisor-seguridad before the PR. Push and PR only on the person's request.
- 2026-10-21 (person): chain strategy `stacked-to-main`, asked once when the running count reached ~866 lines (T1-T2 223, T3 646 incl. 11 generated `uv.lock`).
- Slices (each PR targets `main`; after a squash merge the next branch is rebased onto `main`; every PR says `Refs #67` except the last, `Closes #67`):
  1. PR 1, branch `docs/67-adr-mensajeria` at `587fcbb`: T1-T2 (ADR 0008 and verified facts), 223 lines.
  2. PR 2, branch `feat/67-mensajeria-rabbitmq`: T3 and its review follow-ups (T3b), ~680 lines. One slicing pass found no cohesive split (deploy files, init script, CI step and the tests that verify them form one unit; the 373 test lines stay with it), so `size:exception` is recommended for this PR.
  3. PR 3: T4 (message module).
  4. PR 4: T5 and T6 (publication, `broker_error`, docs); closes #67.

## Route
- T1: inline (one documentation file, decisions owned by the person).
- T2: inline read-only verification on official registries.
- T3-T5: one delegated writer per task (writer trigger: several non-trivial files).
- T6: delegated docs writer.

## Tasks
- [x] **T1** (`fa9bdf5`; Gentle AI passive) ADR 0008: message contract, exchange/queues, users and permissions, queue policy, delivery semantics, lost-notice handling. Accepted by the person.
- [x] **T2** Verify the RabbitMQ image (version, digest, official source) and the AMQP client (`pika` on PyPI: name, maintainer, license, activity). Evidence in "Dependencies".
- [x] **T3** (commit `feat(worker-noticias): rabbitmq for development and ci with least-privilege users (#67)`, sha in `git log`; Gentle AI T1-T2 docs `review-f32745e98f7cb60d` low, approved) RabbitMQ in `docker-compose.yml` and CI, definitions file (per-service users, per-queue permissions, no `guest`, max-length/TTL/dead-letter policy), integration tests skipped without a broker (threats 18, 19).
  - RED (2026-10-21): `test_rabbitmq_definitions.py` 10 tests failed/errored with `FileNotFoundError` (`deploy/rabbitmq/{definitions.json,rabbitmq.conf}` missing); `test_rabbitmq_integration.py` with `WORKER_NOTICIAS_TEST_AMQP_HOST=127.0.0.1` and no broker: 4 failed + 7 errors with `AMQPConnectionError` (the `guest` test passed vacuously without a broker; its real proof is GREEN against the broker).
  - GREEN: with the compose broker up, `uv run --locked pytest -q`: 348 passed, 32 skipped (only the database tests, `WORKER_NOTICIAS_TEST_ADMIN_URL` unset); two consecutive runs. Without the env var: 336 passed, 44 skipped; with `CI=true` and no var the broker tests fail; a non-loopback host is refused.
  - Finding: on RabbitMQ 4.4.0 `delivery-limit` does not count `basic.nack` with requeue; it counts a consumer disconnecting without settling. The test simulates a crashing consumer; documented in `deploy/rabbitmq/README.md`.
  - Design: limits as policies (not queue arguments); DLX is `fanout`.
  - Decision (person, 2026-10-21): gitleaks `generic-api-key` flagged the password hashes in `definitions.json`; the person chose an init script (`scripts/rabbitmq-dev-init.sh`, passwords from env, users and permissions created with `rabbitmqctl`, `guest` deleted) over a gitleaks allowlist. No password or hash is committed; CI uses `ci-only-throwaway-*` env values. A unit test parses the script's `set_permissions` lines against the ADR.
- [x] **T3b** (commit: see `git log`, `fix(worker-noticias): rabbitmq review follow-ups (#67)`) Non-blocking follow-ups of `review-a4758803d2bf902b`: fixed RabbitMQ `hostname` in compose (node data dir survives recreation), a `guest` test that proves rejection by authentication rather than any connection error, stale comments in `rabbitmq.conf` and `docker-compose.yml`, dead `_permissions` helper, named delivery-limit constant, `pipefail`-safe user lookup in the init script.
  - RED: `test_compose_pins_a_fixed_hostname_for_the_broker` failed (no `hostname`); without it, `docker compose up -d --force-recreate` left `list_users` empty (users lost); with `guest` present the new guest test failed with `DID NOT RAISE` (ProbableAuthenticationError, ProbableAccessDeniedError).
  - GREEN: with `hostname: rabbitmq`, after the init script and `--force-recreate` the three users are still listed without re-running it; init script run twice (exit 0) and removes a re-added `guest`; `pytest -q` with broker env: 347 passed, 32 skipped (database tests only), twice; ruff check/format pass; shell syntax check OK.
- [ ] **T4** Message module: encode and validate (JSON only, versioned schema, bounded size, no `pickle`) (threat 33), plus a lint or test guard that fails on any `pickle` use in the service (threat 33 test of the threat model: ruff `S301`/`S403` or a Semgrep rule).
- [ ] **T5** `store.save()` returns the new ids; `cycle.py` publishes after saving; `broker_error` isolation per source.
- [ ] **T6** Threat model, PROJECT_CONTEXT (stack) and BITACORA.

## Progress
- 2026-10-21: branch `feat/67-mensajeria-rabbitmq` from `origin/main` `2c7526c`. T1 and T2 done. T3 done.

## Next step
T4: message module (encode and validate), delegated writer.
