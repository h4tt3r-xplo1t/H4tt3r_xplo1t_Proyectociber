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
- 2026-10-21 (person): ADR 0008 accepted as drafted (ids-only payload, `pika` without Celery, PostgreSQL as source of truth with a periodic sweep in `worker-analisis`, per-service users, queue limits, strict JSON schema). The sweep adds scope to #68 (pending: note it on the issue, remote operation on request).

## Dependencies (verified 2026-10-21)
- `pika` 1.4.4 (PyPI JSON API via WebFetch): BSD-3-Clause; maintainers Gavin M. Roy, Luke Bakken; https://github.com/pika/pika; Production/Stable; Python 3.7-3.14 classifiers; no mandatory dependencies (gevent/tornado/twisted are extras). Releases 1.4.0 (2026-05-06), 1.4.1, 1.4.2, 1.4.4 (2026-08-06) after a gap since 1.3.2 (2023-05-05). Pure-Python AMQP 0-9-1. File hashes are pinned by `uv.lock` from PyPI when added in T3/T4.
- RabbitMQ `docker.io/library/rabbitmq:4.4.0-alpine` (official image, docker-library, no management plugin to reduce surface): index digest `sha256:61d004549357eff7c90187ebbc9fe6f1280b49c32099e16745b4087bfddf9edf`, confirmed locally with `docker buildx imagetools inspect` (amd64 manifest `sha256:2225c656...`, created 2026-10-21, source docker-library/rabbitmq `4ad2872`). Docker Hub API listed it via WebFetch with the same digest.
- RabbitMQ 4.4 docs (rabbitmq.com/docs/quorum-queues, /definitions; summaries via WebFetch): quorum queues support `drop-head` and `reject-publish` (not `reject-publish-dlx`); at-least-once dead-lettering requires `reject-publish`, so `drop-head` overflow is dead-lettered at-most-once; delivery limit defaults to 20 since 4.0; message TTL supported; boot-time definitions import does not create the default `guest` user or vhost; definitions carry users (password hashes), vhosts, permissions, policies, queues, exchanges, bindings. ADR 0008 updated with these facts (no decision change).

## Acceptance criteria (issue #67)
1. ADR 0008 approved by the person.
2. RabbitMQ starts in compose and CI without `guest`, with development-only credentials marked unusable.
3. A cycle with new items publishes a valid notice; a cycle without new items publishes nothing.
4. With the broker down, the source is reported as `broker_error`, the rest of the cycle continues and the rows are kept.
5. Tests reject a non-JSON message, an invalid-schema message and an oversized one.
6. A test proves publishing with another service's credentials is rejected (threat 18).
7. A test proves that with the queue full the policy applies and messages go to the dead-letter queue (threat 19).
8. Observed RED, CI green, no network access to the outlets in tests (`no_network` guard).

## TDD
Mode: strict, enabled (global user configuration). Runner: `uv run --locked pytest` in `services/worker-noticias`. Lint: `uv run --locked ruff check`, `uv run --locked ruff format --check`. T1 (ADR) is documentation only: no RED applies.

## Delivery
Strategy `ask-on-risk` (default). Forecast: above 400 authored lines (T3-T5 of 150-300 each); the chain strategy is asked once when the running count passes ~400. Gentle AI assessment per task commit. revisor-seguridad before the PR. Push and PR only on the person's request.

## Route
- T1: inline (one documentation file, decisions owned by the person).
- T2: inline read-only verification on official registries.
- T3-T5: one delegated writer per task (writer trigger: several non-trivial files).
- T6: delegated docs writer.

## Tasks
- [x] **T1** (`fa9bdf5`; Gentle AI passive) ADR 0008: message contract, exchange/queues, users and permissions, queue policy, delivery semantics, lost-notice handling. Accepted by the person.
- [x] **T2** Verify the RabbitMQ image (version, digest, official source) and the AMQP client (`pika` on PyPI: name, maintainer, license, activity). Evidence in "Dependencies".
- [ ] **T3** RabbitMQ in `docker-compose.yml` and CI, definitions file (per-service users, per-queue permissions, no `guest`, max-length/TTL/dead-letter policy), integration tests skipped without a broker (threats 18, 19).
- [ ] **T4** Message module: encode and validate (JSON only, versioned schema, bounded size, no `pickle`) (threat 33).
- [ ] **T5** `store.save()` returns the new ids; `cycle.py` publishes after saving; `broker_error` isolation per source.
- [ ] **T6** Threat model, PROJECT_CONTEXT (stack) and BITACORA.

## Progress
- 2026-10-21: branch `feat/67-mensajeria-rabbitmq` from `origin/main` `2c7526c`. T1 and T2 done.

## Next step
T3: RabbitMQ in compose and CI with the definitions file and integration tests (delegated writer).
