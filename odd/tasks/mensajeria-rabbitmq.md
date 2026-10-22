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
- [ ] **T1** ADR 0008: message contract, exchange/queues, users and permissions, queue policy, delivery semantics, lost-notice handling. Draft for the person's approval.
- [ ] **T2** Verify the RabbitMQ image (version, digest, official source) and the AMQP client (`pika` on PyPI: name, maintainer, license, activity).
- [ ] **T3** RabbitMQ in `docker-compose.yml` and CI, definitions file (per-service users, per-queue permissions, no `guest`, max-length/TTL/dead-letter policy), integration tests skipped without a broker (threats 18, 19).
- [ ] **T4** Message module: encode and validate (JSON only, versioned schema, bounded size, no `pickle`) (threat 33).
- [ ] **T5** `store.save()` returns the new ids; `cycle.py` publishes after saving; `broker_error` isolation per source.
- [ ] **T6** Threat model, PROJECT_CONTEXT (stack) and BITACORA.

## Progress
- 2026-10-21: branch `feat/67-mensajeria-rabbitmq` from `origin/main` `2c7526c`. T1 in progress.

## Next step
Person reviews and approves the ADR 0008 draft.
