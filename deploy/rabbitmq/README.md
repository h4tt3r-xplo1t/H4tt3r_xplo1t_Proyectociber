# RabbitMQ for development and CI

Broker configuration for ADR 0008 (`docs/adr/0008-contrato-mensajes-rabbitmq.md`).
Never use these files, users or passwords outside local development and CI.

- `rabbitmq.conf`: imports `definitions.json` at boot; AMQP only (no management plugin).
- `definitions.json`: vhost `h4tt3r`, exchanges, quorum queues, bindings and queue policies (no users).

## Starting it

No password or password hash is committed. The users are created from your
environment by `scripts/rabbitmq-dev-init.sh` (development/CI only):

```sh
export RABBITMQ_WORKER_NOTICIAS_PASSWORD=...   # throwaway value, never reuse
export RABBITMQ_WORKER_ANALISIS_PASSWORD=...
export RABBITMQ_ADMIN_PASSWORD=...             # tests only (purge/inspect queues)
export POSTGRES_USER=unused POSTGRES_PASSWORD=unused POSTGRES_DB=unused  # compose validates the whole file
docker compose up -d --wait rabbitmq
scripts/rabbitmq-dev-init.sh
```

The script is idempotent, sets the permissions of ADR 0008 and deletes
`guest`. The broker tests read the same three variables plus
`WORKER_NOTICIAS_TEST_AMQP_HOST=127.0.0.1`. In CI the job sets throwaway values
(`ci-only-throwaway-*`). Production values come from the secrets manager (E5).

Why not users in `definitions.json`: they would need committed password hashes,
which secret scanners (gitleaks) rightly flag; the person chose an init script
over an allowlist.

## Queue limits as policies

Limits are policies, not queue arguments: a policy can be tuned with real data
without deleting and redeclaring the queue, and the services never declare
queues. `overflow: drop-head` dead-letters the oldest message at most once; this
is accepted because PostgreSQL is the source of truth (ADR 0008).

`delivery-limit` (3) counts a delivery as failed when a consumer disconnects
without settling the message (for example a crash). Observed on RabbitMQ 4.4.0:
`basic.nack` with `requeue=true` is not counted, so a consumer that wants to
discard a bad message must reject it without requeue (it then goes to the
dead-letter queue).
