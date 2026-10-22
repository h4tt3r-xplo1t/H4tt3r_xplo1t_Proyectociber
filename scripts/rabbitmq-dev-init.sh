#!/usr/bin/env bash
# DEVELOPMENT AND CI ONLY. Never use this script for a shared or production
# broker: it creates an administrator with full access to the vhost.
#
# Creates the RabbitMQ users of ADR 0008 on the service from docker-compose.yml
# and removes `guest`. Idempotent: an existing user only gets a new password,
# tags and permissions. The vhost, exchanges, queues and policies come from
# deploy/rabbitmq/definitions.json, imported by the broker at boot.
#
# Passwords come from the environment, with no defaults, and are never printed:
#   RABBITMQ_WORKER_NOTICIAS_PASSWORD  user worker_noticias (publisher)
#   RABBITMQ_WORKER_ANALISIS_PASSWORD  user worker_analisis (consumer)
#   RABBITMQ_ADMIN_PASSWORD            user h4tt3r_admin (tests only)
#
# Limitation: rabbitmqctl takes the password as an argument, not from stdin.
# It is passed to the container by variable name (-e NAME), so it never appears
# in the host's docker command line, and expanded by a shell inside the
# container; it is visible there in the process list of rabbitmqctl for the
# fraction of a second the command runs. Acceptable for a throwaway dev/CI
# broker on loopback.
set -euo pipefail

: "${RABBITMQ_WORKER_NOTICIAS_PASSWORD:?set RABBITMQ_WORKER_NOTICIAS_PASSWORD (dev/CI throwaway value)}"
: "${RABBITMQ_WORKER_ANALISIS_PASSWORD:?set RABBITMQ_WORKER_ANALISIS_PASSWORD (dev/CI throwaway value)}"
: "${RABBITMQ_ADMIN_PASSWORD:?set RABBITMQ_ADMIN_PASSWORD (dev/CI throwaway value)}"

cd "$(dirname "${BASH_SOURCE[0]}")/.."

rmq() { docker compose exec -T rabbitmq rabbitmqctl --quiet "$@"; }

user_exists() { rmq list_users --silent | cut -f1 | grep -qxF -- "$1"; }

# ensure_user <user> <password variable name> <tags>
ensure_user() {
  local user=$1 variable=$2 tags=$3
  if user_exists "$user"; then
    docker compose exec -T -e "$variable" rabbitmq sh -c \
      "rabbitmqctl --quiet change_password \"\$0\" \"\$$variable\"" "$user"
  else
    docker compose exec -T -e "$variable" rabbitmq sh -c \
      "rabbitmqctl --quiet add_user \"\$0\" \"\$$variable\"" "$user"
  fi
  # shellcheck disable=SC2086 # $tags is empty or a single word on purpose
  rmq set_user_tags "$user" $tags
}

ensure_user worker_noticias RABBITMQ_WORKER_NOTICIAS_PASSWORD ""
ensure_user worker_analisis RABBITMQ_WORKER_ANALISIS_PASSWORD ""
ensure_user h4tt3r_admin RABBITMQ_ADMIN_PASSWORD "administrator"

# configure, write, read (ADR 0008). The unit tests parse these lines.
rmq set_permissions -p h4tt3r worker_noticias '^$' '^noticias$' '^$'
rmq set_permissions -p h4tt3r worker_analisis '^$' '^$' '^analisis\.noticias$'
rmq set_permissions -p h4tt3r h4tt3r_admin '.*' '.*' '.*'

if user_exists guest; then
  rmq delete_user guest
fi

echo "RabbitMQ users ready: worker_noticias, worker_analisis, h4tt3r_admin (guest removed)."
