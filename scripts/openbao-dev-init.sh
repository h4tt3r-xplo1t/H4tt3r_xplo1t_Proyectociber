#!/usr/bin/env bash
# DEVELOPMENT AND CI ONLY. Never use this script for a shared or production
# OpenBao: it keeps a single unseal key on disk and uses one key share.
#
# Initialises, unseals and configures the OpenBao service from
# docker-compose.yml. Idempotent: every run unseals if needed, and the
# one-time setup (KV v2, AppRole, policy, keys) happens only on the first
# run, when the root token exists. The root token is held in a shell variable,
# never written to disk, and revoked before the script ends.
#
# State, kept under .local/openbao (git-ignored, directory 0700, files 0600):
#   unseal-key  to unseal after a restart
#   role-id     AppRole role_id of the gateway
#   secret-id   AppRole secret_id of the gateway (no expiry in dev)
#
# Recovery: if the setup is interrupted after init, the root token is gone.
# For a disposable dev stack run `docker compose down -v`, delete .local/openbao
# and run this script again.
set -euo pipefail
umask 077

cd "$(dirname "${BASH_SOURCE[0]}")/.."
STATE_DIR=.local/openbao
mkdir -p "$STATE_DIR"
chmod 700 .local "$STATE_DIR"

# BAO_TOKEN is passed by name (-e BAO_TOKEN), so it never appears in the
# docker command line.
bao() { docker compose exec -T -e BAO_TOKEN openbao bao "$@"; }
bao_status() { bao status -format=json 2>/dev/null || true; }
status_field() { python3 -c 'import json,sys; print(str(json.load(sys.stdin)[sys.argv[1]]).lower())' "$1"; }

unset BAO_TOKEN
ROOT_TOKEN=""
revoke_root() {
  if [[ -n "$ROOT_TOKEN" ]]; then
    BAO_TOKEN="$ROOT_TOKEN" bao token revoke -self >/dev/null 2>&1 || true
    ROOT_TOKEN=""
    unset BAO_TOKEN
  fi
}
trap revoke_root EXIT

# Wait until the API answers (an uninitialised or sealed server still answers).
for _ in $(seq 1 30); do
  [[ -n "$(bao_status)" ]] && break
  sleep 1
done
STATUS=$(bao_status)
[[ -n "$STATUS" ]] || { echo "OpenBao is not reachable: run 'docker compose up -d --wait openbao'" >&2; exit 1; }

FIRST_SETUP=false
if [[ "$(status_field initialized <<<"$STATUS")" == "false" ]]; then
  echo "Initialising OpenBao (1 key share, development only)"
  INIT_JSON=$(bao operator init -key-shares=1 -key-threshold=1 -format=json)
  python3 -c 'import json,sys; sys.stdout.write(json.load(sys.stdin)["unseal_keys_b64"][0])' \
    <<<"$INIT_JSON" >"$STATE_DIR/unseal-key"
  ROOT_TOKEN=$(python3 -c 'import json,sys; sys.stdout.write(json.load(sys.stdin)["root_token"])' <<<"$INIT_JSON")
  INIT_JSON=""
  FIRST_SETUP=true
fi

if [[ "$(status_field sealed <<<"$(bao_status)")" == "true" ]]; then
  [[ -s "$STATE_DIR/unseal-key" ]] || { echo "OpenBao is sealed and $STATE_DIR/unseal-key is missing" >&2; exit 1; }
  echo "Unsealing OpenBao"
  # The CLI has no stdin mode for the key: it goes in through stdin to a shell
  # inside the container, so it never reaches the host command line.
  docker compose exec -T openbao sh -c 'bao operator unseal "$(cat)"' \
    <"$STATE_DIR/unseal-key" >/dev/null
fi

if [[ "$FIRST_SETUP" == "true" ]]; then
  export BAO_TOKEN="$ROOT_TOKEN"
  echo "First setup: KV v2, AppRole, policy and keys"
  bao secrets enable -path=secret -version=2 kv >/dev/null
  bao auth enable approle >/dev/null
  bao policy write gateway - <deploy/openbao/gateway-policy.hcl >/dev/null
  # secret_id_ttl=0: the dev secret_id never expires, so there is no re-issue
  # path to maintain; the policy still limits it to reading gateway keys.
  bao write auth/approle/role/gateway \
    token_policies=gateway token_ttl=15m token_max_ttl=1h \
    secret_id_ttl=0 secret_id_num_uses=0 >/dev/null
  bao read -field=role_id auth/approle/role/gateway/role-id >"$STATE_DIR/role-id"
  bao write -f -field=secret_id auth/approle/role/gateway/secret-id >"$STATE_DIR/secret-id"

  # Keys are created only if absent, and read from stdin (key=-) so they are
  # never on a command line or in the output.
  if ! bao kv get -mount=secret gateway/jwt >/dev/null 2>&1; then
    openssl rand -base64 32 | tr -d '\n' |
      bao kv put -mount=secret gateway/jwt "kid=$(openssl rand -hex 8)" key=- >/dev/null
  fi
  if ! bao kv get -mount=secret gateway/csrf >/dev/null 2>&1; then
    openssl rand -base64 32 | tr -d '\n' |
      bao kv put -mount=secret gateway/csrf key=- >/dev/null
  fi

  revoke_root
  echo "Root token revoked"
else
  if [[ ! -s "$STATE_DIR/role-id" || ! -s "$STATE_DIR/secret-id" ]]; then
    echo "Setup is incomplete and the root token is gone. Disposable stack: docker compose down -v, rm -r .local/openbao, rerun. Otherwise generate a root token with 'bao operator generate-root'." >&2
    exit 1
  fi
  echo "Already set up: nothing to do"
fi

chmod 600 "$STATE_DIR"/*
echo "OpenBao ready (unsealed). Credentials are in $STATE_DIR"
