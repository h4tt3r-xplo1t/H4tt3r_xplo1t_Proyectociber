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
#   setup-complete  marker written after every first-setup step succeeded
#
# Recovery: if the setup is interrupted after init, the root token is gone.
# For a disposable dev stack run `docker compose down -v`, delete the files in
# .local/openbao and run this script again.
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
# Revoke the root token and prove it. Proof means OpenBao itself answered the
# lookup with an explicit denial (HTTP 403 "permission denied"). Any other
# failure (docker, network, sealed server) proves nothing, so it counts as
# "not verified" and fails. A root token left alive is threat 42.
# Returns 0 only when revocation is proven; the EXIT trap calls it again as a
# best-effort safety net and turns a failure into a non-zero exit.
revoke_root() {
  [[ -n "$ROOT_TOKEN" ]] || return 0
  local out
  if ! BAO_TOKEN="$ROOT_TOKEN" bao token revoke -self >/dev/null 2>&1; then
    echo "ERROR: the root token revoke call failed (or it was already revoked); verify by hand" >&2
    return 1
  fi
  if out=$(BAO_TOKEN="$ROOT_TOKEN" bao token lookup 2>&1); then
    echo "ERROR: the root token is still valid; revoke it by hand" >&2
    return 1
  fi
  if [[ "$out" != *"Code: 403"* || "$out" != *"permission denied"* ]]; then
    echo "ERROR: could not verify the root token revocation (no explicit permission-denied answer from OpenBao); check it by hand" >&2
    return 1
  fi
  ROOT_TOKEN=""
  unset BAO_TOKEN
}
trap 'revoke_root || exit 1' EXIT

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
  printf '%s' "$INIT_JSON" |
    python3 -c 'import json,sys; sys.stdout.write(json.load(sys.stdin)["unseal_keys_b64"][0])' \
      >"$STATE_DIR/unseal-key"
  ROOT_TOKEN=$(printf '%s' "$INIT_JSON" |
    python3 -c 'import json,sys; sys.stdout.write(json.load(sys.stdin)["root_token"])')
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

# Raft elects itself leader a moment after unsealing; mutating calls before
# that fail or hit a standby. Wait (bounded) until this node is the active one.
LEADER=false
for _ in $(seq 1 30); do
  CURRENT=$(bao_status)
  if [[ -n "$CURRENT" && "$(status_field sealed <<<"$CURRENT")" == "false" &&
    "$(status_field is_self <<<"$CURRENT")" == "true" ]]; then
    LEADER=true
    break
  fi
  sleep 1
done
[[ "$LEADER" == "true" ]] || { echo "OpenBao did not become the active (leader) node within 30 s" >&2; exit 1; }

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

  revoke_root || exit 1
  echo "Root token revoked (lookup with it answers 403 permission denied)"

  # Written only after every step above succeeded, root revocation proof
  # included: its absence marks a partial setup even when role-id and
  # secret-id already exist, so a root token left alive is never "set up".
  : >"$STATE_DIR/setup-complete"
else
  if [[ ! -s "$STATE_DIR/role-id" || ! -s "$STATE_DIR/secret-id" || ! -e "$STATE_DIR/setup-complete" ]]; then
    echo "Setup is incomplete and the root token is gone. Disposable stack: docker compose down -v, remove the files in $STATE_DIR, rerun. Otherwise generate a root token with 'bao operator generate-root'." >&2
    exit 1
  fi
  echo "Already set up: nothing to do"
fi

chmod 600 "$STATE_DIR"/*
echo "OpenBao ready (unsealed). Credentials are in $STATE_DIR"
