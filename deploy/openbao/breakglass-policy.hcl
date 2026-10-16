# The one-shot account recovery (python -m gateway.breakglass) may only read the
# seeded password and then destroy it. It cannot write, list, reach the gateway
# keys or the bootstrap secret, or use transit. The gateway and bootstrap roles
# get none of this (ADR 0004, decision 11).
path "secret/data/breakglass/account" {
  capabilities = ["read"]
}

# `metadata delete` of KV v2 removes every version and the metadata.
path "secret/metadata/breakglass/account" {
  capabilities = ["delete"]
}
