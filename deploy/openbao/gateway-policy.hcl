# The gateway may only read its own keys (KV v2). Nothing else: no write,
# no list, no other paths.
path "secret/data/gateway/*" {
  capabilities = ["read"]
}
