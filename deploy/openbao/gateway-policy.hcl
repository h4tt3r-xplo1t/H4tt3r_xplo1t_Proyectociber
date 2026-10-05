# The gateway may only read its own keys (KV v2) and use the `totp` transit key
# to encrypt and decrypt TOTP secrets. Nothing else: no write to KV, no list,
# no other paths, no read or rotation of the transit key itself.
path "secret/data/gateway/*" {
  capabilities = ["read"]
}

path "transit/encrypt/totp" {
  capabilities = ["update"]
}

path "transit/decrypt/totp" {
  capabilities = ["update"]
}
