# DEVELOPMENT AND CI ONLY. This policy exists so the tests can seed the one-shot
# bootstrap password at secret/bootstrap/admin. In production the responsible
# person writes that secret with their own credentials; no such role exists.
# It can create and update the secret and nothing else: no read, no delete, no
# list, no other path.
path "secret/data/bootstrap/admin" {
  capabilities = ["create", "update"]
}
