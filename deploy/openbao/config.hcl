# OpenBao server configuration for LOCAL DEVELOPMENT AND CI only.
# Server mode with persistent storage (not -dev), so the seal/unseal and
# policy behaviour matches what the gateway will meet elsewhere.

ui = false

# The "file" backend no longer exists in OpenBao 2.7; single-node integrated
# storage (raft) is the persistent option without extra services.
storage "raft" {
  path    = "/openbao/file"
  node_id = "dev-1"
}

# TLS is disabled on purpose and only inside the container network: the
# internal-TLS decision is a pending ADR (threat model, flows 28 and 29).
# docker-compose.yml publishes the port on 127.0.0.1 only.
listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

# Where the server tells clients to find it (single node, no clustering).
api_addr     = "http://127.0.0.1:8200"
cluster_addr = "http://127.0.0.1:8201"
