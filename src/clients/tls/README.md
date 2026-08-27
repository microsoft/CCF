# TLS certificate helpers (client tooling only)

These helpers configure an OpenSSL client with a trusted root and an owned
identity:

- `CA` parses one or more root certificates and populates an `SSL_CTX`'s
  trusted certificate store.
- `Cert` holds a client's own certificate and private key, and applies them
  (and the peer verification mode) to an `SSL_CTX` or `SSL`.

Their only consumer is `TlsClient` in the parent directory, used by the C++
test and perf clients. **No node code uses them.** The node's inbound TLS is
handled by `src/host/tls`, which builds its own `SSL_CTX`, and its outbound
requests go through libcurl.
