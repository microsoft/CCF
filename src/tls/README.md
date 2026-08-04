# TLS certificate helpers

This directory holds the two certificate helpers used to configure OpenSSL
objects with a trusted root and an owned identity:

- `CA` parses one or more root certificates and populates an `SSL_CTX`'s
  trusted certificate store.
- `Cert` holds an endpoint's own certificate and private key, and applies them
  (and the peer verification mode) to an `SSL_CTX` or `SSL`.

They are used by outbound connections, by the JS `isValidX509CertChain` API,
and by the test clients in `src/clients`.

The TLS transport itself lives in `src/host/tls`. See
`doc/architecture/tls_internals.rst` for how it works.
