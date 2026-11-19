TLS connections now retry sending `close_notify` when socket backpressure delays graceful closure, preventing peers from reporting an unexpected EOF after receiving all application data.
See [TLS connection closing](doc/architecture/tls_internals.rst#closing).
