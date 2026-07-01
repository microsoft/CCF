# OpenSSL TLS Implementation

This is a TLS implementation using OpenSSL.

It used to emulate the previous MbedTLS implementation, but now that MbedTLS has
been removed it follows OpenSSL's native style.

## CAs and Certificates

In OpenSSL, session objects (`ssl`) are created from config objects (`cfg`) and
inherit all their properties. Because `Context` only handles a single session
per configuration, configuration is applied to both objects so that either can
be used safely.

### Validation

OpenSSL performs extensive certificate validation. The verification result is
queried via `SSL_get_verify_result`, and a verification failure during the
handshake is surfaced to the caller as a distinct status so it can be treated as
an authentication failure rather than a generic error.

## Context

### BIOs

The `Context` uses a pair of in-memory BIOs to exchange encrypted bytes with the
peer: the TLS layer reads ciphertext from the read BIO and writes ciphertext to
the write BIO.

`TLSSession` drives the I/O directly: it feeds bytes received from the ring
buffer into the read BIO (`Context::recv`) and drains the bytes the TLS layer
wants to send out of the write BIO (`Context::send`), forwarding them to the
ring buffer. There are no BIO callbacks.

### Reads and Writes

`Context::handshake`, `Context::read` and `Context::write` return `0` on success
and an OpenSSL `SSL_ERROR_*` status code otherwise (obtained from
`SSL_get_error`). The number of bytes read or written is returned separately
through an output parameter, so the return value is never overloaded to mean
both a byte count and an error.

The caller (`TLSSession`) inspects the status code to decide whether to wait for
more data (`SSL_ERROR_WANT_READ` / `SSL_ERROR_WANT_WRITE`), close the connection
(`SSL_ERROR_ZERO_RETURN`), or treat it as an error.
