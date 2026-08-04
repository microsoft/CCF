TLS Internals
=============

Overview
~~~~~~~~

In CCF, the :term:`TLS` layer is implemented using OpenSSL (3.3 or later).

TLS is terminated in the **connection layer**: OpenSSL owns the socket file descriptor directly, and a local ``epoll`` loop drives the non-blocking handshake, reads, writes, graceful close and idle connection cleanup. Everything above the connection layer, including HTTP parsing and endpoint dispatch, only ever sees plaintext.

This document describes the connection layer and the seam between it and the session layer, to facilitate further changes.

Layers
~~~~~~

A single RPC interface is served by these pieces:

- :ccf_repo:`OpenSSLServer </src/host/tls/openssl_server.h>` owns the listening socket, one ``epoll`` instance, and one loop thread. Each accepted connection holds an ``SSL`` object bound to its file descriptor with ``SSL_set_fd``. It emits decrypted bytes through an ``OnData`` callback and reports teardown through ``OnClose``.
- :ccf_repo:`OpenSSLSessionManager </src/host/tls/openssl_session_manager.h>` bridges the transport to the session layer. It lazily creates one ``ccf::Session`` per connection using a caller-supplied factory, and implements :ccf_repo:`ccf::SessionWriter </src/enclave/session_writer.h>` so that a session's outbound plaintext is handed back to the transport.
- :ccf_repo:`ccf::PlaintextSession </src/enclave/session.h>` is the base for the protocol sessions (:ccf_repo:`HTTPServerSession </src/http/http_session.h>`, :ccf_repo:`HTTP2ServerSession </src/http/http2_session.h>`). It receives plaintext, and emits plaintext through its ``SessionWriter``.
- :ccf_repo:`RPCConnectionManager </src/host/rpc_connection_manager.h>` owns one of these stacks per configured RPC interface, and holds the cross-interface policy: certificates, session caps, and metrics.

Because TLS lives below the session, there is no separate "encrypted session" type. The difference between a TLS interface and an ``UNSECURED`` one is a flag on the connection layer, not a different session class.

Note that the inbound and outbound paths are not symmetric. Inbound plaintext is pushed straight into the session, but a session cannot touch the socket: it hands bytes to a ``SessionWriter``, which queues them for the loop thread. This is what allows sessions to run on worker threads while all socket I/O stays on one thread per interface.

Listening
~~~~~~~~~

The listening socket is resolved with ``getaddrinfo`` (rather than ``inet_pton``) so that interfaces can be configured with hostnames such as ``localhost`` and with IPv6 addresses, not only IPv4 literals. ``SO_REUSEADDR`` is set, so that a port left in ``TIME_WAIT`` by a previous process can be rebound on restart.

``SO_REUSEPORT`` is deliberately not set. There is one listener per interface, so it would buy nothing today, and it would weaken two useful properties: a second node misconfigured onto the same port would bind successfully instead of failing with ``EADDRINUSE``, with connections then split between the two at random; and any process running with the same effective UID could bind the same port and siphon off a share of inbound connections. If per-worker listeners are added later, it should be enabled explicitly for that case rather than unconditionally.

After binding, the actually bound port is read back with ``getsockname``. This supports configuring port ``0`` to request an ephemeral port, which the test infrastructure relies on, and is why resolved addresses are only known once the interface is listening.

Certificates
~~~~~~~~~~~~

An interface starts listening before its certificate is necessarily known. A joining node, for example, only obtains the service certificate once its join request has been accepted. ``OpenSSLServer`` therefore accepts an empty certificate at construction, and refuses TLS connections until one is supplied.

``set_server_cert()`` may be called from any thread. It does not build the ``SSL_CTX`` inline: it queues the request and wakes the loop, so the context is only ever created or replaced on the loop thread. This avoids locking the context on the hot path. Replacing the context affects only subsequent connections; existing connections keep the context they were created with, which OpenSSL keeps alive by reference counting.

The server context sets a minimum version of TLS 1.2 and, when the interface is configured for HTTP/2, advertises ``h2`` via ALPN.

Two certificate helpers remain in ``src/tls``:

- :ccf_repo:`CA </src/tls/ca.h>` holds a root certificate and can populate a trusted certificate store.
- :ccf_repo:`Cert </src/tls/cert.h>` holds an endpoint's own certificate and private key, and configures an ``SSL`` object with them.

These are used for outbound connections and by node startup code, not by the inbound server path.

Cryptographic policy
~~~~~~~~~~~~~~~~~~~~

The context restricts what the handshake may negotiate:

- TLS 1.2 is limited to four AES-GCM cipher suites, all with ECDHE key exchange and either ECDSA or RSA authentication.
- TLS 1.3 is limited to ``TLS_AES_256_GCM_SHA384`` and ``TLS_AES_128_GCM_SHA256``.
- The key exchange group list prefers the hybrid post-quantum groups ``SecP384r1MLKEM1024``, ``SecP256r1MLKEM768`` and ``X25519MLKEM768``, falling back to ``P-521``, ``P-384`` and ``P-256``. The hybrid groups are prefixed with ``?`` so that the list still loads on OpenSSL versions which do not implement them.
- Renegotiation is disabled, and session resumption on renegotiation with it, to avoid the associated denial-of-service vectors.
- Where a choice remains, the server's ordering wins over the client's.

Note that in TLS 1.3 the *client* effectively chooses the group: OpenSSL picks the first client-offered group that the server also supports, so the server list acts as a filter rather than a preference.

The same policy is applied by :ccf_repo:`ccf::tls::Context </src/tls/context.h>` for the remaining non-RPC TLS users, and the two must be kept in sync. It is asserted from the wire by the ``openssl_server_test`` unit tests and by the :ccf_repo:`tls_groups </tests/tls_groups.py>` end-to-end test, both of which only check the hybrid groups when built with ``-DTEST_HYBRID_TLS_GROUPS=ON``, since those groups require OpenSSL 3.5 or later.

The context also sets ``SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER`` and ``SSL_MODE_ENABLE_PARTIAL_WRITE``, both of which are required by the write path described below.

Client authentication
~~~~~~~~~~~~~~~~~~~~~

The server calls ``SSL_CTX_set_verify`` with ``SSL_VERIFY_PEER`` and an accept-all callback. This is deliberate: it makes the server *request* the client certificate during the handshake so that it is available for application-level caller authentication, without the TLS layer itself rejecting clients. Whether a certificate is required, and whether it is acceptable, is decided by the endpoint's authentication policy.

Reading
~~~~~~~

When ``epoll`` reports a connection readable, the loop calls ``SSL_read`` repeatedly until it reports ``SSL_ERROR_WANT_READ``. Every chunk of decrypted bytes is passed to the ``OnData`` callback as it is produced, so a single readable event may yield several callbacks.

``OpenSSLSessionManager`` receives those bytes, finds or creates the session for that connection, and calls ``handle_incoming_data``. The session dispatches the actual parsing to a worker via ``OrderedTasks``, so the loop thread does not block on application work.

``SSL_ERROR_WANT_WRITE`` on a read is not an error: a TLS 1.3 key update needs the socket to become writable, so the connection is left open with ``EPOLLOUT`` armed. Any other result, whether a clean ``SSL_ERROR_ZERO_RETURN``, an unclean EOF, or a fatal error, closes the connection.

Writing and backpressure
~~~~~~~~~~~~~~~~~~~~~~~~

``send()`` is thread-safe. It appends the plaintext to a queue guarded by a mutex and signals an ``eventfd``, waking the loop thread, which drains the queue and attempts the write.

Writes are where genuine backpressure appears. ``SSL_write`` on a non-blocking socket may report ``SSL_ERROR_WANT_WRITE`` after consuming only part of the buffer. The remainder stays buffered against the connection, ``EPOLLOUT`` is armed, and the write resumes when the socket next becomes writable. Because the socket is owned by OpenSSL and is non-blocking, this reflects the real state of the :term:`TCP` send buffer rather than an internal approximation.

Closing
~~~~~~~

Closing is deferred rather than immediate. A close requested while output is still buffered sets a flag and flushes; the file descriptor is only closed once the buffered bytes have been written.

This matters because the common pattern is to write a response and immediately close. Closing eagerly truncates any response large enough to have been backpressured, which the client observes as a connection reset partway through the body rather than as a well-formed response.

Idle connections are closed separately. If an idle timeout is configured, the loop uses a finite ``epoll_wait`` timeout and periodically sweeps connections whose last I/O is older than the timeout.

Threading
~~~~~~~~~

Each ``OpenSSLServer`` runs exactly one loop thread, and all socket and ``SSL`` operations happen on it. Work reaches that thread in one of two ways: file descriptor readiness reported by ``epoll``, or a cross-thread request (a queued write, a close, or a certificate update) posted to a queue and signalled through an ``eventfd``.

.. warning::

    OpenSSL's error queue is **thread-local**, and one loop thread services every connection on an interface. ``SSL_get_error`` consults that queue, so an error left behind by one connection can be misattributed to the next operation on a completely different connection.

    Every ``SSL_accept``, ``SSL_read`` and ``SSL_write`` is therefore preceded by ``ERR_clear_error()``. Omitting this causes healthy keep-alive connections to be closed spuriously, because a stale error (for example a previous client disconnecting without ``close_notify``) is read as a fatal error on an unrelated connection.

Unsecured interfaces
~~~~~~~~~~~~~~~~~~~~

An interface configured as ``UNSECURED`` runs the same loop with no ``SSL`` object. Connections are immediately ready, and reads and writes use ``::recv`` and ``::send`` directly. The buffering, backpressure, graceful close and idle handling are identical, so the session layer above is unchanged.

Outbound connections
~~~~~~~~~~~~~~~~~~~~

Outbound connections use a non-blocking ``connect`` followed by a client handshake driven by the same loop. The caller supplies a callback that configures the client ``SSL`` object, which is where peer CA verification, the client certificate and SNI are applied via ``tls::Cert``.

Why OpenSSL?
~~~~~~~~~~~~

CCF originally used MbedTLS, and the OpenSSL implementation that replaced it emulated MbedTLS conventions, notably negated error codes and a memory-BIO indirection driven by callbacks.

MbedTLS itself is long gone, and the inbound server path no longer goes anywhere near that emulation: ``OpenSSLServer`` calls ``SSL_read``/``SSL_write`` on a socket-backed ``SSL`` and interprets ``SSL_get_error`` directly. The emulation layer itself, however, still exists in :ccf_repo:`src/tls/context.h </src/tls/context.h>` (``TLS_ERR_WANT_READ`` and friends in :ccf_repo:`src/tls/tls.h </src/tls/tls.h>` are negated OpenSSL error codes, and ``set_bio()`` installs callback-driven memory BIOs). ``ccf::tls::Context`` and its ``Client``, ``Server`` and ``PlaintextServer`` subclasses are now reachable only from the ``tls_test`` unit test, and are candidates for removal.

The reasons for OpenSSL remain:

- OpenSSL is already used for the :doc:`cryptography </architecture/cryptography>` implementation in ``src/crypto``.
- TLS 1.3 support.
- A path to QUIC.

Future: QUIC
~~~~~~~~~~~~

QUIC is not yet implemented. Server-side QUIC requires OpenSSL 3.5 or later, which adds ``SSL_new_listener``, ``SSL_accept_connection`` and ``OSSL_QUIC_server_method``; these are absent from the 3.3.x baseline CCF currently supports.

:ccf_repo:`DatagramServer </src/host/datagram_server.h>` exists as the substrate for that work. It is deliberately shaped as the UDP socket a QUIC server operates on: socket creation, binding, the ``epoll`` loop and the per-datagram dispatch are all reusable as-is. The points that change for QUIC are marked ``QUIC EXTENSION POINT`` inline, and consist of wrapping the socket with ``BIO_new_dgram``/``SSL_set_fd`` on a listener ``SSL``, and replacing the datagram callback with ``SSL_handle_events``.

Until then, a UDP interface uses a built-in datagram echo session.
