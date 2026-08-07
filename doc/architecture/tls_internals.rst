TLS Internals
=============

Overview
~~~~~~~~

In CCF, the :term:`TLS` layer is implemented using OpenSSL (3.3 or later).

TLS is terminated in the **connection layer**: OpenSSL owns the socket file descriptor directly. The existing host ``libuv`` loop reports file descriptor readiness, and a per-connection worker drives the non-blocking handshake, reads, writes and graceful close. Everything above the connection layer, including HTTP parsing and endpoint dispatch, only ever sees plaintext.

This document describes the connection layer and its interface to the session layer above it.

Layers
~~~~~~

A single RPC interface is served by these pieces:

- :ccf_repo:`OpenSSLServer </src/host/tls/openssl_server.h>` owns the listening and accepted sockets and registers ``uv_poll_t`` handles for them on the existing host loop. Each accepted connection holds an ``SSL`` object bound to its file descriptor with ``SSL_set_fd``. It emits decrypted bytes through an ``OnData`` callback and reports teardown through ``OnClose``.
- :ccf_repo:`OpenSSLSessionManager </src/host/tls/openssl_session_manager.h>` bridges the transport to the session layer. It lazily creates one ``ccf::Session`` per connection using a caller-supplied factory, and implements :ccf_repo:`ccf::SessionWriter </src/enclave/session_writer.h>` so that a session's outbound plaintext is handed back to the transport.
- :ccf_repo:`ccf::PlaintextSession </src/enclave/session.h>` is the base for the protocol sessions (:ccf_repo:`HTTPServerSession </src/http/http_session.h>`, :ccf_repo:`HTTP2ServerSession </src/http/http2_session.h>`). It receives plaintext, and emits plaintext through its ``SessionWriter``.
- :ccf_repo:`RPCConnectionManager </src/host/rpc_connection_manager.h>` owns one of these stacks per configured RPC interface, and holds the cross-interface policy: certificates, session caps, and metrics.

Because TLS lives below the session, there is no separate "encrypted session" type. The difference between a TLS interface and an ``UNSECURED`` one is a flag on the connection layer, not a different session class.

Note that the inbound and outbound paths are not symmetric. Inbound plaintext is pushed straight into the session, but a session cannot touch the socket: it hands bytes to a ``SessionWriter``, which queues them for the owning connection. This is what allows sessions to run on any worker thread while each socket is still only ever touched by one thread at a time.

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

Cryptographic policy
~~~~~~~~~~~~~~~~~~~~

The context restricts what the handshake may negotiate:

- TLS 1.2 is limited to four AES-GCM cipher suites, all with ECDHE key exchange and either ECDSA or RSA authentication.
- TLS 1.3 is limited to ``TLS_AES_256_GCM_SHA384`` and ``TLS_AES_128_GCM_SHA256``.
- The key exchange group list prefers the hybrid post-quantum groups ``SecP384r1MLKEM1024``, ``SecP256r1MLKEM768`` and ``X25519MLKEM768``, falling back to ``P-521``, ``P-384`` and ``P-256``. The hybrid groups are prefixed with ``?`` so that the list still loads on OpenSSL versions which do not implement them.
- Renegotiation is disabled, and session resumption on renegotiation with it, to avoid the associated denial-of-service vectors.
- Where a choice remains, the server's ordering wins over the client's.

Note that in TLS 1.3 the *client* effectively chooses the group: OpenSSL picks the first client-offered group that the server also supports, so the server list acts as a filter rather than a preference.

This policy is defined in one place, ``build_server_ctx()``. It is asserted from the wire by the ``openssl_server_test`` unit tests and, for a running service, by the :ccf_repo:`tls_groups </tests/tls_groups.py>` end-to-end test. Both only check the hybrid groups when built with ``-DTEST_HYBRID_TLS_GROUPS=ON``, since those groups require OpenSSL 3.5 or later.

The context also sets ``SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER`` and ``SSL_MODE_ENABLE_PARTIAL_WRITE``, both of which are required by the write path described below.

Client authentication
~~~~~~~~~~~~~~~~~~~~~

The server calls ``SSL_CTX_set_verify`` with ``SSL_VERIFY_PEER`` and an accept-all callback. This is deliberate: it makes the server *request* the client certificate during the handshake so that it is available for application-level caller authentication, without the TLS layer itself rejecting clients. Whether a certificate is required, and whether it is acceptable, is decided by the endpoint's authentication policy.

Reading
~~~~~~~

When ``libuv`` reports a connection readable, the loop hands the connection to its worker (see `Threading`_), which calls ``SSL_read`` repeatedly until it reports ``SSL_ERROR_WANT_READ``. Every chunk of decrypted bytes is passed to the ``OnData`` callback as it is produced, so a single readable event may yield several callbacks.

A single pass is capped at a fixed number of bytes so that one busy connection cannot monopolise its worker. Reaching that cap does not end the read: OpenSSL may still be holding buffered records, in which case the file descriptor is *not* readable and waiting for a further ``uv_poll`` event would stall the connection. The worker therefore reports ``SSL_has_pending()`` back to the loop, which immediately schedules another pass instead of re-arming ``UV_READABLE``. ``SSL_has_pending()`` rather than ``SSL_pending()``, because it also covers bytes which have been read off the socket but not yet processed into plaintext.

``OpenSSLSessionManager`` receives those bytes, finds or creates the session for that connection, and calls ``handle_incoming_data``. The session dispatches the actual parsing to its own ``OrderedTasks``, so neither the loop thread nor the connection worker blocks on application work.

``SSL_ERROR_WANT_WRITE`` on a read is not an error: a TLS 1.3 key update needs the socket to become writable, so the connection is left open with ``UV_WRITABLE`` armed. Any other result, whether a clean ``SSL_ERROR_ZERO_RETURN``, an unclean EOF, or a fatal error, closes the connection.

Inbound flow control
~~~~~~~~~~~~~~~~~~~~

How much the node reads is bounded by how far behind the application is. ``OpenSSLSessionManager`` charges every chunk it hands to a session against a node-wide budget, and releases it once the session reports that chunk processed. Because request execution happens inside the parse task, "processed" means the request has actually run, so the budget measures unexecuted work rather than merely unparsed bytes.

While the budget is exhausted, no interface arms ``UV_READABLE``. The sending client's own :term:`TCP` window then closes, and it cannot queue more work than the node can retire. Nothing is dropped or refused: reads simply pause and resume.

The budget is node-wide rather than per-connection, so a single connection can exhaust it and pause the others. That is deliberate: a per-connection limit would have to be smaller than one maximum-sized request before it could bound total node memory to the same figure.

Releasing the budget wakes every registered transport, not only the one whose session made room, so an interface with no traffic of its own does not stay paused. A session which never reports - a custom protocol, or one whose queued work is cancelled as it is destroyed - cannot strand the budget either: whatever is still outstanding for a connection is released when that connection is torn down.

A connection paused this way is performing no I/O, so it ages towards the idle timeout in the usual way. That is intentional: a connection which cannot make progress in either direction for the whole idle period is one the node is too far behind to serve.

Writing and backpressure
~~~~~~~~~~~~~~~~~~~~~~~~

``send()`` is thread-safe. It appends the plaintext to a queue guarded by a mutex and signals a ``uv_async_t``, waking the loop thread, which moves the bytes onto the target connection and schedules a worker pass to attempt the write.

Writes are where genuine backpressure appears. ``SSL_write`` on a non-blocking socket may report ``SSL_ERROR_WANT_WRITE`` after consuming only part of the buffer. The remainder stays buffered against the connection, ``UV_WRITABLE`` is armed, and the write resumes when the socket next becomes writable. Because the socket is owned by OpenSSL and is non-blocking, this reflects the real state of the :term:`TCP` send buffer rather than an internal approximation.

Closing
~~~~~~~

Closing is deferred rather than immediate. A close requested while output is still buffered sets a flag and flushes; the file descriptor is only closed once the buffered bytes have been written.

This matters because the common pattern is to write a response and immediately close. Closing eagerly truncates any response large enough to have been backpressured, which the client observes as a connection reset partway through the body rather than as a well-formed response.

Server shutdown is the exception: there the close is forced rather than deferred. Each connection takes exactly one further worker pass, writing whatever the socket will accept, and then goes. Waiting for the flush would let a peer which has stopped reading hold the whole node's shutdown open indefinitely.

Idle connections are closed separately. If an idle timeout is configured, a repeating ``uv_timer_t`` periodically sweeps connections whose last I/O is older than the timeout. This retains the once-per-second scheduling used by the previous RPC transport while comparing actual ``steady_clock`` timestamps rather than counting timer ticks.

Threading
~~~~~~~~~

``OpenSSLServer`` does not create a thread or a private reactor. It splits its work between the existing host ``libuv`` thread and the general task system, along a single dividing line:

- The **loop thread** owns everything that touches the server's own state: accepting connections, the connection and identifier maps, ``uv_poll_t`` registration, building and replacing the ``SSL_CTX``, sweeping idle connections, and finally closing file descriptors. It performs no ``SSL`` operations.
- Each connection owns an :ccf_repo:`OrderedTasks </src/tasks/ordered_tasks.h>` queue, and every ``SSL`` operation for that connection - ``SSL_new``, ``SSL_accept``, ``SSL_read``, ``SSL_write``, ``SSL_shutdown``, ``SSL_free`` - runs there, as does the ``OnData`` callback. This keeps handshakes and bulk encryption off the loop thread.

Work reaches the loop in one of two ways: file descriptor readiness reported through ``uv_poll_t``, or a cross-thread request (a queued write, a close, or a certificate update) posted to a mutex-guarded queue and signalled through ``uv_async_t``. Either way the loop only ever *schedules* a pass over the connection; it never performs the I/O itself.

A connection is serviced by at most one worker pass at a time. Before dispatching, the loop calls ``uv_poll_stop`` for that connection, so no second pass can be scheduled while one is running. Readiness events and cross-thread commands that arrive meanwhile accumulate in loop-thread-only fields and are handed to the next pass. When a pass finishes it posts its result back to the loop, which re-arms polling, schedules another pass if more work accumulated, or tears the connection down.

.. warning::

    OpenSSL's error queue is **thread-local**, and successive passes over the same connection may run on different worker threads. ``SSL_get_error`` consults that queue, so an error left behind by unrelated work on the same thread can be misattributed to this connection.

    Every ``SSL_accept``, ``SSL_read`` and ``SSL_write`` is therefore preceded by ``ERR_clear_error()``. Omitting this causes healthy keep-alive connections to be closed spuriously, because a stale error (for example a previous client disconnecting without ``close_notify``) is read as a fatal error on an unrelated connection.

Unsecured interfaces
~~~~~~~~~~~~~~~~~~~~

An interface configured as ``UNSECURED`` runs the same loop with no ``SSL`` object. Connections are immediately ready, and reads and writes use ``::recv`` and ``::send`` directly. The buffering, backpressure, graceful close and idle handling are identical, so the session layer above is unchanged.

Outbound connections
~~~~~~~~~~~~~~~~~~~~

``OpenSSLServer`` is inbound only. Outbound requests - fetching quote endorsements, refreshing JWT signing keys, and the recovery decision protocol - are made with libcurl, which does its own TLS.

The only remaining OpenSSL client helpers, :ccf_repo:`CA </src/clients/tls/ca.h>` and :ccf_repo:`Cert </src/clients/tls/cert.h>`, are used solely by the C++ test and perf clients in :ccf_repo:`src/clients </src/clients>`. No node code uses them.

Why OpenSSL?
~~~~~~~~~~~~

CCF originally used MbedTLS, and the OpenSSL implementation that replaced it emulated MbedTLS conventions, notably negated error codes and a memory-BIO indirection driven by callbacks.

Both are now gone. ``OpenSSLServer`` calls ``SSL_read``/``SSL_write`` on a socket-backed ``SSL`` and interprets ``SSL_get_error`` directly, and ``src/tls`` no longer exists.

The reasons for OpenSSL remain:

- OpenSSL is already used for the :doc:`cryptography </architecture/cryptography>` implementation in ``src/crypto``.
- TLS 1.3 support.
- A path to QUIC.

Future: QUIC
~~~~~~~~~~~~

QUIC is not yet implemented. Server-side QUIC requires OpenSSL 3.5 or later, which adds ``SSL_new_listener``, ``SSL_accept_connection`` and ``OSSL_QUIC_server_method``; these are absent from the 3.3.x baseline CCF currently supports.

:ccf_repo:`DatagramServer </src/host/datagram_server.h>` exists as the substrate for that work. It is deliberately shaped as the UDP socket a QUIC server operates on: socket creation, binding, ``uv_poll_t`` readiness and per-datagram dispatch are all reusable as-is. The points that change for QUIC are marked ``QUIC EXTENSION POINT`` inline, and consist of wrapping the socket with ``BIO_new_dgram``/``SSL_set_fd`` on a listener ``SSL``, adding the OpenSSL event timeout, and replacing the datagram callback with ``SSL_handle_events``.

Until then, an interface whose ``app_protocol`` is ``QUIC`` echoes each datagram straight back, statelessly. Other UDP interfaces are served by the custom protocol subsystem (:ccf_repo:`custom_protocol_subsystem_interface.h </include/ccf/research/custom_protocol_subsystem_interface.h>`) in the usual way, with one session per source address, swept on the same idle timeout as TCP connections.
