TLS Internals
=============

Overview
~~~~~~~~

In CCF, the :term:`TLS` layer is implemented using OpenSSL (3.3 or later).

TLS is terminated in the **connection layer**: OpenSSL uses the socket file descriptor directly.
The existing host ``libuv`` loop reports file descriptor readiness, and a per-connection worker drives the non-blocking handshake, reads, writes and graceful close.
Everything above the connection layer, including HTTP parsing and endpoint dispatch, only ever sees plaintext.

This document describes the connection layer and its interface to the session layer above it.

Layers
~~~~~~

A single RPC interface is served by these pieces:

- :ccf_repo:`OpenSSLServer </src/tls/openssl_server.h>` owns the listener, server TLS context policy, certificate rotation, and accept-time admission.
  It hands accepted sockets to its connection engine and preserves the RPC-facing API.
- :ccf_repo:`OpenSSLConnectionEngine </src/tls/openssl_connection_engine.h>` owns connected sockets and their ``uv_poll_t`` handles on the existing host loop.
  Each TLS connection holds an ``SSL`` object bound to its file descriptor with ``SSL_set_fd``.
  The engine emits decrypted bytes through ``OnData`` and reports teardown through ``OnClose``.
- :ccf_repo:`OpenSSLSessionManager </src/node/rpc/openssl_session_manager.h>` bridges the transport to the session layer. It lazily creates one ``ccf::Session`` per connection using a caller-supplied factory, and implements :ccf_repo:`ccf::SessionWriter </include/ccf/node/session.h>` so that a session's outbound plaintext is handed back to the transport.
- :ccf_repo:`ccf::PlaintextSession </src/node/rpc/session.h>` is the base for the protocol sessions (:ccf_repo:`HTTPServerSession </src/node/rpc/http_session.h>`, :ccf_repo:`HTTP2ServerSession </src/node/rpc/http2_session.h>`). It receives plaintext, and emits plaintext through its ``SessionWriter``.
- :ccf_repo:`RPCConnectionManager </src/node/rpc/rpc_connection_manager.h>` owns one of these stacks per configured RPC interface, and holds the cross-interface policy: certificates, session caps, and metrics.

Because TLS lives below the session, there is no separate "encrypted session" type. The difference between a TLS interface and an ``UNSECURED`` one is a flag on the connection layer, not a different session class.

Initiating connections use :ccf_repo:`OpenSSLClient </src/tls/openssl_client.h>` rather than ``OpenSSLServer``.
Both compose the same connection engine; neither inherits the other's establishment machinery.
The server and engine contain no outbound resolver, address-candidate retry state, or dialing timers.
The client does not bind or create a listening socket at construction or startup.

Note that the inbound and outbound paths are not symmetric. Inbound plaintext is pushed straight into the session, but a session cannot touch the socket: it hands bytes to a ``SessionWriter``, which queues them for the owning connection. This is what allows sessions to run on any worker thread while each socket is still only ever touched by one thread at a time.

Listening
~~~~~~~~~

The listening socket is resolved with ``getaddrinfo`` (rather than ``inet_pton``) so that interfaces can be configured with hostnames such as ``localhost`` and with IPv6 addresses, not only IPv4 literals. ``SO_REUSEADDR`` is set, so that a port left in ``TIME_WAIT`` by a previous process can be rebound on restart.

``SO_REUSEPORT`` is deliberately not set. There is one listener per interface, so it would buy nothing today, and it would weaken two useful properties: a second node misconfigured onto the same port would bind successfully instead of failing with ``EADDRINUSE``, with connections then split between the two at random; and any process running with the same effective UID could bind the same port and siphon off a share of inbound connections. If per-worker listeners are added later, it should be enabled explicitly for that case rather than unconditionally.

After binding, the actually bound port is read back with ``getsockname``. This supports configuring port ``0`` to request an ephemeral port, which the test infrastructure relies on, and is why resolved addresses are only known once the interface is listening.

Initiating connections
~~~~~~~~~~~~~~~~~~~~~~

``OpenSSLClient::connect()`` initiates TLS connections through the shared engine.
It returns a connection id immediately (see below for when it does not), queues asynchronous ``uv_getaddrinfo`` resolution of the destination and optional source address, binds a matching local address when requested, and tries the resolved TCP candidates with non-blocking sockets.
TLS handshake failures and admission rejection terminate the attempt rather than retrying another address.

``ConnectConfig::per_phase_timeout`` bounds each establishment phase separately: destination resolution, source resolution when requested, each TCP address candidate, and the TLS handshake.
When a candidate times out, the client falls back to the next address.
It is not an overall deadline: an attempt with several address candidates can take a multiple of this value before its close notification.

The client owns each resolution/connect attempt until TCP establishment succeeds.
It then transfers the connected socket, poll handle, TLS context, handshake timeout, and queued output to the engine.
The engine takes exclusive responsibility for TLS establishment and subsequent I/O, worker scheduling, buffering, and teardown.
The client and server each stop their own establishment resources through the engine's loop-side shutdown callback before the engine drains connected sockets.

The owner supplies an already configured client-capable ``SSL_CTX`` and retains responsibility for protocol versions, trust anchors, certificate verification and peer identity policy.
The context must not be mutated while in use.
``connect()`` fails closed on a context which would not authenticate the peer: it throws unless the context sets ``SSL_VERIFY_PEER`` and its store holds at least one trusted certificate.
OpenSSL client contexts otherwise default to ``SSL_VERIFY_NONE``, which completes the handshake with any certificate.
This check cannot detect a verification callback which overrides failures; such a callback remains the owner's responsibility.
The engine does not impose N2N policy on RPC: RPC retains its existing TLS configuration.
This foundation does not activate N2N endpoints or route messages.

``Config::on_handshake`` is optional and applies to both accepted and initiating TLS connections.
It runs once on a connection worker after TLS establishment, with a borrowed ``SSL`` and a direction flag.
Returning false rejects the connection before any application reads or queued writes.
Without a hook, successful TLS establishment admits the connection as before.
Callbacks must not throw or block waiting for engine shutdown.

Initiating connections use the same worker scheduling, buffers, ``send()``, ``OnData``, and ``OnClose`` as accepted connections.
Each id returned by ``connect()`` receives exactly one close notification, including failed or cancelled attempts.
``connect()`` returns no id, and no close notification follows, if the client has not been started or is stopping.
This is an expected outcome rather than an error, so ``connect()`` is safe to call from ``OnClose``, including the close notifications delivered during shutdown.
``close_connection()`` cancels establishment without flushing pending application data; after establishment it retains the normal flush-before-close behavior.
For initiating connections, the loop's cancellation and the worker's entry into handshake admission atomically claim the establishment state.
If cancellation wins, a concurrently completing TLS handshake cannot invoke admission or perform application I/O.
If admission wins, including a close issued by the admission callback itself, close retains flush-before-close behavior.
Shutdown cancels outstanding resolution and connect attempts.
Resolver requests retain their own callback storage and a weak reference to the client, so even a late completion after client destruction can safely free its result without accessing the client or engine.
When stopping without a running loop, the caller must eventually drain the loop before closing it to reclaim outstanding libuv requests and handles.

An optional ``tcp_user_timeout`` sets Linux ``TCP_USER_TIMEOUT`` on accepted sockets (in ``Config``) or an initiating socket (in ``ConnectConfig``).
It bounds how long transmitted data can remain unacknowledged or blocked by a zero receive window, independently of the application's idle timeout.
Leaving it unset preserves the operating system defaults, including existing RPC behavior.

Opt-in traffic-key policy
~~~~~~~~~~~~~~~~~~~~~~~~~

The internal ``Config::traffic_key_policy`` option on the shared engine, server and client enables :ccf_repo:`TrafficKeyPolicy </src/tls/traffic_keys.h>` for both accepted and initiating connections.
It requires TLS 1.3 with AES-GCM, without changing the supplied context or the owner's certificate and admission policy.
It is unset by default, preserving RPC behavior, and neither activates N2N endpoints nor adds an operator configuration option.

OpenSSL implements the standard TLS 1.3 `KeyUpdate protocol <https://docs.openssl.org/3.3/man3/SSL_key_update/>`_, but does not automatically initiate record-usage-based updates for ordinary TLS connections.
The engine counts encrypted records separately by direction through OpenSSL's `record callbacks <https://docs.openssl.org/3.3/man3/SSL_CTX_set_msg_callback/>`_, including KeyUpdate under the old key, rather than counting application messages or I/O calls.
The internal ``record_budget`` field defaults to 2^20 records and accepts values from 2 through 2^24, below the AES-GCM limit in RFC 8446 section 5.5.
Tests configure eight records through the same field.
Each sender reserves a record for its own KeyUpdate.
The engine does not periodically request peer updates: it closes without delivering plaintext from the first record beyond the receive budget if the peer fails to update.

The engine schedules updates only between ordinary TLS I/O operations, leaving OpenSSL to derive keys, transmit KeyUpdate and handle peer-requested responses.
OpenSSL may defer a requested response until the next application write, as permitted by TLS 1.3.
The existing ordered workers and readable/writable polling handle I/O retries, without a separate update-driving state machine.
Policy reads yield after control records, allowing a pending write to finish before processing further peer updates that could require another write.
For every TLS connection, read interest is also withheld while an ``SSL_read`` is blocked writing a response such as a peer-requested KeyUpdate, because that read cannot progress until the socket is writable and level-triggered readability would only spin.
A write which would begin with a KeyUpdate is started only once the socket polls writable, because OpenSSL cannot read application data until a started update has been written.
Reads continue while such a write waits, so two peers whose updates fall due on full sockets drain each other regardless of kernel buffer sizes.
An OpenSSL input-buffer BIO holds at most 64 KiB of ciphertext per opted-in connection.
Should the writes of started updates nevertheless block on both peers, the worker can fill that buffer without processing TLS, freeing socket space without violating the pending-write retry contract.
Application reads still obey inbound admission, buffered input is scheduled without requiring a new socket event, and outgoing ciphertext is written directly to the socket.
Each pass reads a bounded amount and then writes at most one record, so a continuously active sender cannot indefinitely delay responses, and output does not wait for the node to admit input which the connection has already buffered.
The sent prefix of a connection's output buffer is released as each such pass ends, so the memory it holds follows what remains to be sent rather than what has been sent.
Control messages which OpenSSL has already read when it yields are processed by a bounded number of further read attempts, because the socket will not report them again.
Application reads remain subject to inbound admission, and existing flush-before-close and forced-shutdown behavior is retained.

Opt-in queued output bound
~~~~~~~~~~~~~~~~~~~~~~~~~~

The internal ``Config::max_queued_output`` option on the shared engine, server and client bounds, in bytes, the output accepted for one connection and not yet written.
It is unset by default, leaving RPC behavior unchanged, and is not an operator configuration option.
A send which would take a connection beyond its bound closes that connection without flushing and discards its queued output.
A peer which stops reading therefore holds at most the bound, rather than an amount set by how much its owner goes on sending.
The bound must be at least as large as the largest burst an owner sends before the engine can write, including any single message.
The bound is enforced as each send is made, on whichever thread makes it, rather than when the loop later processes that send.
A client connection is charged from the moment ``connect()`` returns its id, so output sent while it is still being established counts towards the same bound, and that charge carries over when the connection is adopted.
Output sent to an id which is neither being established nor adopted, such as a connection which has closed or one still inside ``OnAccept``, is discarded as it is sent rather than held until the loop can drop it.
Workers report what they wrote as each pass completes, so the count may briefly overstate, but never understates, what a connection holds.
A send made just after earlier output was written can therefore still be counted alongside it, so the bound needs headroom over what an owner expects to have outstanding.

Trace capture
~~~~~~~~~~~~~

A build configured with ``-DCCF_TLS_TRACING=ON`` compiles test-only hooks into the engine, which record each worker pass over an established connection that has a traffic-key policy.
:ccf_repo:`tests/tls_trace_validation.py` replays those records through the Lean model of the engine; see :doc:`/architecture/verification`.
The hooks only read connection state, and are absent from normal builds.

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

Admission rechecks use the same mutex as queued responses and worker completions. This matters with ``uv_async_t`` notification coalescing on libuv versions before 1.53: the loop clears libuv's pending bit before entering its callback, but an unsynchronised sender could still observe its previous value and skip a notification. In the reduced ordering, the callback could clear the admission flag before a worker sets it, the worker could acquire the lifecycle lock and send, and the callback could acquire the lifecycle lock only later. These shared acquisitions may overlap; making the sender's lock exclusive would still leave the callback's later acquisition too late to order the worker's earlier read of libuv's pending bit with the clear. With the queue mutex, either the worker publishes the recheck before the callback drains it, or the callback releases the mutex before the worker publishes and sends. In the latter case, the pending-bit clear happens before the sender reads it. The separate lifecycle lock continues to protect the async handle during shutdown.

A connection paused this way is performing no I/O, so it ages towards the idle timeout in the usual way. That is intentional: a connection which cannot make progress in either direction for the whole idle period is one the node is too far behind to serve.

Writing and backpressure
~~~~~~~~~~~~~~~~~~~~~~~~

``send()`` is thread-safe. It appends the plaintext to a queue guarded by a mutex and signals a ``uv_async_t``, waking the loop thread, which moves the bytes onto the target connection and schedules a worker pass to attempt the write.

Writes are where genuine backpressure appears. ``SSL_write`` on a non-blocking socket may report ``SSL_ERROR_WANT_WRITE`` after consuming only part of the buffer. The remainder stays buffered against the connection, ``UV_WRITABLE`` is armed, and the write resumes when the socket next becomes writable. Because the socket is owned by OpenSSL and is non-blocking, this reflects the real state of the :term:`TCP` send buffer rather than an internal approximation.

Closing
~~~~~~~

Closing is deferred rather than immediate. A close requested while output is still buffered sets a flag and flushes; the file descriptor is only closed once the buffered bytes have been written.

This matters because the common pattern is to write a response and immediately close. Closing eagerly truncates any response large enough to have been backpressured, which the client observes as a connection reset partway through the body rather than as a well-formed response.

Server shutdown and idle expiry are exceptions: there the close is forced rather than deferred. Each connection takes exactly one further worker pass, writing whatever the socket will accept, and then goes. Waiting for the flush would let a peer which has stopped reading hold the whole node's shutdown open, or retain an expired connection, indefinitely.

Idle connections are closed separately. If an idle timeout is configured, a repeating ``uv_timer_t`` periodically sweeps connections whose last I/O is older than the timeout. This retains the once-per-second scheduling used by the previous RPC transport while comparing actual ``steady_clock`` timestamps rather than counting timer ticks.

Threading
~~~~~~~~~

``OpenSSLServer``, ``OpenSSLClient`` and their shared ``OpenSSLConnectionEngine`` do not create a thread or a private reactor.
They split their work between the existing host ``libuv`` thread and the general task system, along a single dividing line:

- The **loop thread** owns everything that touches transport state: accepting connections (server), resolving and dialing addresses (client), the connection and identifier maps, ``uv_poll_t`` registration, building and replacing the server ``SSL_CTX``, sweeping idle connections and establishment deadlines, and finally closing file descriptors.
  It performs no ``SSL`` operations.
- Each connection owns an :ccf_repo:`OrderedTasks </src/tasks/ordered_tasks.h>` queue, and every ``SSL`` operation for that connection - ``SSL_new``, ``SSL_do_handshake``, ``SSL_read``, ``SSL_write``, ``SSL_shutdown``, ``SSL_free`` - runs there, as do the ``OnHandshake`` and ``OnData`` callbacks.
  This keeps handshakes and bulk encryption off the loop thread.

Work reaches the loop in one of two ways: file descriptor readiness reported through ``uv_poll_t``, or a cross-thread request (a queued write, a close, or a certificate update) posted to a mutex-guarded queue and signalled through ``uv_async_t``. Either way the loop only ever *schedules* a pass over the connection; it never performs the I/O itself.

A connection is serviced by at most one worker pass at a time. Before dispatching, the loop calls ``uv_poll_stop`` for that connection, so no second pass can be scheduled while one is running. Readiness events and cross-thread commands that arrive meanwhile accumulate in loop-thread-only fields and are handed to the next pass. When a pass finishes it posts its result back to the loop, which re-arms polling, schedules another pass if more work accumulated, or tears the connection down.

.. warning::

    OpenSSL's error queue is **thread-local**, and successive passes over the same connection may run on different worker threads. ``SSL_get_error`` consults that queue, so an error left behind by unrelated work on the same thread can be misattributed to this connection.

    Every ``SSL_do_handshake``, ``SSL_read`` and ``SSL_write`` is therefore preceded by ``ERR_clear_error()``.
    Omitting this causes healthy keep-alive connections to be closed spuriously, because a stale error (for example a previous client disconnecting without ``close_notify``) is read as a fatal error on an unrelated connection.

Unsecured interfaces
~~~~~~~~~~~~~~~~~~~~

An interface configured as ``UNSECURED`` runs the same loop with no ``SSL`` object. Connections are immediately ready, and reads and writes use ``::recv`` and ``::send`` directly. The buffering, backpressure, graceful close and idle handling are identical, so the session layer above is unchanged.

Outbound connections
~~~~~~~~~~~~~~~~~~~~

``OpenSSLServer`` is inbound only.
``OpenSSLClient`` (see `Initiating connections`_) is the outbound counterpart built on the same connection engine, but no node component uses it yet.
Existing outbound requests - fetching quote endorsements, refreshing JWT signing keys, and the recovery decision protocol - are made with libcurl, which does its own TLS.

The former ``CA`` and ``Cert`` OpenSSL client helpers were removed along with the last C++ clients that used them.
``OpenSSLClient`` does not reintroduce them: its owner supplies an already configured ``SSL_CTX``.

Why OpenSSL?
~~~~~~~~~~~~

CCF originally used MbedTLS, and the OpenSSL implementation that replaced it emulated MbedTLS conventions, notably negated error codes and a memory-BIO indirection driven by callbacks.

Both are now gone.
The connection engine calls ``SSL_read``/``SSL_write`` on a socket-backed ``SSL`` and interprets ``SSL_get_error`` directly.

The reasons for OpenSSL remain:

- OpenSSL is already used for the :doc:`cryptography </architecture/cryptography>` implementation in ``src/crypto``.
- TLS 1.3 support.
- A path to QUIC.

Future: QUIC
~~~~~~~~~~~~

QUIC is not yet implemented. Server-side QUIC requires OpenSSL 3.5 or later, which adds ``SSL_new_listener``, ``SSL_accept_connection`` and ``OSSL_QUIC_server_method``; these are absent from the 3.3.x baseline CCF currently supports.

:ccf_repo:`DatagramServer </src/tls/datagram_server.h>` exists as the substrate for that work. It is deliberately shaped as the UDP socket a QUIC server operates on: socket creation, binding, ``uv_poll_t`` readiness and per-datagram dispatch are all reusable as-is. The points that change for QUIC are marked ``QUIC EXTENSION POINT`` inline, and consist of wrapping the socket with ``BIO_new_dgram``/``SSL_set_fd`` on a listener ``SSL``, adding the OpenSSL event timeout, and replacing the datagram callback with ``SSL_handle_events``.

There is no built-in ``QUIC`` application protocol or UDP echo service. UDP interfaces are served only by registered custom protocols (:ccf_repo:`custom_protocol_subsystem_interface.h </include/ccf/research/custom_protocol_subsystem_interface.h>`), with one session per source address, swept on the same idle timeout as TCP connections.

UDP listeners bind exclusively: configuring two listeners on the same address and port fails rather than silently redirecting datagrams between them. Unlike TCP, UDP has no ``TIME_WAIT`` state, so rebinding after shutdown does not require ``SO_REUSEADDR``.
