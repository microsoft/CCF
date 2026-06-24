// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "tcp/msg_types.h"

#include <cstdint>
#include <span>
#include <sys/socket.h>
#include <vector>

namespace ccf
{
  // Abstract output sink injected into Sessions.
  //
  // This replaces the per-session ringbuffer `to_host` writer that used to
  // carry outbound bytes (tcp_outbound) and lifecycle signals (tcp_closed /
  // tcp_stop) from the enclave back to the host. With the host/enclave split
  // removed, sessions instead hold a reference to a SessionWriter implemented
  // by the host-side RPCConnectionManager.
  //
  // IMPORTANT: Sessions invoke these methods from worker threads (see
  // ccf::ThreadedSession / OrderedTasks). Implementations MUST be thread-safe
  // and must marshal any libuv socket operations onto the loop thread (e.g. via
  // asynchost::LoopExecutorImpl), since libuv handles are not thread-safe.
  class SessionWriter
  {
  public:
    virtual ~SessionWriter() = default;

    // Queue bytes (already encrypted by the session's TLS layer, or plaintext
    // for unencrypted sessions) to be written to the socket associated with
    // `id`. For datagram protocols, `addr` identifies the destination peer; it
    // is ignored for stream (TCP) connections. The bytes are copied, so the
    // caller's buffer can be reused immediately.
    //
    // Fire-and-forget: there is currently no backpressure signal. The old
    // ringbuffer "buffer full" was not real network backpressure, so it is not
    // reproduced here.
    //
    // FUTURE: to surface genuine TCP-layer backpressure (so that e.g.
    // TLSSession::handle_send can return TLS_WRITING and let OpenSSL retry), an
    // implementation should report when a connection's pending-write queue
    // exceeds a watermark. The manager can track per-connection queued bytes
    // (incremented on enqueue here, decremented once the uv write completes)
    // and have this return a writable/would-block status.
    virtual void write_outbound(
      ::tcp::ConnID id, std::span<const uint8_t> data, sockaddr addr = {}) = 0;

    // Tear down the connection: stop the underlying socket and drop the
    // session. This single call replaces the old two-phase tcp_stop +
    // tcp_closed handshake, which existed only to reconcile the separate host
    // and enclave bookkeeping across the ringbuffer. With a single owner there
    // is no second party to notify, so one close is sufficient.
    virtual void close_socket(::tcp::ConnID id) = 0;
  };
}
