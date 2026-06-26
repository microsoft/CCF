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
  // Abstract output sink injected into Sessions: a Session hands its outbound
  // bytes (and connection-teardown requests) to a SessionWriter, which is
  // implemented by the host-side RPCConnectionManager.
  //
  // IMPORTANT: Sessions invoke these methods from worker threads (see
  // ccf::ThreadedSession / OrderedTasks), so implementations MUST be
  // thread-safe and must marshal any socket operations onto their I/O thread.
  class SessionWriter
  {
  public:
    virtual ~SessionWriter() = default;

    // Queue bytes to be written to the socket associated with `id`. For
    // datagram protocols, `addr` identifies the destination peer; it is ignored
    // for stream (TCP) connections. The bytes are copied, so the caller's
    // buffer can be reused immediately.
    //
    // Fire-and-forget: there is currently no backpressure signal.
    //
    // FUTURE: to surface genuine TCP-layer backpressure, an implementation
    // should report when a connection's pending-write queue exceeds a watermark
    // (tracking per-connection queued bytes) and return a writable/would-block
    // status here.
    virtual void write_outbound(
      ::tcp::ConnID id, std::span<const uint8_t> data, sockaddr addr = {}) = 0;

    // Tear down the connection: stop the underlying socket and drop the
    // session.
    virtual void close_socket(::tcp::ConnID id) = 0;
  };
}
