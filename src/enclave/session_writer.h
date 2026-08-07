// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/node/session.h"
#include "tcp/msg_types.h"

#include <cstdint>
#include <vector>

namespace ccf
{
  // Abstract output sink injected into Sessions: a Session hands its outbound
  // bytes (and connection-teardown requests) to a SessionWriter, which is
  // implemented by the RPC transport.
  //
  // IMPORTANT: Sessions may invoke these methods from worker threads, so
  // implementations MUST be thread-safe and must marshal any socket operations
  // onto their I/O thread if required.
  class SessionWriter
  {
  public:
    virtual ~SessionWriter() = default;

    // Queue bytes to be written to the socket associated with `id`. Ownership
    // is transferred, so that a response which may be arbitrarily large is
    // moved through to the transport rather than copied again.
    //
    // Fire-and-forget: there is currently no backpressure signal.
    //
    // FUTURE: to surface genuine TCP-layer backpressure, an implementation
    // should report when a connection's pending-write queue exceeds a watermark
    // (tracking per-connection queued bytes) and return a writable/would-block
    // status here.
    virtual void write_outbound(
      ::tcp::ConnID id, std::vector<uint8_t>&& data) = 0;

    // Tear down the connection: stop the underlying socket and drop the
    // session.
    virtual void close_socket(::tcp::ConnID id) = 0;

    // Report that `bytes` of previously delivered inbound data have now been
    // processed. The transport uses this to decide when it may read more: it
    // stops reading once the node is holding more unprocessed inbound data
    // than it is willing to, and resumes as sessions catch up. Without it a
    // client could make the node queue work faster than it retires it, for as
    // long as it liked.
    //
    // A session which does not report is not penalised beyond its own
    // connection - the transport releases whatever is still outstanding when
    // the connection closes - so this defaults to a no-op.
    virtual void inbound_consumed(::tcp::ConnID /*id*/, size_t /*bytes*/) {}
  };
}
