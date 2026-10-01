// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/non_blocking.h"
#include "timer.h"

namespace asynchost
{
  class HandleRingbufferImpl
  {
  private:
    // Maximum number of outbound ringbuffer messages which will be processed in
    // a single iteration
    static constexpr size_t max_messages = 256;

    messaging::BufferProcessor& bp;
    ringbuffer::Reader& r;
    ringbuffer::NonBlockingWriterFactory& nbwf;

  public:
    HandleRingbufferImpl(
      messaging::BufferProcessor& bp,
      ringbuffer::Reader& r,
      ringbuffer::NonBlockingWriterFactory& nbwf) :
      bp(bp),
      r(r),
      nbwf(nbwf)
    {}

    void on_timer()
    {
      // Regularly read (and process) some outbound ringbuffer messages...
      bp.read_n(max_messages, r);

      // ...flush any pending inbound messages...
      nbwf.flush_all_inbound();
    }
  };

  using HandleRingbuffer = ccf::uv::proxy_ptr<Timer<HandleRingbufferImpl>>;
}
