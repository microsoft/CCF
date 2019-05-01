// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "enclave.h"
#include "timer.h"

#include <chrono>

namespace asynchost
{
  class TickerImpl
  {
  private:
    std::unique_ptr<ringbuffer::AbstractWriter> to_enclave;
    std::chrono::time_point<std::chrono::steady_clock> last;

  public:
    TickerImpl(ringbuffer::AbstractWriterFactory& writer_factory) :
      to_enclave(writer_factory.create_writer_to_inside()),
      last(std::chrono::steady_clock::now())
    {}

    void on_timer()
    {
      auto next = std::chrono::steady_clock::now();
      auto elapsed =
        std::chrono::duration_cast<std::chrono::milliseconds>(next - last);
      last = next;

      RINGBUFFER_WRITE_MESSAGE(
        AdminMessage::tick, to_enclave, (size_t)elapsed.count());
    }
  };

  using Ticker = proxy_ptr<Timer<TickerImpl>>;
}
