// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "timer.h"

#include <chrono>

namespace asynchost
{
  class TickerImpl
  {
  private:
    ringbuffer::WriterPtr to_enclave;
    std::chrono::time_point<std::chrono::system_clock> last;

  public:
    TickerImpl(ringbuffer::AbstractWriterFactory& writer_factory) :
      to_enclave(writer_factory.create_writer_to_inside()),
      last(std::chrono::system_clock::now())
    {}

    void on_timer()
    {
      RINGBUFFER_WRITE_MESSAGE(AdminMessage::tick, to_enclave);
    }
  };

  using Ticker = proxy_ptr<Timer<TickerImpl>>;
}
