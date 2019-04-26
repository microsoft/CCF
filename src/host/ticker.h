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
    host::Enclave& enclave;
    std::chrono::time_point<std::chrono::steady_clock> last;

  public:
    TickerImpl(host::Enclave& enclave) :
      enclave(enclave),
      last(std::chrono::steady_clock::now())
    {}

    void on_timer()
    {
      auto next = std::chrono::steady_clock::now();
      auto elapsed =
        std::chrono::duration_cast<std::chrono::milliseconds>(next - last);
      last = next;
      enclave.tick(elapsed);
    }
  };

  using Ticker = proxy_ptr<Timer<TickerImpl>>;
}
