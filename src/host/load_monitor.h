// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/messaging.h"
#include "timer.h"

namespace asynchost
{
  class LoadMonitorImpl
  {
    using TClock = std::chrono::high_resolution_clock;
    TClock::time_point start_time;
    TClock::duration last_update = {};

    messaging::Dispatcher<ringbuffer::Message>& dispatcher;

  public:
    LoadMonitorImpl(messaging::Dispatcher<ringbuffer::Message>& disp) :
      dispatcher(disp)
    {
      dispatcher.retrieve_message_counts();
      start_time = TClock::now();
    }

    void on_timer()
    {
      const auto message_counts = dispatcher.retrieve_message_counts();
      const auto duration_now = TClock::now() - start_time;

      if (!message_counts.empty())
      {
        std::string formatted;
        for (const auto& it : message_counts)
        {
          if (!formatted.empty())
          {
            formatted += ", ";
          }

          formatted += fmt::format(
            "{}={}", dispatcher.get_message_name(it.first), it.second);
        }

        LOG_INFO_FMT(
          "Outbound messages from {} to {}: {}",
          std::chrono::duration_cast<std::chrono::milliseconds>(last_update)
            .count(),
          std::chrono::duration_cast<std::chrono::milliseconds>(duration_now)
            .count(),
          formatted);

        last_update = duration_now;
      }
    }
  };

  using LoadMonitor = proxy_ptr<Timer<LoadMonitorImpl>>;
}
