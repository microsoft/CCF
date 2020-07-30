// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/messaging.h"
#include "timer.h"

namespace asynchost
{
  class MessageCounterImpl
  {
    using TClock = std::chrono::high_resolution_clock;
    TClock::time_point last_update;

    messaging::Dispatcher<ringbuffer::Message>& dispatcher;

    std::map<size_t, std::string> message_names;

  public:
    MessageCounterImpl(messaging::Dispatcher<ringbuffer::Message>& disp) :
      dispatcher(disp)
    {
      dispatcher.retrieve_message_counts();
      last_update = TClock::now();
    }

    void on_timer()
    {
      const auto message_counts = dispatcher.retrieve_message_counts();
      const auto now = TClock::now();

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
          "Outbound messages between {} and {}: {}",
          last_update.time_since_epoch().count(),
          now.time_since_epoch().count(),
          formatted);

        last_update = now;
      }
    }
  };

  using MessageCounter = proxy_ptr<Timer<MessageCounterImpl>>;
}
