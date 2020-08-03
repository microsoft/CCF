// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/messaging.h"
#include "timer.h"

namespace asynchost
{
  class LoadMonitorImpl
  {
    using TClock = std::chrono::system_clock;
    std::chrono::milliseconds last_update;

    messaging::Dispatcher<ringbuffer::Message>& dispatcher;

    std::fstream output_file;

  public:
    LoadMonitorImpl(messaging::Dispatcher<ringbuffer::Message>& disp) :
      dispatcher(disp)
    {
      dispatcher.retrieve_message_counts();
      last_update = std::chrono::duration_cast<std::chrono::milliseconds>(
        TClock::now().time_since_epoch());

      output_file.open("host_load.log", std::fstream::out);
    }

    void on_timer()
    {
      const auto message_counts = dispatcher.retrieve_message_counts();
      const auto time_now =
        std::chrono::duration_cast<std::chrono::milliseconds>(
          TClock::now().time_since_epoch());

      if (!message_counts.empty())
      {
        auto j = nlohmann::json::object();

        j["start_time_ms"] = last_update.count();
        j["end_time_ms"] = time_now.count();

        auto& messages = j["ringbuffer_messages"];
        for (const auto& it : message_counts)
        {
          messages[dispatcher.get_message_name(it.first)] = {
            {"count", it.second.messages}, {"bytes", it.second.bytes}};
        }

        const auto line = j.dump();
        output_file.write(line.data(), line.size());
        output_file << std::endl;

        last_update = time_now;
      }
    }
  };

  using LoadMonitor = proxy_ptr<Timer<LoadMonitorImpl>>;
}
