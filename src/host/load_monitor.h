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
    std::chrono::milliseconds last_update{};

    messaging::Dispatcher<ringbuffer::Message>& dispatcher;

    nlohmann::json enclave_counts;

  public:
    LoadMonitorImpl(messaging::BufferProcessor& bp) :
      dispatcher(bp.get_dispatcher())
    {
      dispatcher.retrieve_message_counts();
      last_update = std::chrono::duration_cast<std::chrono::milliseconds>(
        TClock::now().time_since_epoch());

      enclave_counts = nlohmann::json::object();

      // Register message handler for work_stats message from enclave
      DISPATCHER_SET_MESSAGE_HANDLER(
        bp, AdminMessage::work_stats, [this](const uint8_t* data, size_t size) {
          auto [dumped_json] =
            ringbuffer::read_message<AdminMessage::work_stats>(data, size);

          nlohmann::json j;
          try
          {
            j = nlohmann::json::parse(dumped_json);
          }
          catch (const nlohmann::json::parse_error& e)
          {
            LOG_FAIL_FMT("Received unparseable work_stats from enclave");
            return;
          }

          for (const auto& [outer_key, outer_value] : j.items())
          {
            for (const auto& [inner_key, inner_value] : outer_value.items())
            {
              auto& outer_obj = enclave_counts[outer_key];
              auto it = outer_obj.find(inner_key);
              if (it == outer_obj.end())
              {
                outer_obj[inner_key] = inner_value;
              }
              else
              {
                const auto prev = it.value().get<size_t>();
                outer_obj[inner_key] = prev + inner_value.get<size_t>();
              }
            }
          }
        });
    }

    void on_timer()
    {
      if (ccf::logger::config::level() <= ccf::LoggerLevel::DEBUG)
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

          {
            j["ringbuffer_messages"] =
              dispatcher.convert_message_counts(message_counts);

            LOG_DEBUG_FMT("Host load: {}", j.dump());
          }

          {
            j["ringbuffer_messages"] = enclave_counts;
            enclave_counts = nlohmann::json::object();

            LOG_DEBUG_FMT("Enclave load: {}", j.dump());
          }

          last_update = time_now;
        }
      }
    }
  };

  using LoadMonitor = proxy_ptr<Timer<LoadMonitorImpl>>;
}
