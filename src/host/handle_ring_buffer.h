// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "../ds/files.h"
#include "../enclave/interface.h"
#include "ccf/ds/logger.h"
#include "ds/non_blocking.h"
#include "self_healing_open.h"
#include "timer.h"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <nlohmann/json.hpp>
#include <string>
#include <sys/types.h>
#include <unistd.h>

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
    {
      // Register message handler for log message from enclave
      DISPATCHER_SET_MESSAGE_HANDLER(
        bp, AdminMessage::log_msg, [](const uint8_t* data, size_t size) {
          auto
            [log_time_us_count,
             file_name,
             line_number,
             log_level,
             tag,
             thread_id,
             msg] = ringbuffer::read_message<AdminMessage::log_msg>(data, size);

          ccf::logger::LogLine ll(
            log_level, tag, file_name.c_str(), line_number, thread_id);
          ll.msg = msg;

          // Represent offset as a real (counting seconds) to handle both small
          // negative _and_ positive numbers. Since the system clock used is not
          // monotonic, the offset we calculate could go in either direction,
          // and tm can't represent small negative values.
          std::optional<double> offset_time = std::nullopt;

          // If enclave doesn't know the
          // current time yet, don't try to produce an offset, just give them
          // the host's time (producing offset of 0)
          if (log_time_us_count != 0)
          {
            // Enclave time is recomputed every time. If multiple threads
            // log inside the enclave, offsets may not always increase
            const double enclave_time_s = log_time_us_count / 1'000'000.0;

            ::timespec ts;
            ::timespec_get(&ts, TIME_UTC);
            const double host_time_s =
              ts.tv_sec + (ts.tv_nsec / 1'000'000'000.0);

            offset_time = enclave_time_s - host_time_s;
          }

          auto& loggers = ccf::logger::config::loggers();
          for (auto const& logger : loggers)
          {
            logger->write(ll, offset_time);
          }
        });

      DISPATCHER_SET_MESSAGE_HANDLER(
        bp,
        AdminMessage::fatal_error_msg,
        [](const uint8_t* data, size_t size) {
          auto [msg] =
            ringbuffer::read_message<AdminMessage::fatal_error_msg>(data, size);

          std::cerr << msg << std::endl << std::flush;
          throw std::logic_error(msg);
        });

      DISPATCHER_SET_MESSAGE_HANDLER(
        bp, AdminMessage::stopped, [](const uint8_t*, size_t) {
          uv_stop(uv_default_loop());
          LOG_INFO_FMT("Host stopped successfully");
        });

      DISPATCHER_SET_MESSAGE_HANDLER(
        bp,
        AdminMessage::restart_and_join,
        [&](const uint8_t* data, size_t size) {
          auto [url, service_identity] = ringbuffer::read_message<AdminMessage::restart_and_join>(
            data, size);
          ccf::SelfHealingOpenSingleton::instance()->trigger_restart_and_join_url(url, service_identity);
        });
    }

    void on_timer()
    {
      // Regularly read (and process) some outbound ringbuffer messages...
      bp.read_n(max_messages, r);

      // ...flush any pending inbound messages...
      nbwf.flush_all_inbound();
    }
  };

  using HandleRingbuffer = proxy_ptr<Timer<HandleRingbufferImpl>>;
}
