// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "../ds/files.h"
#include "../enclave/interface.h"
#include "ds/internal_logger.h"
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
        bp, AdminMessage::restart, [&](const uint8_t*, size_t) {
          ccf::SelfHealingOpenRBHandlerSingleton::instance()->trigger_restart();
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
