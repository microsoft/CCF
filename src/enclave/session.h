// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/node/session.h"
#include "ds/thread_messaging.h"
#include "tcp/msg_types.h"

#include <span>

namespace ccf
{
  class ThreadedSession : public Session,
                          public std::enable_shared_from_this<ThreadedSession>
  {
  private:
    size_t execution_thread;

    struct SendRecvMsg
    {
      size_t len;
      const uint8_t* buf;
      std::shared_ptr<ThreadedSession> self;
    };

  public:
    ThreadedSession(int64_t thread_affinity)
    {
      execution_thread =
        ::threading::ThreadMessaging::instance().get_execution_thread(
          thread_affinity);
    }

    // Implement Session::handle_incoming_data by dispatching a thread message
    // that eventually invokes the virtual handle_incoming_data_thread()
    void handle_incoming_data(std::span<const uint8_t> data) override
    {
      auto [_, len, buf] = ringbuffer::read_message<::tcp::tcp_inbound>(data);

      auto msg = std::make_unique<::threading::Tmsg<SendRecvMsg>>(
        &handle_incoming_data_cb);
      msg->data.self = this->shared_from_this();
      msg->data.len = len;
      msg->data.buf = (const uint8_t*)buf /*crimes*/;

      ::threading::ThreadMessaging::instance().add_task(
        execution_thread, std::move(msg));
    }

    static void handle_incoming_data_cb(
      std::unique_ptr<::threading::Tmsg<SendRecvMsg>> msg)
    {
      msg->data.self->handle_incoming_data_thread(
        {msg->data.buf, msg->data.len});
      delete[] msg->data.buf;
    }

    virtual void handle_incoming_data_thread(std::span<const uint8_t> data) = 0;
  };
}
