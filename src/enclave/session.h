// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/thread_messaging.h"
#include "tls/msg_types.h"

#include <span>

namespace ccf
{
  class Session
  {
  public:
    virtual ~Session() = default;

    virtual void handle_incoming_data(std::span<const uint8_t> data) = 0;
    virtual void send_data(std::span<const uint8_t> data) = 0;
    virtual void close_session() = 0;
  };

  class ThreadedSession : public Session,
                          public std::enable_shared_from_this<ThreadedSession>
  {
  private:
    size_t execution_thread;

    struct SendRecvMsg
    {
      std::vector<uint8_t> data;
      std::shared_ptr<ThreadedSession> self;
    };

  public:
    ThreadedSession(int64_t thread_affinity)
    {
      execution_thread =
        threading::ThreadMessaging::get_execution_thread(thread_affinity);
    }

    // Implement Session::handle_incoming_data by dispatching a thread message
    // that eventually invokes the virtual handle_incoming_data_thread()
    void handle_incoming_data(std::span<const uint8_t> data) override
    {
      auto [_, body] = ringbuffer::read_message<tls::tls_inbound>(data);

      auto msg = std::make_unique<threading::Tmsg<SendRecvMsg>>(
        &handle_incoming_data_cb);
      msg->data.self = this->shared_from_this();
      msg->data.data.assign(body.data, body.data + body.size);

      threading::ThreadMessaging::thread_messaging.add_task(
        execution_thread, std::move(msg));
    }

    static void handle_incoming_data_cb(
      std::unique_ptr<threading::Tmsg<SendRecvMsg>> msg)
    {
      msg->data.self->handle_incoming_data_thread(std::move(msg->data.data));
    }

    virtual void handle_incoming_data_thread(std::vector<uint8_t>&& data) = 0;
  };
}
