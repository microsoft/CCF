// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/node/session.h"
#include "enclave/session_writer.h"
#include "tasks/ordered_tasks.h"
#include "tasks/task.h"
#include "tasks/task_system.h"
#include "tcp/msg_types.h"

#include <span>
#include <string>

namespace ccf
{
  class ThreadedSession : public Session,
                          public std::enable_shared_from_this<ThreadedSession>
  {
  private:
    std::shared_ptr<ccf::tasks::OrderedTasks> task_scheduler;
    std::atomic<bool> is_closing = false;

    struct SessionDataTask : public ccf::tasks::ITaskAction
    {
      std::vector<uint8_t> data;
      std::shared_ptr<ThreadedSession> self;

      SessionDataTask(
        std::span<const uint8_t> d, std::shared_ptr<ThreadedSession> s) :
        self(std::move(s))
      {
        data.assign(d.begin(), d.end());
      }
    };

    struct HandleIncomingDataTask : public SessionDataTask
    {
      using SessionDataTask::SessionDataTask;

      void do_action() override
      {
        if (self->is_closing.load())
        {
          return;
        }

        self->handle_incoming_data_thread(std::move(data));
      }

      [[nodiscard]] const std::string& get_name() const override
      {
        static const std::string name =
          "ThreadedSession::HandleIncomingDataTask";
        return name;
      }
    };

    struct SendDataTask : public SessionDataTask
    {
      using SessionDataTask::SessionDataTask;

      void do_action() override
      {
        self->send_data_thread(std::move(data));
      }

      [[nodiscard]] const std::string& get_name() const override
      {
        static const std::string name = "ThreadedSession::SendDataTask";
        return name;
      }
    };

  public:
    ThreadedSession(int64_t session_id)
    {
      task_scheduler = ccf::tasks::OrderedTasks::create(
        ccf::tasks::get_main_job_board(),
        fmt::format("Session {}", session_id));
    }

    ~ThreadedSession() override
    {
      task_scheduler->cancel_task();
    }

    // Implement Session::handle_incoming_data by dispatching a thread message
    // that eventually invokes the virtual handle_incoming_data_thread()
    void handle_incoming_data(
      std::span<const uint8_t> data, sockaddr /*addr*/) override
    {
      task_scheduler->add_action(
        std::make_shared<HandleIncomingDataTask>(data, shared_from_this()));
    }

    virtual void handle_incoming_data_thread(std::vector<uint8_t>&& data) = 0;

    // Implement Session::sent_data by dispatching a thread message
    // that eventually invokes the virtual send_data_thread()
    void send_data(std::vector<uint8_t>&& data) override
    {
      task_scheduler->add_action(
        std::make_shared<SendDataTask>(std::move(data), shared_from_this()));
    }

    virtual void send_data_thread(std::vector<uint8_t>&& data) = 0;

    void close_session() override
    {
      is_closing.store(true);

      task_scheduler->add_action(ccf::tasks::make_basic_action(
        [self = shared_from_this()]() { self->close_session_thread(); }));
    }

    virtual void close_session_thread() = 0;
  };

  // A protocol session (HTTP/HTTP2/...) running over a transport that owns the
  // TLS connection (the host-side OpenSSL connection). It receives and emits
  // plaintext: inbound bytes are already decrypted, and outbound bytes are
  // handed to a SessionWriter which encrypts and writes them. The peer
  // certificate and SNI (captured by the transport at handshake) are provided
  // for caller authentication.
  class PlaintextSession : public ThreadedSession
  {
  public:
    virtual bool parse(std::span<const uint8_t> data) = 0;

  protected:
    ::tcp::ConnID session_id;
    ccf::SessionWriter& session_writer;
    std::vector<uint8_t> peer_cert_;
    std::string sni_;

    PlaintextSession(
      ::tcp::ConnID session_id_,
      ccf::SessionWriter& writer,
      std::vector<uint8_t> peer_cert = {},
      std::string sni = {}) :
      ThreadedSession(session_id_),
      session_id(session_id_),
      session_writer(writer),
      peer_cert_(std::move(peer_cert)),
      sni_(std::move(sni))
    {}

  public:
    const std::vector<uint8_t>& peer_cert() const
    {
      return peer_cert_;
    }

    const std::string& hostname() const
    {
      return sni_;
    }

    void send_data_thread(std::vector<uint8_t>&& data) override
    {
      session_writer.write_outbound(session_id, {data.data(), data.size()});
    }

    void handle_incoming_data_thread(std::vector<uint8_t>&& data) override
    {
      parse({data.data(), data.size()});
    }

    void close_session_thread() override
    {
      session_writer.close_socket(session_id);
    }
  };
}
