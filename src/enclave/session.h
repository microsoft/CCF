// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/node/session.h"
#include "enclave/tls_session.h"
#include "tasks/ordered_tasks.h"
#include "tasks/task.h"
#include "tasks/task_system.h"
#include "tcp/msg_types.h"

#include <span>

namespace ccf
{
  class ThreadedSession : public Session,
                          public std::enable_shared_from_this<ThreadedSession>
  {
  private:
    std::shared_ptr<ccf::tasks::OrderedTasks> task_scheduler;

    struct SessionDataTask : public ccf::tasks::ITaskAction
    {
      std::vector<uint8_t> data;
      std::shared_ptr<ThreadedSession> self;

      SessionDataTask(
        std::span<const uint8_t> d, std::shared_ptr<ThreadedSession> s) :
        self(s)
      {
        data.assign(d.begin(), d.end());
      }
    };

    struct HandleIncomingDataTask : public SessionDataTask
    {
      using SessionDataTask::SessionDataTask;

      void do_action() override
      {
        self->handle_incoming_data_thread(std::move(data));
      }
    };

    struct SendDataTask : public SessionDataTask
    {
      using SessionDataTask::SessionDataTask;

      void do_action() override
      {
        self->send_data_thread(std::move(data));
      }
    };

  public:
    ThreadedSession(int64_t session_id)
    {
      task_scheduler = ccf::tasks::make_ordered_tasks(
        ccf::tasks::get_main_job_board(),
        fmt::format("Session {}", session_id));
    }

    ~ThreadedSession()
    {
      task_scheduler->cancel_task();
    }

    // Implement Session::handle_incoming_data by dispatching a thread message
    // that eventually invokes the virtual handle_incoming_data_thread()
    void handle_incoming_data(std::span<const uint8_t> data) override
    {
      auto [_, body] = ringbuffer::read_message<::tcp::tcp_inbound>(data);

      task_scheduler->add_action(
        std::make_shared<HandleIncomingDataTask>(body, shared_from_this()));
    }

    virtual void handle_incoming_data_thread(std::vector<uint8_t>&& data) = 0;

    // Implement Session::sent_data by dispatching a thread message
    // that eventually invokes the virtual send_data_thread()
    void send_data(std::span<const uint8_t> data) override
    {
      task_scheduler->add_action(
        std::make_shared<SendDataTask>(data, shared_from_this()));
    }

    virtual void send_data_thread(std::vector<uint8_t>&& data) = 0;

    void close_session() override
    {
      task_scheduler->add_action(ccf::tasks::make_basic_action(
        [self = shared_from_this()]() { self->close_session_thread(); }));
    }

    virtual void close_session_thread() = 0;
  };

  class EncryptedSession : public ThreadedSession
  {
  public:
    virtual bool parse(std::span<const uint8_t> data) = 0;

  protected:
    std::shared_ptr<ccf::TLSSession> tls_io;
    ::tcp::ConnID session_id;

    EncryptedSession(
      ::tcp::ConnID session_id_,
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::unique_ptr<ccf::tls::Context> ctx) :
      ThreadedSession(session_id_),
      tls_io(std::make_shared<ccf::TLSSession>(
        session_id_, writer_factory, std::move(ctx))),
      session_id(session_id_)
    {}

  public:
    void send_data_thread(std::vector<uint8_t>&& data) override
    {
      tls_io->send_data(data.data(), data.size());
    }

    void handle_incoming_data_thread(std::vector<uint8_t>&& data) override
    {
      tls_io->recv_buffered(data.data(), data.size());

      LOG_TRACE_FMT("recv called with {} bytes", data.size());

      // Try to parse all incoming data, reusing the vector we were just passed
      // for storage. Increase the size if the received vector was too small
      // (for the case where this chunk is very small, but we had some previous
      // data to continue reading).
      constexpr auto min_read_block_size = 4096;
      if (data.size() < min_read_block_size)
      {
        data.resize(min_read_block_size);
      }

      auto n_read = tls_io->read(data.data(), data.size(), false);

      while (true)
      {
        if (n_read == 0)
        {
          return;
        }

        LOG_TRACE_FMT("Going to parse {} bytes", n_read);

        bool cont = parse({data.data(), n_read});
        if (!cont)
        {
          return;
        }

        // Used all provided bytes - check if more are available
        n_read = tls_io->read(data.data(), data.size(), false);
      }
    }

    void close_session_thread() override
    {
      tls_io->close();
    }
  };

  class UnencryptedSession : public ccf::ThreadedSession
  {
  public:
    virtual bool parse(std::span<const uint8_t> data) = 0;

  protected:
    ::tcp::ConnID session_id;
    ringbuffer::WriterPtr to_host;

    UnencryptedSession(
      ::tcp::ConnID session_id_,
      ringbuffer::AbstractWriterFactory& writer_factory_) :
      ccf::ThreadedSession(session_id_),
      session_id(session_id_),
      to_host(writer_factory_.create_writer_to_outside())
    {}

    void send_data_thread(std::vector<uint8_t>&& data) override
    {
      RINGBUFFER_WRITE_MESSAGE(
        ::tcp::tcp_outbound,
        to_host,
        session_id,
        serializer::ByteRange{data.data(), data.size()});
    }

    void close_session_thread() override
    {
      RINGBUFFER_WRITE_MESSAGE(
        ::tcp::tcp_stop, to_host, session_id, std::string("Session closed"));
    }

    void handle_incoming_data_thread(std::vector<uint8_t>&& data) override
    {
      parse(data);
    }
  };
}
