// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/node/session.h"
#include "ds/thread_messaging.h"
#include "enclave/tls_session.h"
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
      std::vector<uint8_t> data;
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
      auto [_, body] = ringbuffer::read_message<::tcp::tcp_inbound>(data);

      auto msg = std::make_unique<::threading::Tmsg<SendRecvMsg>>(
        &handle_incoming_data_cb);
      msg->data.self = this->shared_from_this();
      msg->data.data.assign(body.data, body.data + body.size);

      ::threading::ThreadMessaging::instance().add_task(
        execution_thread, std::move(msg));
    }

    static void handle_incoming_data_cb(
      std::unique_ptr<::threading::Tmsg<SendRecvMsg>> msg)
    {
      msg->data.self->handle_incoming_data_thread(std::move(msg->data.data));
    }

    virtual void handle_incoming_data_thread(std::vector<uint8_t>&& data) = 0;
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
    void send_data(std::span<const uint8_t> data) override
    {
      tls_io->send_raw(data.data(), data.size());
    }

    void close_session() override
    {
      tls_io->close();
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

    void send_data(std::span<const uint8_t> data) override
    {
      RINGBUFFER_WRITE_MESSAGE(
        ::tcp::tcp_outbound,
        to_host,
        session_id,
        serializer::ByteRange{data.data(), data.size()});
    }

    void close_session() override
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
