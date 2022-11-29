// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/logger.h"
#include "ds/messaging.h"
#include "ds/pending_io.h"
#include "ds/ring_buffer.h"
#include "ds/thread_messaging.h"
#include "enclave/session.h"
#include "quic/msg_types.h"

#include <exception>

namespace quic
{
  class QUICSession : public ccf::Session,
                      public std::enable_shared_from_this<QUICSession>
  {
  protected:
    ringbuffer::WriterPtr to_host;
    tls::ConnID session_id;
    size_t execution_thread;

    enum Status
    {
      handshake,
      ready,
      closed,
      authfail,
      error
    };

    Status get_status() const
    {
      return status;
    }

  protected:
    using PendingBuffer = PendingIO<uint8_t>;
    using PendingList = std::vector<PendingBuffer>;
    PendingList pending_writes;
    PendingList pending_reads;

  private:
    // Decrypted data
    std::vector<uint8_t> read_buffer;

    Status status;

  public:
    QUICSession(
      int64_t session_id_, ringbuffer::AbstractWriterFactory& writer_factory_) :
      to_host(writer_factory_.create_writer_to_outside()),
      session_id(session_id_),
      status(handshake)
    {
      execution_thread =
        threading::ThreadMessaging::get_execution_thread(session_id);
    }

    ~QUICSession()
    {
      // RINGBUFFER_WRITE_MESSAGE(quic::quic_closed, to_host, session_id);
    }

    std::string hostname()
    {
      return {};
    }

    std::vector<uint8_t> peer_cert()
    {
      return {};
    }

    // Returns count N of bytes read, which will be the first N bytes of data,
    // up to a maximum of size. If exact is true, will only return either size
    // or 0 (when size bytes are not currently available). data may be accessed
    // beyond N during operation, up to size, but only the first N should be
    // used by caller.
    size_t read(uint8_t* data, size_t size, sockaddr addr, bool exact = false)
    {
      LOG_TRACE_FMT("Requesting up to {} bytes", size);

      // This will return empty if the connection isn't
      // ready, but it will not block on the handshake.
      do_handshake();

      if (status != ready)
      {
        return 0;
      }

      // Send pending writes.
      flush();

      size_t offset = 0;

      if (read_buffer.size() > 0)
      {
        LOG_TRACE_FMT(
          "Have existing read_buffer of size: {}", read_buffer.size());
        offset = std::min(size, read_buffer.size());
        ::memcpy(data, read_buffer.data(), offset);

        if (offset < read_buffer.size())
          read_buffer.erase(read_buffer.begin(), read_buffer.begin() + offset);
        else
          read_buffer.clear();

        if (offset == size)
          return size;

        // NB: If we continue past here, read_buffer is empty
      }

      // This will need to be handled by the actual QUIC stack
      auto r = handle_recv(data + offset, size - offset, addr);
      LOG_TRACE_FMT("quic read returned: {}", r);

      if (r < 0)
      {
        LOG_TRACE_FMT("QUIC {} error on read", session_id);
        stop(error);
        return 0;
      }

      auto total = r + offset;

      // We read _some_ data but not enough, and didn't get
      // WANT_READ. Probably hit an internal size limit - try
      // again
      if (exact && (total < size))
      {
        LOG_TRACE_FMT(
          "Asked for exactly {}, received {}, retrying", size, total);
        read_buffer.insert(read_buffer.end(), data, data + total);
        return read(data, size, addr, exact);
      }

      return total;
    }

    void recv_buffered(const uint8_t* data, size_t size, sockaddr addr)
    {
      if (threading::get_current_thread_id() != execution_thread)
      {
        throw std::runtime_error("Called recv_buffered from incorrect thread");
      }
      LOG_TRACE_FMT("QUIC Session recv_buffered with {} bytes", size);
      pending_reads.emplace_back(const_cast<uint8_t*>(data), size, addr);
      do_handshake();
    }

    struct SendRecvMsg
    {
      std::vector<uint8_t> data;
      std::shared_ptr<QUICSession> self;
      sockaddr addr;
    };

    static void send_raw_cb(std::unique_ptr<threading::Tmsg<SendRecvMsg>> msg)
    {
      msg->data.self->send_raw_thread(msg->data.data, msg->data.addr);
    }

    void send_raw(const uint8_t* data, size_t size, sockaddr addr)
    {
      auto msg = std::make_unique<threading::Tmsg<SendRecvMsg>>(&send_raw_cb);
      msg->data.self = this->shared_from_this();
      msg->data.data = std::vector<uint8_t>(data, data + size);
      msg->data.addr = addr;

      threading::ThreadMessaging::thread_messaging.add_task(
        execution_thread, std::move(msg));
    }

    void send_raw_thread(const std::vector<uint8_t>& data, sockaddr addr)
    {
      if (threading::get_current_thread_id() != execution_thread)
      {
        throw std::runtime_error(
          "Called send_raw_thread from incorrect thread");
      }
      // Writes as much of the data as possible. If the data cannot all
      // be written now, we store the remainder. We
      // will try to send pending writes again whenever write() is called.
      do_handshake();

      if (status == handshake)
      {
        pending_writes.emplace_back(
          const_cast<uint8_t*>(data.data()), data.size(), addr);
        return;
      }

      if (status != ready)
        return;

      pending_writes.emplace_back(
        const_cast<uint8_t*>(data.data()), data.size(), addr);

      flush();
    }

    void send_buffered(const std::vector<uint8_t>& data, sockaddr addr)
    {
      if (threading::get_current_thread_id() != execution_thread)
      {
        throw std::runtime_error("Called send_buffered from incorrect thread");
      }

      pending_writes.emplace_back(
        const_cast<uint8_t*>(data.data()), data.size(), addr);
    }

    void flush()
    {
      if (threading::get_current_thread_id() != execution_thread)
      {
        throw std::runtime_error("Called flush from incorrect thread");
      }

      do_handshake();

      if (status != ready)
        return;

      int written = 0;
      for (auto& write : pending_writes)
      {
        LOG_TRACE_FMT("QUIC write_some {} bytes", write.len);

        // This will need to be handled by the actual QUIC stack
        int rc = handle_send(write.req, write.len, write.addr);
        if (rc < 0)
        {
          LOG_TRACE_FMT("QUIC {} error on flush", session_id);
          stop(error);
          return;
        }
        written += rc;

        // Mark for deletion (avoiding invalidating iterator)
        write.clear = true;
      }

      // Clear all marked for deletion
      PendingBuffer::clear_empty(pending_writes);
    }

    struct EmptyMsg
    {
      std::shared_ptr<QUICSession> self;
    };

    static void close_cb(std::unique_ptr<threading::Tmsg<EmptyMsg>> msg)
    {
      msg->data.self->close_thread();
    }

    void close_session() override
    {
      auto msg = std::make_unique<threading::Tmsg<EmptyMsg>>(&close_cb);
      msg->data.self = this->shared_from_this();

      threading::ThreadMessaging::thread_messaging.add_task(
        execution_thread, std::move(msg));
    }

    void close_thread()
    {
      if (threading::get_current_thread_id() != execution_thread)
      {
        throw std::runtime_error("Called close_thread from incorrect thread");
      }

      switch (status)
      {
        case handshake:
        {
          LOG_TRACE_FMT("QUIC {} closed during handshake", session_id);
          stop(closed);
          break;
        }

        case ready:
        {
          LOG_TRACE_FMT("QUIC {} closed", session_id);
          stop(closed);
          break;
        }

        default:
        {
        }
      }
    }

  private:
    void do_handshake()
    {
      // This should be called when additional data is written to the
      // input buffer, until the handshake is complete.
      if (status != handshake)
        return;

      // This will need to be handled by the actual QUIC stack
      LOG_TRACE_FMT("QUIC do_handshake unimplemented");
      status = ready;
    }

    void stop(Status status_)
    {
      switch (status)
      {
        case closed:
        case authfail:
        case error:
          return;

        default:
        {
        }
      }

      status = status_;
    }

    int handle_send(const uint8_t* buf, size_t len, sockaddr addr)
    {
      auto [addr_family, addr_data] = quic::sockaddr_encode(addr);

      // Either write all of the data or none of it.
      auto wrote = RINGBUFFER_TRY_WRITE_MESSAGE(
        quic::quic_outbound,
        to_host,
        session_id,
        addr_family,
        addr_data,
        serializer::ByteRange{buf, len});

      if (!wrote)
        return -1;

      return (int)len;
    }

    int handle_recv(uint8_t* buf, size_t len, sockaddr addr)
    {
      if (threading::get_current_thread_id() != execution_thread)
      {
        throw std::runtime_error("Called handle_recv from incorrect thread");
      }

      size_t len_read = 0;
      for (auto& read : pending_reads)
      {
        // Only handle pending reads that belong to the same address
        if (!memcmp((void*)&addr, (void*)&read.addr, sizeof(addr)))
          continue;

        size_t rd = std::min(len, read.len);
        ::memcpy(buf, read.req, rd);
        read.clear = true;

        // UDP packets are datagrams, so it's either whole or nothing
        len_read += rd;
        if (len_read >= len)
          break;
      }

      // Clear all marked for deletion
      PendingBuffer::clear_empty(pending_reads);

      if (len_read > 0)
        return len_read;
      else
        return -1;
    }
  };

  // This is a wrapper for the QUICSession so we can use in rpc_sessions
  // Ultimately, this needs to be an HTTP3ServerSession : HTTP3Session :
  // QUICSession
  class QUICEchoSession : public QUICSession
  {
    std::shared_ptr<ccf::RPCMap> rpc_map;
    std::shared_ptr<ccf::RpcHandler> handler;
    std::shared_ptr<ccf::SessionContext> session_ctx;
    int64_t session_id;
    ccf::ListenInterfaceID interface_id;
    sockaddr addr;

    /// Move all reads into the writes and push back to the client
    void echo()
    {
      pending_reads.swap(pending_writes);
      flush();
    }

  public:
    QUICEchoSession(
      std::shared_ptr<ccf::RPCMap> rpc_map,
      int64_t session_id,
      const ccf::ListenInterfaceID& interface_id,
      ringbuffer::AbstractWriterFactory& writer_factory) :
      QUICSession(session_id, writer_factory),
      rpc_map(rpc_map),
      session_id(session_id),
      interface_id(interface_id)
    {}

    void send_data(std::span<const uint8_t> data) override
    {
      send_raw(data.data(), data.size(), addr);
    }

    static void recv_cb(std::unique_ptr<threading::Tmsg<SendRecvMsg>> msg)
    {
      reinterpret_cast<QUICEchoSession*>(msg->data.self.get())
        ->recv_(msg->data.data.data(), msg->data.data.size(), msg->data.addr);
    }

    void handle_incoming_data(std::span<const uint8_t> data) override
    {
      auto [_, addr_family, addr_data, body] =
        ringbuffer::read_message<quic::quic_inbound>(data);

      auto msg = std::make_unique<threading::Tmsg<SendRecvMsg>>(&recv_cb);
      msg->data.self = this->shared_from_this();
      msg->data.data.assign(body.data, body.data + body.size);
      msg->data.addr = quic::sockaddr_decode(addr_family, addr_data);

      threading::ThreadMessaging::thread_messaging.add_task(
        execution_thread, std::move(msg));
    }

    void recv_(const uint8_t* data_, size_t size_, sockaddr addr_)
    {
      recv_buffered(data_, size_, addr_);
      addr = addr_;

      LOG_TRACE_FMT("recv called with {} bytes", size_);

      // ECHO SERVER
      echo();
    }
  };
}
