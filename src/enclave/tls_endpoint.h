// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/logger.h"
#include "ds/messaging.h"
#include "ds/ring_buffer.h"
#include "endpoint.h"
#include "tls/context.h"
#include "tls/msg_types.h"

#include <exception>

namespace enclave
{
  class TLSEndpoint : public Endpoint
  {
  protected:
    ringbuffer::WriterPtr to_host;
    size_t session_id;
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

    virtual std::vector<uint8_t> oversized_message_error(
      size_t msg_size, size_t max_msg_size)
    {
      const auto s = fmt::format(
        "Requested message ({} bytes) is too large. Maximum allowed is {} "
        "bytes. Closing connection.",
        msg_size,
        max_msg_size);
      const auto data = (const uint8_t*)s.data();
      return std::vector<uint8_t>(data, data + s.size());
    }

  private:
    std::vector<uint8_t> pending_write;
    std::vector<uint8_t> pending_read;
    // Decrypted data, read through mbedtls
    std::vector<uint8_t> read_buffer;

    std::unique_ptr<tls::Context> ctx;
    Status status;

  public:
    TLSEndpoint(
      size_t session_id_,
      ringbuffer::AbstractWriterFactory& writer_factory_,
      std::unique_ptr<tls::Context> ctx_) :
      to_host(writer_factory_.create_writer_to_outside()),
      session_id(session_id_),
      ctx(move(ctx_)),
      status(handshake)
    {
      if (enclave::ThreadMessaging::thread_count > 1)
      {
        execution_thread =
          (session_id_ % (enclave::ThreadMessaging::thread_count - 1)) + 1;
      }
      else
      {
        execution_thread = 0;
      }
      ctx->set_bio(this, send_callback, recv_callback, dbg_callback);
    }

    ~TLSEndpoint()
    {
      RINGBUFFER_WRITE_MESSAGE(tls::tls_closed, to_host, session_id);
    }

    std::string hostname()
    {
      if (status != ready)
      {
        return {};
      }

      return ctx->host();
    }

    std::vector<uint8_t> peer_cert()
    {
      if (status != ready)
      {
        return {};
      }

      auto client_cert = ctx->peer_cert();
      if (client_cert == nullptr)
      {
        return {};
      }

      return std::vector<uint8_t>(
        client_cert->raw.p, client_cert->raw.p + client_cert->raw.len);
    }

    std::vector<uint8_t> read(size_t up_to, bool exact = false)
    {
      LOG_TRACE_FMT("Requesting {} bytes", up_to);
      // This will return an empty vector if the connection isn't
      // ready, but it will not block on the handshake.
      do_handshake();

      if (status != ready)
      {
        return {};
      }

      // Send pending writes.
      flush();

      std::vector<uint8_t> data(up_to);
      size_t offset = 0;

      if (read_buffer.size() > 0)
      {
        LOG_TRACE_FMT("read_buffer is of size: {}", read_buffer.size());
        offset = std::min(up_to, read_buffer.size());
        ::memcpy(data.data(), read_buffer.data(), offset);

        if (offset < read_buffer.size())
          read_buffer.erase(read_buffer.begin(), read_buffer.begin() + offset);
        else
          read_buffer.clear();

        if (offset == up_to)
          return data;
      }

      auto r = ctx->read(data.data() + offset, up_to - offset);
      LOG_TRACE_FMT("ctx->read returned: {}", r);

      switch (r)
      {
        case 0:
        case MBEDTLS_ERR_NET_CONN_RESET:
        case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
        {
          LOG_TRACE_FMT("TLS {} on read: {}", session_id, tls::error_string(r));

          stop(closed);

          if (!exact)
          {
            data.resize(offset);
            return data;
          }

          return {};
        }

        case MBEDTLS_ERR_SSL_WANT_READ:
        case MBEDTLS_ERR_SSL_WANT_WRITE:
        {
          data.resize(offset);

          if (!exact)
          {
            return data;
          }

          read_buffer = move(data);
          return {};
        }

        default:
        {}
      }

      if (r < 0)
      {
        LOG_TRACE_FMT("TLS {} on read: {}", session_id, tls::error_string(r));
        stop(error);
        return {};
      }

      auto total = r + offset;
      data.resize(total);

      // We read _some_ data but not enough, and didn't get
      // MBEDTLS_ERR_SSL_WANT_READ. Probably hit a size limit - try again
      if (exact && (total < up_to))
      {
        LOG_TRACE_FMT(
          "Asked for exactly {}, received {}, retrying", up_to, total);
        read_buffer = move(data);
        return read(up_to, exact);
      }

      return data;
    }

    void recv_buffered(const uint8_t* data, size_t size)
    {
      if (thread_ids[std::this_thread::get_id()] != execution_thread)
      {
        throw std::exception();
      }
      pending_read.insert(pending_read.end(), data, data + size);
      do_handshake();
    }

    struct SendRecvMsg
    {
      std::vector<uint8_t> data;
      std::shared_ptr<Endpoint> self;
    };

    static void send_raw_cb(std::unique_ptr<enclave::Tmsg<SendRecvMsg>> msg)
    {
      reinterpret_cast<TLSEndpoint*>(msg->data.self.get())
        ->send_raw_thread(msg->data.data);
    }

    void send_raw(const std::vector<uint8_t>& data)
    {
      auto msg = std::make_unique<enclave::Tmsg<SendRecvMsg>>(&send_raw_cb);
      msg->data.self = this->shared_from_this();
      msg->data.data = data;

      enclave::ThreadMessaging::thread_messaging.add_task<SendRecvMsg>(
        execution_thread, std::move(msg));
    }

    void send_raw_thread(std::vector<uint8_t>& data)
    {
      if (thread_ids[std::this_thread::get_id()] != execution_thread)
      {
        throw std::runtime_error("running from incorrect thread");
      }
      // Writes as much of the data as possible. If the data cannot all
      // be written now, we store the remainder. We
      // will try to send pending writes again whenever write() is called.
      do_handshake();

      if (status == handshake)
      {
        pending_write.insert(pending_write.end(), data.begin(), data.end());
        return;
      }

      if (status != ready)
        return;

      pending_write.insert(pending_write.end(), data.begin(), data.end());

      flush();
    }

    void send_buffered(const std::vector<uint8_t>& data)
    {
      if (thread_ids[std::this_thread::get_id()] != execution_thread)
      {
        throw std::runtime_error("running from incorrect thread");
      }

      pending_write.insert(pending_write.end(), data.begin(), data.end());
    }

    void flush()
    {
      if (thread_ids[std::this_thread::get_id()] != execution_thread)
      {
        throw std::runtime_error("running from incorrect thread");
      }

      do_handshake();

      if (status != ready)
        return;

      while (pending_write.size() > 0)
      {
        auto r = write_some(pending_write);

        if (r > 0)
        {
          pending_write.erase(pending_write.begin(), pending_write.begin() + r);
        }
        else if (r == 0)
        {
          break;
        }
        else
        {
          LOG_TRACE_FMT(
            "TLS {} on flush: {}", session_id, tls::error_string(r));
          stop(error);
        }
      }
    }

    void close()
    {
      switch (status)
      {
        case handshake:
        {
          LOG_TRACE_FMT("TLS {} closed during handshake", session_id);
          stop(closed);
          break;
        }

        case ready:
        {
          int r = ctx->close();

          switch (r)
          {
            case 0:
            case MBEDTLS_ERR_SSL_WANT_READ:
            case MBEDTLS_ERR_SSL_WANT_WRITE:
            {
              // mbedtls may return 0 when a close notify has not been
              // sent. This can't be disambiguated from a successful
              // close notify, so treat them the same.
              LOG_TRACE_FMT("TLS {} closed ({})", session_id, r);
              stop(closed);
              break;
            }

            default:
            {
              LOG_TRACE_FMT(
                "TLS {} on_close: {}", session_id, tls::error_string(r));
              stop(error);
              break;
            }
          }
          break;
        }

        default:
        {}
      }
    }

  private:
    void do_handshake()
    {
      // This should be called when additional data is written to the
      // input buffer, until the handshake is complete.
      if (status != handshake)
        return;

      auto rc = ctx->handshake();

      switch (rc)
      {
        case 0:
        {
          status = ready;
          break;
        }

        case MBEDTLS_ERR_SSL_WANT_READ:
        case MBEDTLS_ERR_SSL_WANT_WRITE:
          break;

        case MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE:
        case MBEDTLS_ERR_SSL_PEER_VERIFY_FAILED:
        {
          LOG_TRACE_FMT(
            "TLS {} on handshake: {}", session_id, tls::error_string(rc));
          stop(authfail);
          break;
        }

        case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
        {
          LOG_TRACE_FMT(
            "TLS {} on handshake: {}", session_id, tls::error_string(rc));
          stop(closed);
          break;
        }

        case MBEDTLS_ERR_X509_CERT_VERIFY_FAILED:
        {
          std::vector<char> buf(512);
          auto r = mbedtls_x509_crt_verify_info(
            buf.data(),
            buf.size(),
            "Cert verify failed: ",
            ctx->verify_result());

          if (r > 0)
          {
            buf.resize(r);
            LOG_TRACE_FMT(std::string(buf.data(), buf.size()));
          }

          LOG_TRACE_FMT(
            "TLS {} on handshake: {}", session_id, tls::error_string(rc));
          stop(authfail);
          return;
        }

        default:
        {
          LOG_TRACE_FMT(
            "TLS {} on handshake: {}", session_id, tls::error_string(rc));
          stop(error);
          break;
        }
      }
    }

    int write_some(const std::vector<uint8_t>& data)
    {
      auto r = ctx->write(data.data(), data.size());

      switch (r)
      {
        case MBEDTLS_ERR_SSL_WANT_READ:
        case MBEDTLS_ERR_SSL_WANT_WRITE:
          return 0;

        default:
          return r;
      }
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
        {}
      }

      status = status_;

      switch (status)
      {
        case closed:
        {
          RINGBUFFER_WRITE_MESSAGE(
            tls::tls_stop, to_host, session_id, std::string("Session closed"));
          break;
        }

        case authfail:
        {
          RINGBUFFER_WRITE_MESSAGE(
            tls::tls_stop,
            to_host,
            session_id,
            std::string("Authentication failed"));
        }
        case error:
        {
          RINGBUFFER_WRITE_MESSAGE(
            tls::tls_stop, to_host, session_id, std::string("Error"));
          break;
        }

        default:
        {}
      }
    }

    int handle_send(const uint8_t* buf, size_t len)
    {
      // Either write all of the data or none of it.
      auto wrote = RINGBUFFER_TRY_WRITE_MESSAGE(
        tls::tls_outbound,
        to_host,
        session_id,
        serializer::ByteRange{buf, len});

      if (!wrote)
        return MBEDTLS_ERR_SSL_WANT_WRITE;

      return (int)len;
    }

    int handle_recv(uint8_t* buf, size_t len)
    {
      if (thread_ids[std::this_thread::get_id()] != execution_thread)
      {
        throw std::runtime_error("running from incorrect thread");
      }
      if (pending_read.size() > 0)
      {
        // Use the pending data vector. This is populated when the host
        // writes a chunk larger than the size requested by the enclave.
        size_t rd = std::min(len, pending_read.size());
        ::memcpy(buf, pending_read.data(), rd);

        if (rd >= pending_read.size())
        {
          pending_read.clear();
        }
        else
        {
          pending_read.erase(pending_read.begin(), pending_read.begin() + rd);
        }

        return (int)rd;
      }

      return MBEDTLS_ERR_SSL_WANT_READ;
    }

    static int send_callback(void* ctx, const unsigned char* buf, size_t len)
    {
      return reinterpret_cast<TLSEndpoint*>(ctx)->handle_send(buf, len);
    }

    static int recv_callback(void* ctx, unsigned char* buf, size_t len)
    {
      return reinterpret_cast<TLSEndpoint*>(ctx)->handle_recv(buf, len);
    }

    static void dbg_callback(
      void* ctx, int level, const char* file, int line, const char* str)
    {
      (void)level;
      LOG_DEBUG_FMT("{}:{}: {}", file, line, str);
    }
  };
}
