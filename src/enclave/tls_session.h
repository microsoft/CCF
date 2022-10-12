// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/logger.h"
#include "ds/messaging.h"
#include "ds/ring_buffer.h"
#include "ds/thread_messaging.h"
#include "enclave/session.h"
#include "tls/context.h"
#include "tls/msg_types.h"
#include "tls/tls.h"

#include <exception>

namespace ccf
{
  enum SessionStatus
  {
    handshake,
    ready,
    closing,
    closed,
    authfail,
    error
  };

  class TLSSession : public std::enable_shared_from_this<TLSSession>
  {
  public:
    using HandshakeErrorCB = std::function<void(std::string&&)>;

  protected:
    ringbuffer::WriterPtr to_host;
    tls::ConnID session_id;
    size_t execution_thread;

  private:
    std::vector<uint8_t> pending_write;
    std::vector<uint8_t> pending_read;
    // Decrypted data
    std::vector<uint8_t> read_buffer;

    std::unique_ptr<tls::Context> ctx;
    SessionStatus status;

    HandshakeErrorCB handshake_error_cb;

    bool can_send()
    {
      // Closing endpoint should still be able to respond to clients (e.g. to
      // report errors)
      return status == ready || status == closing;
    }

    bool can_recv()
    {
      return status == ready || status == handshake;
    }

    struct SendRecvMsg
    {
      std::vector<uint8_t> data;
      std::shared_ptr<TLSSession> self;
    };

    struct EmptyMsg
    {
      std::shared_ptr<TLSSession> self;
    };

  public:
    TLSSession(
      int64_t session_id_,
      ringbuffer::AbstractWriterFactory& writer_factory_,
      std::unique_ptr<tls::Context> ctx_) :
      to_host(writer_factory_.create_writer_to_outside()),
      session_id(session_id_),
      ctx(move(ctx_)),
      status(handshake)
    {
      execution_thread =
        threading::ThreadMessaging::get_execution_thread(session_id);
      ctx->set_bio(this, send_callback_openssl, recv_callback_openssl);
    }

    virtual ~TLSSession()
    {
      RINGBUFFER_WRITE_MESSAGE(tls::tls_closed, to_host, session_id);
    }

    SessionStatus get_status() const
    {
      return status;
    }

    void on_handshake_error(std::string&& error_msg)
    {
      if (handshake_error_cb)
      {
        handshake_error_cb(std::move(error_msg));
      }
      else
      {
        LOG_TRACE_FMT("{}", error_msg);
      }
    }

    void set_handshake_error_cb(HandshakeErrorCB&& cb)
    {
      handshake_error_cb = std::move(cb);
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
      return ctx->peer_cert();
    }

    // Returns count N of bytes read, which will be the first N bytes of data,
    // up to a maximum of size. If exact is true, will only return either size
    // or 0 (when size bytes are not currently available). data may be accessed
    // beyond N during operation, up to size, but only the first N should be
    // used by caller.
    size_t read(uint8_t* data, size_t size, bool exact = false)
    {
      // This will return empty if the connection isn't
      // ready, but it will not block on the handshake.
      do_handshake();

      if (status != ready)
      {
        LOG_TRACE_FMT("Not ready to read {} bytes", size);
        return 0;
      }

      LOG_TRACE_FMT("Requesting up to {} bytes", size);

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

      auto r = ctx->read(data + offset, size - offset);
      LOG_TRACE_FMT("ctx->read returned: {}", r);

      switch (r)
      {
        case 0:
        case TLS_ERR_CONN_CLOSE_NOTIFY:
        {
          LOG_TRACE_FMT(
            "TLS {} close on read: {}", session_id, tls::error_string(r));

          stop(closed);

          if (!exact)
          {
            // Hit an error, but may still have some useful data from the
            // previous read_buffer
            return offset;
          }

          return 0;
        }

        case TLS_ERR_WANT_READ:
        case TLS_ERR_WANT_WRITE:
        {
          if (!exact)
          {
            return offset;
          }

          // May have read something but not enough - copy it into read_buffer
          // for next call
          read_buffer.insert(read_buffer.end(), data, data + offset);
          return 0;
        }

        default:
        {
        }
      }

      if (r < 0)
      {
        LOG_TRACE_FMT(
          "TLS {} error on read: {}", session_id, tls::error_string(r));
        stop(error);
        return 0;
      }

      auto total = r + offset;

      // We read _some_ data but not enough, and didn't get
      // TLS_ERR_WANT_READ. Probably hit an internal size limit - try
      // again
      if (exact && (total < size))
      {
        LOG_TRACE_FMT(
          "Asked for exactly {}, received {}, retrying", size, total);
        read_buffer.insert(read_buffer.end(), data, data + total);
        return read(data, size, exact);
      }

      return total;
    }

    void recv_buffered(const uint8_t* data, size_t size)
    {
      if (threading::get_current_thread_id() != execution_thread)
      {
        throw std::runtime_error("Called recv_buffered from incorrect thread");
      }

      if (can_recv())
      {
        pending_read.insert(pending_read.end(), data, data + size);
      }

      do_handshake();
    }

    virtual void close()
    {
      status = closing;
      if (threading::get_current_thread_id() != execution_thread)
      {
        auto msg = std::make_unique<threading::Tmsg<EmptyMsg>>(&close_cb);
        msg->data.self = this->shared_from_this();

        threading::ThreadMessaging::thread_messaging.add_task(
          execution_thread, std::move(msg));
      }
      else
      {
        // Close inline immediately
        close_thread();
      }
    }

    static void close_cb(std::unique_ptr<threading::Tmsg<EmptyMsg>> msg)
    {
      msg->data.self->close_thread();
    }

    virtual void close_thread()
    {
      if (threading::get_current_thread_id() != execution_thread)
      {
        throw std::runtime_error("Called close_thread from incorrect thread");
      }

      switch (status)
      {
        case handshake:
        {
          LOG_TRACE_FMT("TLS {} closed during handshake", session_id);
          stop(closed);
          break;
        }

        case ready:
        case closing:
        {
          int r = ctx->close();

          switch (r)
          {
            case TLS_ERR_WANT_READ:
            case TLS_ERR_WANT_WRITE:
            {
              LOG_TRACE_FMT("TLS {} has pending data ({})", session_id, r);
              // FALLTHROUGH
            }
            case 0:
            {
              LOG_TRACE_FMT("TLS {} closed ({})", session_id, r);
              stop(closed);
              break;
            }

            default:
            {
              LOG_TRACE_FMT(
                "TLS {} error on_close: {}", session_id, tls::error_string(r));
              stop(error);
              break;
            }
          }
          break;
        }

        default:
        {
        }
      }
    }

    void send_raw(const uint8_t* data, size_t size)
    {
      if (threading::get_current_thread_id() != execution_thread)
      {
        auto msg = std::make_unique<threading::Tmsg<SendRecvMsg>>(&send_raw_cb);
        msg->data.self = this->shared_from_this();
        msg->data.data = std::vector<uint8_t>(data, data + size);

        threading::ThreadMessaging::thread_messaging.add_task(
          execution_thread, std::move(msg));
      }
      else
      {
        // Send inline immediately
        send_raw_thread(data, size);
      }
    }

  private:
    static void send_raw_cb(std::unique_ptr<threading::Tmsg<SendRecvMsg>> msg)
    {
      msg->data.self->send_raw_thread(
        msg->data.data.data(), msg->data.data.size());
    }

    void send_raw_thread(const uint8_t* data, size_t size)
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
        pending_write.insert(pending_write.end(), data, data + size);
        return;
      }

      if (!can_send())
      {
        return;
      }

      pending_write.insert(pending_write.end(), data, data + size);

      flush();
    }

    void send_buffered(const std::vector<uint8_t>& data)
    {
      if (threading::get_current_thread_id() != execution_thread)
      {
        throw std::runtime_error("Called send_buffered from incorrect thread");
      }

      pending_write.insert(pending_write.end(), data.begin(), data.end());
    }

    void flush()
    {
      if (threading::get_current_thread_id() != execution_thread)
      {
        throw std::runtime_error("Called flush from incorrect thread");
      }

      do_handshake();

      if (!can_send())
      {
        return;
      }

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

    void do_handshake()
    {
      // This should be called when additional data is written to the
      // input buffer, until the handshake is complete.
      if (status != handshake)
      {
        return;
      }

      auto rc = ctx->handshake();

      switch (rc)
      {
        case 0:
        {
          status = ready;
          break;
        }

        case TLS_ERR_WANT_READ:
        case TLS_ERR_WANT_WRITE:
          break;

        case TLS_ERR_NEED_CERT:
        {
          on_handshake_error(fmt::format(
            "TLS {} verify error on handshake: {}",
            session_id,
            tls::error_string(rc)));
          stop(authfail);
          break;
        }

        case TLS_ERR_CONN_CLOSE_NOTIFY:
        {
          LOG_TRACE_FMT(
            "TLS {} closed on handshake: {}",
            session_id,
            tls::error_string(rc));
          stop(closed);
          break;
        }

        case TLS_ERR_X509_VERIFY:
        {
          auto err = ctx->get_verify_error();
          on_handshake_error(fmt::format(
            "TLS {} invalid cert on handshake: {} [{}]",
            session_id,
            err,
            tls::error_string(rc)));
          stop(authfail);
          return;
        }

        default:
        {
          on_handshake_error(fmt::format(
            "TLS {} error on handshake: {}",
            session_id,
            tls::error_string(rc)));
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
        case TLS_ERR_WANT_READ:
        case TLS_ERR_WANT_WRITE:
          return 0;

        default:
          return r;
      }
    }

    void stop(SessionStatus status_)
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

      switch (status)
      {
        case closing:
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
        {
        }
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
        return TLS_WRITING;

      return (int)len;
    }

    int handle_recv(uint8_t* buf, size_t len)
    {
      if (threading::get_current_thread_id() != execution_thread)
      {
        throw std::runtime_error("Called handle_recv from incorrect thread");
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

      return TLS_READING;
    }

    static int send_callback(void* ctx, const unsigned char* buf, size_t len)
    {
      return reinterpret_cast<TLSSession*>(ctx)->handle_send(buf, len);
    }

    static int recv_callback(void* ctx, unsigned char* buf, size_t len)
    {
      return reinterpret_cast<TLSSession*>(ctx)->handle_recv(buf, len);
    }

    // These callbacks below are complex, using the callbacks above and
    // manipulating OpenSSL's BIO objects accordingly. This is just so we can
    // emulate what MbedTLS used to do.
    // Now that we have removed it from the code, we can move the callbacks
    // above to handle BIOs directly and hopefully remove the complexity below.
    // This work will be carried out in #3429.
    static long send_callback_openssl(
      BIO* b,
      int oper,
      const char* argp,
      size_t len,
      int argi,
      long argl,
      int ret,
      size_t* processed)
    {
      // Unused arguments
      (void)argi;
      (void)argl;
      (void)argp;

      if (ret && len > 0 && oper == (BIO_CB_WRITE | BIO_CB_RETURN))
      {
        // Flush BIO so the "pipe doesn't clog", but we don't use the
        // data here, because 'argp' already has it.
        BIO_flush(b);
        size_t pending = BIO_pending(b);
        if (pending)
          BIO_reset(b);

        // Pipe object
        void* ctx = (BIO_get_callback_arg(b));
        int put = send_callback(ctx, (const uint8_t*)argp, len);

        // WANTS_WRITE
        if (put == TLS_WRITING)
        {
          LOG_TRACE_FMT("TLS Session::send_cb() : WANTS_WRITE");
          *processed = 0;
          return -1;
        }
        else
        {
          LOG_TRACE_FMT("TLS Session::send_cb() : Put {} bytes", put);
        }

        // Update the number of bytes to external users
        *processed = put;
      }

      // Unless we detected an error, the return value is always the same as the
      // original operation.
      return ret;
    }

    static long recv_callback_openssl(
      BIO* b,
      int oper,
      const char* argp,
      size_t len,
      int argi,
      long argl,
      int ret,
      size_t* processed)
    {
      // Unused arguments
      (void)argi;
      (void)argl;

      if (ret && oper == (BIO_CB_READ | BIO_CB_RETURN))
      {
        // Pipe object
        void* ctx = (BIO_get_callback_arg(b));
        int got = recv_callback(ctx, (uint8_t*)argp, len);

        // WANTS_READ
        if (got == TLS_READING)
        {
          LOG_TRACE_FMT("TLS Session::recv_cb() : WANTS_READ");
          *processed = 0;
          return -1;
        }
        else
        {
          LOG_TRACE_FMT(
            "TLS Session::recv_cb() : Got {} bytes of {}", got, len);
        }

        // If got less than requested, return WANT_READ
        if ((size_t)got < len)
        {
          *processed = got;
          return 1;
        }

        // Write to the actual BIO so SSL can use it
        BIO_write_ex(b, argp, got, processed);

        // The buffer should be enough, we can't return WANT_WRITE here
        if ((size_t)got != *processed)
        {
          LOG_TRACE_FMT("TLS Session::recv_cb() : BIO error");
          *processed = got;
          return -1;
        }

        // If original return was -1 because it didn't find anything to read,
        // return 1 to say we actually read something. This is common when the
        // buffer is empty and needs an external read, so let's not log this.
        if (got > 0 && ret < 0)
        {
          return 1;
        }
      }

      // Unless we detected an error, the return value is always the same as the
      // original operation.
      return ret;
    }
  };
}
