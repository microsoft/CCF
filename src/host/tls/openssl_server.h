// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

// OpenSSL-native TLS/plaintext TCP server for RPC interfaces. OpenSSL owns the
// socket fd directly. The host libuv loop reports readiness, while
// per-connection OrderedTasks drive non-blocking handshake, reads, writes, and
// graceful close away from the loop thread.

#include "ccf/crypto/openssl/openssl_wrappers.h"
#include "ds/internal_logger.h"
#include "tasks/ordered_tasks.h"
#include "tasks/task_system.h"
#include "tasks/worker.h"
#include "tcp/msg_types.h"

#include <arpa/inet.h>
#include <atomic>
#include <cassert>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <functional>
#include <memory>
#include <mutex>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <optional>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <system_error>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <uv.h>
#include <vector>

namespace asynchost
{
  namespace details
  {
    struct SocketOptionError
    {
      const char* option = nullptr;
      int error = 0;
    };

    inline std::optional<SocketOptionError> configure_tcp_connection(int fd)
    {
      const auto set_option = [fd](
                                int level,
                                int option,
                                const char* option_name,
                                int value) -> std::optional<SocketOptionError> {
        if (setsockopt(fd, level, option, &value, sizeof(value)) != 0)
        {
          return SocketOptionError{option_name, errno};
        }
        return std::nullopt;
      };

      const int one = 1;
      if (auto error = set_option(IPPROTO_TCP, TCP_NODELAY, "TCP_NODELAY", one))
      {
        return error;
      }
      if (
        auto error = set_option(SOL_SOCKET, SO_KEEPALIVE, "SO_KEEPALIVE", one))
      {
        return error;
      }
      if (
        auto error = set_option(IPPROTO_TCP, TCP_KEEPIDLE, "TCP_KEEPIDLE", 30))
      {
        return error;
      }
      if (
        auto error = set_option(IPPROTO_TCP, TCP_KEEPINTVL, "TCP_KEEPINTVL", 1))
      {
        return error;
      }
      return set_option(IPPROTO_TCP, TCP_KEEPCNT, "TCP_KEEPCNT", 10);
    }
  }

  class OpenSSLServer
  {
  public:
    // Invoked on a worker with a complete chunk of decrypted bytes, the
    // certificate captured during this connection's handshake, and the
    // soft-limit decision taken when the connection was admitted.
    using OnData = std::function<void(
      ::tcp::ConnID conn_id,
      std::vector<uint8_t> data,
      const std::vector<uint8_t>& peer_cert,
      bool soft_limited)>;

    // Invoked on the libuv thread when a connection is torn down (peer
    // disconnect, error, or close_connection()). Lets an owner drop per-
    // connection state.
    using OnClose = std::function<void(::tcp::ConnID conn_id)>;

    // Invoked on the libuv thread for each newly accepted connection, before
    // any TLS state is created. Returning nullopt refuses the connection: the
    // socket is closed immediately and OnClose is *not* invoked for it.
    //
    // Otherwise the returned bool is the "admitted above a soft limit"
    // decision, recorded on the connection and handed back to OnData. It is
    // decided here rather than when the first request arrives so that it
    // reflects the connection's position in the admission order, and does not
    // drift for a client which is slow to send.
    //
    // If this returns a value, OnClose is guaranteed to be invoked exactly
    // once for that connection id. Admission control can therefore reserve a
    // resource here and release it in OnClose.
    using OnAccept = std::function<std::optional<bool>(::tcp::ConnID conn_id)>;

  private:
    static constexpr size_t read_chunk = 16384;
    static constexpr size_t max_read_per_event = read_chunk * 4;

    struct OutItem;

    struct Conn
    {
      OpenSSLServer* owner = nullptr;
      int fd = -1;
      uv_poll_t poll{};
      std::shared_ptr<ccf::tasks::OrderedTasks> tls_tasks;
      std::shared_ptr<SSL_CTX> accepted_ctx;
      SSL* ssl = nullptr;
      ::tcp::ConnID id = 0;
      // Admission decision from OnAccept, passed to OnData.
      bool soft_limited = false;
      enum State : uint8_t
      {
        Handshaking,
        Ready
      } state = Handshaking;
      std::vector<uint8_t> peer_cert;
      // Pending plaintext to be encrypted/written; out_off bytes already sent.
      std::vector<uint8_t> outbuf;
      size_t out_off = 0;
      // True when progress needs the socket to become writable (handshake
      // wants write, or there is buffered outbound data).
      bool want_write = false;
      // A close was requested but is deferred until the buffered output has
      // been fully written, so a response queued just before close is not
      // truncated.
      bool close_after_flush = false;
      // Last time any I/O happened on this connection; used for idle timeout.
      std::chrono::steady_clock::time_point last_active =
        std::chrono::steady_clock::now();

      // The fields below are accessed only on the libuv thread. Polling stays
      // stopped while worker_active is true.
      std::vector<OutItem> pending_commands;
      int pending_events = 0;
      bool worker_active = false;
      bool close_requested = false;
    };

    struct OutItem
    {
      ::tcp::ConnID id = 0;
      std::vector<uint8_t> data;
      bool close = false;
    };

    struct DriveInput
    {
      int events = 0;
      std::vector<OutItem> commands;
      bool close_requested = false;
    };

    struct DriveResult
    {
      std::shared_ptr<Conn> conn;
      bool alive = true;
      // The pass stopped at the per-pass read cap with bytes still available
      // that will not produce a new readability event. The loop must schedule
      // another pass rather than re-arm polling.
      bool more_to_read = false;
      std::chrono::steady_clock::time_point last_active;
    };

    std::shared_ptr<SSL_CTX> ctx;
    uv_loop_t* loop = nullptr;
    ::tcp::ConnID next_id = 1;
    // Optional shared id source so multiple servers (one per interface)
    // allocate connection ids from a single global space - required for a
    // global session registry and reply routing.
    std::atomic<::tcp::ConnID>* shared_next_id = nullptr;
    std::chrono::steady_clock::time_point last_idle_sweep =
      std::chrono::steady_clock::now();
    size_t pending_uv_closes = 0;
    std::thread::id initialising_thread_id;
    std::thread::id loop_thread_id;

    // Close a connection after this much inactivity (no I/O); nullopt disables
    // idle closure. A libuv timer wakes every idle_sweep_interval_ms to check.
    static constexpr int idle_sweep_interval_ms = 1000;
    std::optional<std::chrono::milliseconds> idle_timeout;

    // Cross-thread outbound queue: send()/close_connection() append here from
    // any thread and wake the loop, which drains it on the libuv thread.
    std::vector<OutItem> pending_out;
    std::vector<DriveResult> completed_drives;

    // Cross-thread server-cert (re)load requests (deferred cert / rotation),
    // applied on the loop thread so `ctx` is only ever touched there.
    std::vector<std::pair<std::string, std::string>> pending_certs;

    // ALPN protocol advertised by the server (wire format, length-prefixed),
    // e.g. "\x02h2" or "\x08http/1.1". Empty disables ALPN.
    std::string alpn_wire;
    OnData on_data;
    OnClose on_close;
    OnAccept on_accept;

    std::mutex out_mutex;
    std::mutex lifecycle_mutex;
    std::condition_variable stopped_cv;
    std::unordered_map<int, std::shared_ptr<Conn>> conns;
    std::unordered_map<Conn*, std::shared_ptr<Conn>> closing_conns;
    std::unordered_map<::tcp::ConnID, int> id_to_fd;
    uv_async_t wake_handle{};
    uv_timer_t idle_timer{};
    uv_poll_t listen_poll{};
    int listen_fd = -1;
    uint16_t bound_port = 0;
    // Plaintext (UNSECURED) interface: no TLS, raw socket I/O.
    bool plaintext = false;
    bool listen_poll_initialised = false;
    bool wake_handle_initialised = false;
    bool idle_timer_initialised = false;
    bool verbose = false;
    bool started = false;
    bool stopping = false;
    bool shutdown_started = false;
    // Set once every connection has gone *and* the server's own handles have
    // been handed to uv_close(). Until then pending_uv_closes reaching zero is
    // only a lull between connection closures, not the end of shutdown.
    bool handles_closing = false;
    bool stopped = false;
    bool loop_thread_seen = false;

    void logf(const char* fmt, ...) const
    {
      if (!verbose)
      {
        return;
      }
      va_list args; // NOLINT
      va_start(args, fmt);
      (void)std::vfprintf(stderr, fmt, args);
      (void)std::fputc('\n', stderr);
      va_end(args);
    }

    static bool set_nonblocking(int fd)
    {
      int flags = fcntl(fd, F_GETFL, 0);
      if (flags < 0)
      {
        return false;
      }
      return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
    }

    static bool load_cert_key(
      SSL_CTX* ctx, const std::string& cert_pem, const std::string& key_pem)
    {
      namespace OpenSSL = ccf::crypto::OpenSSL;

      OpenSSL::Unique_BIO cbio(
        cert_pem.data(), static_cast<int>(cert_pem.size()));
      // check_null defaults to false for this overload: a malformed PEM yields
      // a null pointer rather than an exception.
      OpenSSL::Unique_X509 cert(cbio, true);
      if (cert == nullptr)
      {
        return false;
      }
      if (SSL_CTX_use_certificate(ctx, cert) != 1)
      {
        return false;
      }

      OpenSSL::Unique_BIO kbio(
        key_pem.data(), static_cast<int>(key_pem.size()));
      OpenSSL::Unique_PKEY pkey(
        PEM_read_bio_PrivateKey(kbio, nullptr, nullptr, nullptr),
        EVP_PKEY_free,
        false);
      if (pkey == nullptr)
      {
        return false;
      }
      if (SSL_CTX_use_PrivateKey(ctx, pkey) != 1)
      {
        return false;
      }

      return SSL_CTX_check_private_key(ctx) == 1;
    }

    // Build a server SSL_CTX (min TLS 1.2, ALPN if configured) and load the
    // cert/key. Returns nullptr on failure. Called on the loop thread.
    //
    // This is the only place CCF's inbound TLS policy is defined. It is
    // asserted from the wire by src/host/test/openssl_server_test.cpp and, for
    // a running service, by tests/tls_groups.py.
    std::shared_ptr<SSL_CTX> build_server_ctx(
      const std::string& cert_pem, const std::string& key_pem)
    {
      SSL_CTX* c = SSL_CTX_new(TLS_server_method());
      if (c == nullptr)
      {
        return {};
      }
      // Require at least TLS 1.2, support up to 1.3
      if (SSL_CTX_set_min_proto_version(c, TLS1_2_VERSION) != 1)
      {
        SSL_CTX_free(c);
        return {};
      }

      // Disable renegotiation to avoid DoS
      SSL_CTX_set_options(
        c,
        SSL_OP_CIPHER_SERVER_PREFERENCE |
          SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION |
          SSL_OP_NO_RENEGOTIATION);

      // Set cipher for TLS 1.2
      const auto* const cipher_list =
        "ECDHE-ECDSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES128-GCM-SHA256";
      if (SSL_CTX_set_cipher_list(c, cipher_list) != 1)
      {
        SSL_CTX_free(c);
        return {};
      }

      // Set cipher for TLS 1.3
      const auto* const ciphersuites =
        "TLS_AES_256_GCM_SHA384:"
        "TLS_AES_128_GCM_SHA256";
      if (SSL_CTX_set_ciphersuites(c, ciphersuites) != 1)
      {
        SSL_CTX_free(c);
        return {};
      }

      // Prefer hybrid post-quantum groups when available, while retaining the
      // approved classical groups as fallbacks
      if (
        SSL_CTX_set1_groups_list(
          c,
          "?SecP384r1MLKEM1024:?SecP256r1MLKEM768:?X25519MLKEM768:"
          "P-521:P-384:P-256") != 1)
      {
        SSL_CTX_free(c);
        return {};
      }

      // Allow buffer to be relocated between WANT_WRITE retries, and do partial
      // writes if possible. do_write() retries SSL_write() from a std::vector
      // which drive_connection() may have appended to (and so reallocated)
      // since the previous attempt, so both are required.
      SSL_CTX_set_mode(
        c, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE);

      // Request the client certificate during the handshake so it can be used
      // for application-level caller authentication (user/member cert auth).
      // Verification is not enforced here - the application decides.
      SSL_CTX_set_verify(
        c, SSL_VERIFY_PEER, [](int, X509_STORE_CTX*) { return 1; });
      if (!alpn_wire.empty())
      {
        SSL_CTX_set_alpn_select_cb(c, alpn_select_cb, this);
      }
      if (!load_cert_key(c, cert_pem, key_pem))
      {
        SSL_CTX_free(c);
        return {};
      }
      return {c, SSL_CTX_free};
    }

    void update_interest(Conn& c) const
    {
      const int events = UV_READABLE | (c.want_write ? UV_WRITABLE : 0);
      const int rc = uv_poll_start(&c.poll, events, on_connection_poll);
      if (rc != 0)
      {
        logf("uv_poll_start error: %s", uv_strerror(rc));
      }
    }

    static int alpn_select_cb(
      SSL* /*ssl*/,
      const unsigned char** out,
      unsigned char* outlen,
      const unsigned char* in,
      unsigned int inlen,
      void* arg)
    {
      auto* self = static_cast<OpenSSLServer*>(arg);
      const auto& wire = self->alpn_wire;
      if (wire.empty())
      {
        return SSL_TLSEXT_ERR_NOACK;
      }
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      const auto* protos = reinterpret_cast<const unsigned char*>(wire.data());
      if (
        SSL_select_next_proto(
          const_cast<unsigned char**>(out),
          outlen,
          protos,
          static_cast<unsigned int>(wire.size()),
          in,
          inlen) != OPENSSL_NPN_NEGOTIATED)
      {
        return SSL_TLSEXT_ERR_NOACK;
      }
      return SSL_TLSEXT_ERR_OK;
    }

    // Returns false if the connection should be closed.
    bool do_handshake(Conn& c, bool& more_to_read)
    {
      // The error queue is thread-local and SSL_get_error() consults it. Clear
      // it before each operation because successive actions for this
      // connection may execute on different workers.
      ERR_clear_error();
      const int r = SSL_accept(c.ssl);
      if (r == 1)
      {
        c.state = Conn::Ready;
        c.want_write = false;
        X509* cert = SSL_get_peer_certificate(c.ssl);
        if (cert != nullptr)
        {
          const int len = i2d_X509(cert, nullptr);
          if (len > 0)
          {
            c.peer_cert.resize(static_cast<size_t>(len));
            unsigned char* p = c.peer_cert.data();
            if (i2d_X509(cert, &p) != len)
            {
              c.peer_cert.clear();
            }
          }
          X509_free(cert);
        }
        logf("conn %llu: handshake complete", (unsigned long long)c.id);
        return do_read(c, more_to_read) && do_write(c);
      }

      const int e = SSL_get_error(c.ssl, r);
      if (e == SSL_ERROR_WANT_READ)
      {
        c.want_write = false;
        return true;
      }
      if (e == SSL_ERROR_WANT_WRITE)
      {
        c.want_write = true;
        return true;
      }
      logf("conn %llu: handshake error %d", (unsigned long long)c.id, e);
      return false;
    }

    // Returns false if the connection should be closed.
    bool do_read_plaintext(Conn& c, bool& more_to_read)
    {
      size_t total_read = 0;
      while (total_read < max_read_per_event)
      {
        uint8_t buf[read_chunk];
        const ssize_t n = ::recv(c.fd, buf, sizeof(buf), 0);
        if (n > 0)
        {
          total_read += static_cast<size_t>(n);
          if (on_data)
          {
            on_data(
              c.id,
              std::vector<uint8_t>(buf, buf + static_cast<size_t>(n)),
              c.peer_cert,
              c.soft_limited);
          }
          continue;
        }
        if (n == 0)
        {
          return false; // peer closed
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
          return true;
        }
        if (errno == EINTR)
        {
          continue;
        }
        return false;
      }
      // Stopped at the cap rather than at EAGAIN, so there may be more in the
      // socket buffer. Level-triggered polling would report it again, but ask
      // for another pass directly rather than depend on that.
      more_to_read = true;
      return true;
    }

    // Returns false if the connection should be closed.
    bool do_write_plaintext(Conn& c)
    {
      while (c.out_off < c.outbuf.size())
      {
        const ssize_t n = ::send(
          c.fd,
          c.outbuf.data() + c.out_off,
          c.outbuf.size() - c.out_off,
          MSG_NOSIGNAL);
        if (n > 0)
        {
          c.out_off += static_cast<size_t>(n);
          continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        {
          c.want_write = true;
          return true;
        }
        if (n < 0 && errno == EINTR)
        {
          continue;
        }
        return false;
      }
      c.outbuf.clear();
      c.out_off = 0;
      c.want_write = false;
      return true;
    }

    // Returns false if the connection should be closed.
    bool do_read(Conn& c, bool& more_to_read)
    {
      if (c.ssl == nullptr)
      {
        return do_read_plaintext(c, more_to_read);
      }
      size_t total_read = 0;
      while (total_read < max_read_per_event)
      {
        uint8_t buf[read_chunk];
        ERR_clear_error();
        const int n = SSL_read(c.ssl, buf, static_cast<int>(sizeof(buf)));
        if (n > 0)
        {
          total_read += static_cast<size_t>(n);
          if (on_data)
          {
            on_data(
              c.id,
              std::vector<uint8_t>(buf, buf + n),
              c.peer_cert,
              c.soft_limited);
          }
          continue;
        }

        const int e = SSL_get_error(c.ssl, n);
        if (e == SSL_ERROR_WANT_READ)
        {
          return true;
        }
        if (e == SSL_ERROR_WANT_WRITE)
        {
          // A renegotiation needs the socket to become writable.
          c.want_write = true;
          return true;
        }
        // SSL_ERROR_ZERO_RETURN (clean close), an unclean EOF from the peer
        // (no close_notify), or a fatal error - in all cases close.
        return false;
      }

      // Stopped at the per-pass cap rather than at WANT_READ. OpenSSL may
      // still be holding bytes it has already taken off the socket - either
      // decrypted plaintext or a buffered record. Those bytes will never
      // produce a readability event, so waiting for one here would stall the
      // connection until the peer happened to send more. Ask for another pass
      // instead. SSL_has_pending() covers both processed and unprocessed
      // buffered data; if it is only a partial record, the next pass returns
      // WANT_READ and polling resumes normally.
      more_to_read = SSL_has_pending(c.ssl) == 1;
      return true;
    }

    // Returns false if the connection should be closed. Implements
    // backpressure: a WANT_WRITE leaves the remaining plaintext buffered and
    // arms UV_WRITABLE.
    bool do_write(Conn& c)
    {
      if (c.ssl == nullptr)
      {
        return do_write_plaintext(c);
      }
      while (c.out_off < c.outbuf.size())
      {
        ERR_clear_error();
        const int n = SSL_write(
          c.ssl,
          c.outbuf.data() + c.out_off,
          static_cast<int>(c.outbuf.size() - c.out_off));
        if (n > 0)
        {
          c.out_off += static_cast<size_t>(n);
          continue;
        }

        const int e = SSL_get_error(c.ssl, n);
        if (e == SSL_ERROR_WANT_WRITE)
        {
          c.want_write = true;
          return true;
        }
        if (e == SSL_ERROR_WANT_READ)
        {
          // A renegotiation needs to read before we can write more.
          return true;
        }
        logf("conn %llu: write err %d", (unsigned long long)c.id, e);
        return false;
      }

      // Fully flushed.
      c.outbuf.clear();
      c.out_off = 0;
      c.want_write = false;
      return true;
    }

    void complete_drive(
      std::shared_ptr<Conn> conn, bool alive, bool more_to_read)
    {
      {
        std::lock_guard<std::mutex> guard(out_mutex);
        completed_drives.push_back(
          {std::move(conn),
           alive,
           more_to_read,
           std::chrono::steady_clock::now()});
      }
      // Unlike wake(), this must signal even while stopping: shutdown only
      // completes once the loop has observed every outstanding completion and
      // closed the corresponding connection. The wake handle is guaranteed to
      // still be open here, because finish_stopping_on_loop() only closes it
      // once `conns` is empty, and a connection with a running worker has not
      // yet been removed from `conns`.
      std::lock_guard<std::mutex> guard(lifecycle_mutex);
      if (wake_handle_initialised)
      {
        (void)uv_async_send(&wake_handle);
      }
    }

    void drive_connection(std::shared_ptr<Conn> conn, DriveInput input)
    {
      bool alive = true;
      bool more_to_read = false;

      if (conn->ssl == nullptr && conn->accepted_ctx != nullptr)
      {
        conn->ssl = SSL_new(conn->accepted_ctx.get());
        if (conn->ssl == nullptr || SSL_set_fd(conn->ssl, conn->fd) != 1)
        {
          if (conn->ssl != nullptr)
          {
            SSL_free(conn->ssl);
            conn->ssl = nullptr;
          }
          complete_drive(std::move(conn), false, false);
          return;
        }
        SSL_set_accept_state(conn->ssl);
      }

      for (auto& command : input.commands)
      {
        if (command.close)
        {
          conn->close_after_flush = true;
        }
        else
        {
          conn->outbuf.insert(
            conn->outbuf.end(), command.data.begin(), command.data.end());
        }
      }
      if (input.close_requested)
      {
        conn->close_after_flush = true;
      }

      if (conn->state == Conn::Handshaking)
      {
        alive = do_handshake(*conn, more_to_read);
      }
      else
      {
        if ((input.events & (UV_READABLE | UV_DISCONNECT)) != 0)
        {
          alive = do_read(*conn, more_to_read);
        }
        if (alive)
        {
          alive = do_write(*conn);
        }
      }

      if (
        alive && conn->close_after_flush &&
        conn->out_off >= conn->outbuf.size())
      {
        alive = false;
      }
      if (!alive && conn->ssl != nullptr)
      {
        ERR_clear_error();
        (void)SSL_shutdown(conn->ssl);
        SSL_free(conn->ssl);
        conn->ssl = nullptr;
      }
      complete_drive(std::move(conn), alive, more_to_read);
    }

    void dispatch_connection(const std::shared_ptr<Conn>& conn)
    {
      if (conn->worker_active)
      {
        return;
      }
      (void)uv_poll_stop(&conn->poll);
      conn->worker_active = true;
      DriveInput input;
      input.events = std::exchange(conn->pending_events, 0);
      input.commands.swap(conn->pending_commands);
      input.close_requested = std::exchange(conn->close_requested, false);
      conn->tls_tasks->add_action(ccf::tasks::make_basic_action(
        [this, conn, input = std::move(input)]() mutable {
          drive_connection(conn, std::move(input));
        },
        "OpenSSLServer::drive_connection"));
    }

    void close_conn(int fd)
    {
      auto it = conns.find(fd);
      if (it == conns.end())
      {
        return;
      }
      if (on_close)
      {
        on_close(it->second->id);
      }
      id_to_fd.erase(it->second->id);
      auto conn = it->second;
      conns.erase(it);
      (void)uv_poll_stop(&conn->poll);
      assert(conn->ssl == nullptr);
      ::close(fd);
      conn->fd = -1;
      auto* raw = conn.get();
      closing_conns.emplace(raw, std::move(conn));
      {
        std::lock_guard<std::mutex> guard(lifecycle_mutex);
        ++pending_uv_closes;
      }
      uv_close(
        reinterpret_cast<uv_handle_t*>(&raw->poll), on_connection_poll_closed);
      finish_stopping_on_loop();
    }

    void accept_all()
    {
      for (;;)
      {
        sockaddr_storage peer{};
        socklen_t plen = sizeof(peer);
        const int cfd = accept4(
          listen_fd,
          reinterpret_cast<sockaddr*>(&peer),
          &plen,
          SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (cfd < 0)
        {
          if (errno == EAGAIN || errno == EWOULDBLOCK)
          {
            break;
          }
          if (errno == EINTR)
          {
            continue;
          }
          const auto err = errno;
          logf(
            "accept error: %s", std::generic_category().message(err).c_str());
          break;
        }

        if (const auto error = details::configure_tcp_connection(cfd))
        {
          LOG_FAIL_FMT(
            "setsockopt({}) failed for accepted RPC socket: {}",
            error->option,
            std::generic_category().message(error->error));
          ::close(cfd);
          continue;
        }

        const ::tcp::ConnID cid = (shared_next_id != nullptr) ?
          shared_next_id->fetch_add(1) :
          next_id++;

        // Admission control runs here, before any TLS context, SSL object or
        // task queue is created for the connection. A refused connection
        // therefore costs nothing beyond the accept itself, and - crucially -
        // an admitted connection is counted from the moment it exists, not
        // from the moment it first sends a request. A client which completes
        // the TCP and TLS handshakes and then goes silent still holds a file
        // descriptor and TLS state, and must count against the caps.
        bool soft_limited = false;
        if (on_accept)
        {
          const auto admission = on_accept(cid);
          if (!admission.has_value())
          {
            ::close(cfd);
            continue;
          }
          soft_limited = *admission;
        }

        // From here on the connection has been admitted, so every failure path
        // must release it by invoking on_close.
        const auto release_admitted = [this, cid]() {
          if (on_accept && on_close)
          {
            on_close(cid);
          }
        };

        auto c = std::make_unique<Conn>();
        c->owner = this;
        c->fd = cfd;
        c->id = cid;
        c->soft_limited = soft_limited;
        c->tls_tasks = ccf::tasks::OrderedTasks::create(
          ccf::tasks::get_main_job_board(),
          "TLS connection " + std::to_string(c->id));

        if (plaintext)
        {
          // No TLS: ready to read/write raw bytes immediately.
          c->state = Conn::Ready;
        }
        else
        {
          if (ctx == nullptr)
          {
            // No server certificate yet - refuse the connection until one is
            // supplied (see set_server_cert). Expected while a joining node
            // waits for the service certificate, so this is not an error, but
            // it is otherwise invisible, hence the log.
            LOG_DEBUG_FMT(
              "Refusing connection {}: no server certificate yet", cid);
            ::close(cfd);
            release_admitted();
            continue;
          }
          c->accepted_ctx = ctx;
        }

        const int poll_rc = uv_poll_init_socket(loop, &c->poll, cfd);
        if (poll_rc != 0)
        {
          logf("uv_poll_init_socket error: %s", uv_strerror(poll_rc));
          ::close(cfd);
          release_admitted();
          continue;
        }
        c->poll.data = c.get();
        const int start_rc =
          uv_poll_start(&c->poll, UV_READABLE, on_connection_poll);
        if (start_rc != 0)
        {
          logf("uv_poll_start error: %s", uv_strerror(start_rc));
          ::close(cfd);
          c->fd = -1;
          auto* raw = c.get();
          closing_conns.emplace(raw, std::move(c));
          {
            std::lock_guard<std::mutex> guard(lifecycle_mutex);
            ++pending_uv_closes;
          }
          uv_close(
            reinterpret_cast<uv_handle_t*>(&raw->poll),
            on_connection_poll_closed);
          release_admitted();
          continue;
        }
        conns.emplace(cfd, std::move(c));
        id_to_fd.emplace(cid, cfd);
        logf("accepted conn on fd %d", cfd);
      }
    }

    void on_conn_event(int fd, int events)
    {
      auto it = conns.find(fd);
      if (it == conns.end())
      {
        return;
      }
      auto& c = it->second;
      c->last_active = std::chrono::steady_clock::now();
      c->pending_events |= events;
      dispatch_connection(c);
    }

    void mark_loop_thread()
    {
      std::lock_guard<std::mutex> guard(lifecycle_mutex);
      loop_thread_id = std::this_thread::get_id();
      loop_thread_seen = true;
    }

    static void on_connection_poll(uv_poll_t* handle, int status, int events)
    {
      auto* conn = static_cast<Conn*>(handle->data);
      auto* self = conn->owner;
      self->mark_loop_thread();
      if (status < 0)
      {
        auto it = self->conns.find(conn->fd);
        if (it != self->conns.end())
        {
          it->second->close_requested = true;
          self->dispatch_connection(it->second);
        }
        return;
      }
      self->on_conn_event(conn->fd, events);
    }

    static void on_connection_poll_closed(uv_handle_t* handle)
    {
      auto* conn = static_cast<Conn*>(handle->data);
      auto* self = conn->owner;
      self->closing_conns.erase(conn);
      self->complete_uv_close();
    }

    void wake()
    {
      std::lock_guard<std::mutex> guard(lifecycle_mutex);
      if (wake_handle_initialised && !stopping)
      {
        (void)uv_async_send(&wake_handle);
      }
    }

    // Apply worker completions and cross-thread commands on the libuv thread.
    void drain_pending_out()
    {
      std::vector<OutItem> items;
      std::vector<DriveResult> completions;
      std::vector<std::pair<std::string, std::string>> certs;
      {
        std::lock_guard<std::mutex> g(out_mutex);
        std::swap(items, pending_out);
        std::swap(completions, completed_drives);
        std::swap(certs, pending_certs);
      }

      for (auto& [cert_pem, key_pem] : certs)
      {
        // This runs inside a libuv callback, so nothing may escape: an
        // operator-supplied cert which fails to parse must not terminate the
        // process, it must leave the previous context in place.
        try
        {
          auto nc = build_server_ctx(cert_pem, key_pem);
          if (nc == nullptr)
          {
            LOG_FAIL_FMT("set_server_cert: failed to build TLS context");
            continue;
          }
          ctx = std::move(nc);
        }
        catch (const std::exception& e)
        {
          LOG_FAIL_FMT(
            "set_server_cert: failed to build TLS context: {}", e.what());
        }
      }

      for (auto& item : items)
      {
        auto fit = id_to_fd.find(item.id);
        if (fit == id_to_fd.end())
        {
          continue;
        }
        auto cit = conns.find(fit->second);
        if (cit == conns.end())
        {
          continue;
        }
        if (item.close)
        {
          cit->second->close_requested = true;
        }
        else
        {
          cit->second->last_active = std::chrono::steady_clock::now();
          cit->second->pending_commands.push_back(std::move(item));
        }
      }

      for (auto& completion : completions)
      {
        const auto& conn = completion.conn;
        auto it = conns.find(conn->fd);
        if (it == conns.end() || it->second.get() != conn.get())
        {
          continue;
        }
        conn->worker_active = false;
        conn->last_active = completion.last_active;
        if (!completion.alive)
        {
          close_conn(conn->fd);
        }
        else if (completion.more_to_read)
        {
          // Data is buffered where polling cannot see it, so ask for another
          // pass explicitly. The loop below dispatches on pending_events.
          conn->pending_events |= UV_READABLE;
        }
      }

      for (auto& [fd, conn] : conns)
      {
        if (conn->worker_active)
        {
          continue;
        }
        if (
          conn->close_requested || !conn->pending_commands.empty() ||
          conn->pending_events != 0)
        {
          dispatch_connection(conn);
        }
        else
        {
          update_interest(*conn);
        }
      }
    }

    // Close connections idle longer than idle_timeout (loop thread).
    void sweep_idle()
    {
      if (!idle_timeout.has_value())
      {
        return;
      }
      const auto now = std::chrono::steady_clock::now();
      std::vector<int> to_close;
      for (const auto& [fd, c] : conns)
      {
        if (!c->worker_active && now - c->last_active > *idle_timeout)
        {
          to_close.push_back(fd);
        }
      }
      for (const int fd : to_close)
      {
        logf("closing idle connection on fd %d", fd);
        auto it = conns.find(fd);
        if (it != conns.end())
        {
          it->second->close_requested = true;
          dispatch_connection(it->second);
        }
      }
    }

    static void on_listen_poll(uv_poll_t* handle, int status, int events)
    {
      auto* self = static_cast<OpenSSLServer*>(handle->data);
      self->mark_loop_thread();
      if (status < 0)
      {
        self->request_stop_on_loop();
        return;
      }
      if ((events & UV_READABLE) != 0)
      {
        self->accept_all();
      }
    }

    static void on_wake(uv_async_t* handle)
    {
      auto* self = static_cast<OpenSSLServer*>(handle->data);
      self->mark_loop_thread();
      bool should_stop = false;
      {
        std::lock_guard<std::mutex> guard(self->lifecycle_mutex);
        should_stop = self->stopping;
      }
      if (should_stop)
      {
        self->request_stop_on_loop();
      }
      self->drain_pending_out();
    }

    static void on_idle_timer(uv_timer_t* handle)
    {
      auto* self = static_cast<OpenSSLServer*>(handle->data);
      self->mark_loop_thread();
      self->sweep_idle();
    }

    static void on_server_handle_closed(uv_handle_t* handle)
    {
      auto* self = static_cast<OpenSSLServer*>(handle->data);
      self->complete_uv_close();
    }

    void complete_uv_close()
    {
      std::lock_guard<std::mutex> guard(lifecycle_mutex);
      if (pending_uv_closes > 0)
      {
        --pending_uv_closes;
      }
      // Only finish once finish_stopping_on_loop() has queued the listener,
      // timer and async handles for closure. Connections close one at a time,
      // so without the handles_closing gate the first connection to finish
      // closing would drive the count to zero and declare shutdown complete
      // while other connections, and all three server handles, were still
      // open - leaving uv_loop_close() to fail with EBUSY.
      if (stopping && handles_closing && pending_uv_closes == 0)
      {
        stopped = true;
        stopped_cv.notify_all();
      }
    }

    // Requires lifecycle_mutex to be held by the caller. uv_close() never runs
    // its callback synchronously, so complete_uv_close() cannot re-enter the
    // lock from here.
    void close_server_handle(uv_handle_t* handle)
    {
      if (uv_is_closing(handle) == 0)
      {
        ++pending_uv_closes;
        uv_close(handle, on_server_handle_closed);
      }
    }

    void request_stop_on_loop()
    {
      {
        std::lock_guard<std::mutex> guard(lifecycle_mutex);
        if (shutdown_started)
        {
          return;
        }
        stopping = true;
        shutdown_started = true;
      }
      // May run before start() finished initialising, if start() threw part
      // way through, so the handle may not exist yet.
      if (listen_poll_initialised)
      {
        (void)uv_poll_stop(&listen_poll);
      }
      if (listen_fd >= 0)
      {
        ::close(listen_fd);
        listen_fd = -1;
      }
      for (auto& [fd, conn] : conns)
      {
        conn->close_requested = true;
        dispatch_connection(conn);
      }
      finish_stopping_on_loop();
    }

    // Loop thread. Completes shutdown once every connection has gone: stops
    // the idle timer and closes the server's own uv handles.
    //
    // Every flag touched here is also read from other threads (see wake() and
    // complete_drive()), so the whole body runs under lifecycle_mutex, and
    // each *_initialised flag is cleared *before* the corresponding uv_close().
    // Clearing afterwards would leave a window in which another thread sees
    // the handle as usable and calls uv_async_send() on a closing handle.
    void finish_stopping_on_loop()
    {
      std::lock_guard<std::mutex> guard(lifecycle_mutex);
      if (!stopping || handles_closing || !conns.empty())
      {
        return;
      }

      // Every connection has gone. From here on there is nothing left to
      // close but the server's own handles, so once the count reaches zero
      // shutdown really is complete.
      handles_closing = true;

      if (idle_timer_initialised)
      {
        idle_timer_initialised = false;
        (void)uv_timer_stop(&idle_timer);
        close_server_handle(reinterpret_cast<uv_handle_t*>(&idle_timer));
      }
      if (listen_poll_initialised)
      {
        listen_poll_initialised = false;
        close_server_handle(reinterpret_cast<uv_handle_t*>(&listen_poll));
      }
      if (wake_handle_initialised)
      {
        wake_handle_initialised = false;
        close_server_handle(reinterpret_cast<uv_handle_t*>(&wake_handle));
      }
      if (pending_uv_closes == 0)
      {
        stopped = true;
        stopped_cv.notify_all();
      }
    }

  public:
    OpenSSLServer(
      const std::string& cert_pem,
      const std::string& key_pem,
      const std::string& host,
      uint16_t port,
      OnData on_data_,
      OnClose on_close_ = {},
      const std::string& alpn = "",
      bool plaintext_ = false,
      bool verbose_ = false,
      std::atomic<::tcp::ConnID>* shared_next_id_ = nullptr,
      std::optional<std::chrono::milliseconds> idle_timeout_ = std::nullopt,
      OnAccept on_accept_ = {},
      uv_loop_t* loop_ = uv_default_loop()) :
      loop(loop_),
      shared_next_id(shared_next_id_),
      idle_timeout(idle_timeout_),
      on_data(std::move(on_data_)),
      on_close(std::move(on_close_)),
      on_accept(std::move(on_accept_)),
      plaintext(plaintext_),
      verbose(verbose_)
    {
      if (!alpn.empty())
      {
        alpn_wire.push_back(static_cast<char>(alpn.size()));
        alpn_wire.append(alpn);
      }

      // Plaintext interfaces have no TLS context. TLS interfaces build their
      // context now if the cert is already available, or defer until
      // set_server_cert() (e.g. a joining node receiving the service cert).
      if (!plaintext && !cert_pem.empty())
      {
        ctx = build_server_ctx(cert_pem, key_pem);
        if (ctx == nullptr)
        {
          throw std::runtime_error("Failed to load server cert/key");
        }
      }

      // Resolve and bind the listening address. Using getaddrinfo (rather than
      // inet_pton) supports hostnames (e.g. "localhost") and IPv6 (e.g. "::1"),
      // not just IPv4 literals.
      addrinfo hints{};
      hints.ai_family = AF_UNSPEC;
      hints.ai_socktype = SOCK_STREAM;
      hints.ai_flags = AI_PASSIVE;
      addrinfo* res = nullptr;
      const std::string port_str = std::to_string(port);
      if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res) != 0)
      {
        cleanup();
        throw std::runtime_error("getaddrinfo failed for " + host);
      }

      const int one = 1;
      bool bound_ok = false;
      for (addrinfo* ai = res; ai != nullptr; ai = ai->ai_next)
      {
        listen_fd = socket(
          ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
        if (listen_fd < 0)
        {
          continue;
        }
        // SO_REUSEADDR permits rebinding a port left in TIME_WAIT by a
        // previous process. Note that SO_REUSEPORT is deliberately *not* set:
        // it would suppress EADDRINUSE, so two nodes misconfigured onto the
        // same port would both bind successfully and have connections split
        // between them at random, and it would let any process with the same
        // effective UID siphon off a share of inbound connections.
        if (
          setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) !=
          0)
        {
          ::close(listen_fd);
          listen_fd = -1;
          continue;
        }
        if (bind(listen_fd, ai->ai_addr, ai->ai_addrlen) == 0)
        {
          bound_ok = true;
          break;
        }
        ::close(listen_fd);
        listen_fd = -1;
      }
      freeaddrinfo(res);
      if (!bound_ok)
      {
        cleanup();
        throw std::runtime_error("bind() failed for " + host);
      }
      if (listen(listen_fd, SOMAXCONN) != 0)
      {
        cleanup();
        throw std::runtime_error("listen() failed");
      }
      if (!set_nonblocking(listen_fd))
      {
        cleanup();
        throw std::runtime_error("set_nonblocking(listen) failed");
      }

      // Read back the actual bound port (supports ephemeral port 0, v4 and v6).
      sockaddr_storage bound{};
      socklen_t blen = sizeof(bound);
      if (
        getsockname(listen_fd, reinterpret_cast<sockaddr*>(&bound), &blen) == 0)
      {
        if (bound.ss_family == AF_INET6)
        {
          bound_port =
            ntohs(reinterpret_cast<sockaddr_in6*>(&bound)->sin6_port);
        }
        else
        {
          bound_port = ntohs(reinterpret_cast<sockaddr_in*>(&bound)->sin_port);
        }
      }
    }

    OpenSSLServer(const OpenSSLServer&) = delete;
    OpenSSLServer& operator=(const OpenSSLServer&) = delete;
    OpenSSLServer(OpenSSLServer&&) = delete;
    OpenSSLServer& operator=(OpenSSLServer&&) = delete;

    ~OpenSSLServer()
    {
      stop();
      cleanup();
    }

    uint16_t port() const
    {
      return bound_port;
    }

    void start()
    {
      std::lock_guard<std::mutex> guard(lifecycle_mutex);
      if (started)
      {
        return;
      }

      // Mark the server started, and reset the lifecycle flags, *before* any
      // handle is initialised. If one of the steps below throws, the handles
      // which were already initialised are still registered with the loop and
      // must be closed, or uv_loop_close() will fail with EBUSY. stop() does
      // exactly that, but only when `started` is set - so setting it here is
      // what makes a partially-initialised server safe to destroy.
      stopped = false;
      stopping = false;
      shutdown_started = false;
      handles_closing = false;
      initialising_thread_id = std::this_thread::get_id();
      loop_thread_seen = false;
      started = true;

      int rc = uv_poll_init_socket(loop, &listen_poll, listen_fd);
      if (rc != 0)
      {
        throw std::runtime_error(
          std::string("uv_poll_init_socket(listen) failed: ") +
          uv_strerror(rc));
      }
      listen_poll_initialised = true;
      listen_poll.data = this;

      rc = uv_async_init(loop, &wake_handle, on_wake);
      if (rc != 0)
      {
        throw std::runtime_error(
          std::string("uv_async_init failed: ") + uv_strerror(rc));
      }
      wake_handle_initialised = true;
      wake_handle.data = this;

      if (idle_timeout.has_value())
      {
        rc = uv_timer_init(loop, &idle_timer);
        if (rc != 0)
        {
          throw std::runtime_error(
            std::string("uv_timer_init failed: ") + uv_strerror(rc));
        }
        idle_timer_initialised = true;
        idle_timer.data = this;
        rc = uv_timer_start(
          &idle_timer,
          on_idle_timer,
          idle_sweep_interval_ms,
          idle_sweep_interval_ms);
        if (rc != 0)
        {
          throw std::runtime_error(
            std::string("uv_timer_start failed: ") + uv_strerror(rc));
        }
      }

      rc = uv_poll_start(&listen_poll, UV_READABLE, on_listen_poll);
      if (rc != 0)
      {
        throw std::runtime_error(
          std::string("uv_poll_start(listen) failed: ") + uv_strerror(rc));
      }
    }

    void stop()
    {
      std::unique_lock<std::mutex> lock(lifecycle_mutex);
      if (!started || stopped)
      {
        return;
      }
      if (!stopping)
      {
        stopping = true;
        // finish_stopping_on_loop() clears wake_handle_initialised before it
        // closes the handle, so this cannot signal a handle already closing.
        if (wake_handle_initialised)
        {
          (void)uv_async_send(&wake_handle);
        }
      }
      const bool loop_not_started_here = !loop_thread_seen &&
        std::this_thread::get_id() == initialising_thread_id;
      if (loop_not_started_here)
      {
        lock.unlock();
        request_stop_on_loop();
        for (;;)
        {
          {
            std::lock_guard<std::mutex> guard(lifecycle_mutex);
            if (stopped)
            {
              return;
            }
          }
          auto task = ccf::tasks::get_main_job_board().get_task();
          if (task != nullptr)
          {
            ccf::tasks::try_do_task(*task);
          }
          (void)uv_run(loop, UV_RUN_NOWAIT);
          if (task == nullptr)
          {
            // Nothing to do but wait for outstanding uv close callbacks.
            // uv_run(UV_RUN_NOWAIT) returns immediately, so without this the
            // loop below would spin at 100% CPU for the whole shutdown.
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
          }
        }
      }
      if (std::this_thread::get_id() == loop_thread_id)
      {
        lock.unlock();
        request_stop_on_loop();
        return;
      }
      while (!stopped)
      {
        lock.unlock();
        auto task = ccf::tasks::get_main_job_board().get_task();
        if (task != nullptr)
        {
          ccf::tasks::try_do_task(*task);
        }
        lock.lock();
        if (!stopped && task == nullptr)
        {
          stopped_cv.wait_for(lock, std::chrono::milliseconds(1));
        }
      }
    }

    // Thread-safe. Queue plaintext to be encrypted and written to `conn_id`.
    void send(::tcp::ConnID conn_id, const uint8_t* data, size_t len)
    {
      {
        std::lock_guard<std::mutex> g(out_mutex);
        pending_out.push_back(
          {conn_id, std::vector<uint8_t>(data, data + len), false});
      }
      wake();
    }

    // Thread-safe. Request that `conn_id` be torn down.
    void close_connection(::tcp::ConnID conn_id)
    {
      {
        std::lock_guard<std::mutex> g(out_mutex);
        pending_out.push_back({conn_id, {}, true});
      }
      wake();
    }

    // Thread-safe. (Re)load the server certificate/key. Used for deferred cert
    // (a node that learns the service cert after binding) and rotation; applies
    // to connections accepted after it takes effect on the loop thread.
    void set_server_cert(
      const std::string& cert_pem, const std::string& key_pem)
    {
      {
        std::lock_guard<std::mutex> g(out_mutex);
        pending_certs.emplace_back(cert_pem, key_pem);
      }
      wake();
    }

  private:
    void cleanup()
    {
      if (listen_fd >= 0)
      {
        ::close(listen_fd);
        listen_fd = -1;
      }
      ctx.reset();
    }
  };
}
