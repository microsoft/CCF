// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

// OpenSSL-native TLS/plaintext TCP server for RPC interfaces. OpenSSL owns the
// socket fd directly, while the host libuv loop drives non-blocking handshake,
// reads, writes, graceful close, and idle connection cleanup.

#include "tcp/msg_types.h"

#include <arpa/inet.h>
#include <atomic>
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
  class OpenSSLServer
  {
  public:
    // Invoked on the libuv thread with a complete chunk of decrypted bytes for
    // connection `conn_id`. The handler typically hands processing to a worker
    // (e.g. OrderedTasks) and later calls send()/close_connection() from that
    // thread - both are thread-safe and wake the loop.
    using OnData =
      std::function<void(::tcp::ConnID conn_id, std::vector<uint8_t> data)>;

    // Invoked on the libuv thread when a connection is torn down (peer
    // disconnect, error, or close_connection()). Lets an owner drop per-
    // connection state.
    using OnClose = std::function<void(::tcp::ConnID conn_id)>;

  private:
    static constexpr size_t read_chunk = 16384;

    struct Conn
    {
      OpenSSLServer* owner = nullptr;
      int fd = -1;
      uv_poll_t poll{};
      SSL* ssl = nullptr;
      ::tcp::ConnID id = 0;
      enum State : uint8_t
      {
        Handshaking,
        Ready
      } state = Handshaking;
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
    };

    SSL_CTX* ctx = nullptr;
    // Plaintext (UNSECURED) interface: no TLS, raw socket I/O.
    bool plaintext = false;
    // ALPN protocol advertised by the server (wire format, length-prefixed),
    // e.g. "\x02h2" or "\x08http/1.1". Empty disables ALPN.
    std::string alpn_wire;
    uv_loop_t* loop = nullptr;
    int listen_fd = -1;
    uv_poll_t listen_poll{};
    uv_async_t wake_handle{};
    uv_timer_t idle_timer{};
    bool listen_poll_initialised = false;
    bool wake_handle_initialised = false;
    bool idle_timer_initialised = false;
    uint16_t bound_port = 0;
    OnData on_data;
    OnClose on_close;
    bool verbose = false;

    std::unordered_map<int, std::unique_ptr<Conn>> conns;
    std::unordered_map<Conn*, std::unique_ptr<Conn>> closing_conns;
    std::unordered_map<::tcp::ConnID, int> id_to_fd;
    ::tcp::ConnID next_id = 1;
    // Optional shared id source so multiple servers (one per interface)
    // allocate connection ids from a single global space - required for a
    // global session registry and reply routing.
    std::atomic<::tcp::ConnID>* shared_next_id = nullptr;

    // Close a connection after this much inactivity (no I/O); nullopt disables
    // idle closure. A libuv timer wakes every idle_sweep_interval_ms to check.
    static constexpr int idle_sweep_interval_ms = 1000;
    std::optional<std::chrono::milliseconds> idle_timeout;
    std::chrono::steady_clock::time_point last_idle_sweep =
      std::chrono::steady_clock::now();

    // Cross-thread outbound queue: send()/close_connection() append here from
    // any thread and wake the loop, which drains it on the libuv thread.
    struct OutItem
    {
      ::tcp::ConnID id = 0;
      std::vector<uint8_t> data;
      bool close = false;
    };
    std::mutex out_mutex;
    std::vector<OutItem> pending_out;

    // Cross-thread server-cert (re)load requests (deferred cert / rotation),
    // applied on the loop thread so `ctx` is only ever touched there.
    std::vector<std::pair<std::string, std::string>> pending_certs;

    std::mutex lifecycle_mutex;
    std::condition_variable stopped_cv;
    bool started = false;
    bool stopping = false;
    bool shutdown_started = false;
    bool stopped = false;
    size_t pending_uv_closes = 0;
    std::thread::id initialising_thread_id;
    std::thread::id loop_thread_id;
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
      BIO* cbio =
        BIO_new_mem_buf(cert_pem.data(), static_cast<int>(cert_pem.size()));
      if (cbio == nullptr)
      {
        return false;
      }
      X509* cert = PEM_read_bio_X509(cbio, nullptr, nullptr, nullptr);
      BIO_free(cbio);
      if (cert == nullptr)
      {
        return false;
      }
      const bool cert_ok = SSL_CTX_use_certificate(ctx, cert) == 1;
      X509_free(cert);
      if (!cert_ok)
      {
        return false;
      }

      BIO* kbio =
        BIO_new_mem_buf(key_pem.data(), static_cast<int>(key_pem.size()));
      if (kbio == nullptr)
      {
        return false;
      }
      EVP_PKEY* pkey = PEM_read_bio_PrivateKey(kbio, nullptr, nullptr, nullptr);
      BIO_free(kbio);
      if (pkey == nullptr)
      {
        return false;
      }
      const bool key_ok = SSL_CTX_use_PrivateKey(ctx, pkey) == 1;
      EVP_PKEY_free(pkey);
      if (!key_ok)
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
    SSL_CTX* build_server_ctx(
      const std::string& cert_pem, const std::string& key_pem)
    {
      SSL_CTX* c = SSL_CTX_new(TLS_server_method());
      if (c == nullptr)
      {
        return nullptr;
      }
      // Require at least TLS 1.2, support up to 1.3
      if (SSL_CTX_set_min_proto_version(c, TLS1_2_VERSION) != 1)
      {
        SSL_CTX_free(c);
        return nullptr;
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
        return nullptr;
      }

      // Set cipher for TLS 1.3
      const auto* const ciphersuites =
        "TLS_AES_256_GCM_SHA384:"
        "TLS_AES_128_GCM_SHA256";
      if (SSL_CTX_set_ciphersuites(c, ciphersuites) != 1)
      {
        SSL_CTX_free(c);
        return nullptr;
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
        return nullptr;
      }

      // Allow buffer to be relocated between WANT_WRITE retries, and do partial
      // writes if possible. do_write() retries SSL_write() from a std::vector
      // that may have been appended to (and so reallocated) by
      // drain_pending_out() since the previous attempt, so both are required.
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
        return nullptr;
      }
      return c;
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

    // After writing, tear the connection down if a graceful close was requested
    // and all buffered output has been flushed; otherwise update poll interest
    // (re-arming UV_WRITABLE while output remains).
    void finish_or_close(int fd, Conn& c)
    {
      if (c.close_after_flush && c.out_off >= c.outbuf.size())
      {
        close_conn(fd);
      }
      else
      {
        update_interest(c);
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
    bool do_handshake(Conn& c)
    {
      // The error queue is thread-local and shared across every connection
      // serviced by this loop, and SSL_get_error() consults it. Clear it before
      // each SSL operation so a stale error from another connection cannot be
      // misattributed (which would spuriously close healthy connections).
      ERR_clear_error();
      const int r = SSL_accept(c.ssl);
      if (r == 1)
      {
        c.state = Conn::Ready;
        c.want_write = false;
        logf("conn %llu: handshake complete", (unsigned long long)c.id);
        return do_read(c) && do_write(c);
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
    bool do_read_plaintext(Conn& c)
    {
      for (;;)
      {
        uint8_t buf[read_chunk];
        const ssize_t n = ::recv(c.fd, buf, sizeof(buf), 0);
        if (n > 0)
        {
          if (on_data)
          {
            on_data(
              c.id, std::vector<uint8_t>(buf, buf + static_cast<size_t>(n)));
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
    bool do_read(Conn& c)
    {
      if (c.ssl == nullptr)
      {
        return do_read_plaintext(c);
      }
      for (;;)
      {
        uint8_t buf[read_chunk];
        ERR_clear_error();
        const int n = SSL_read(c.ssl, buf, static_cast<int>(sizeof(buf)));
        if (n > 0)
        {
          if (on_data)
          {
            on_data(c.id, std::vector<uint8_t>(buf, buf + n));
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
      auto conn = std::move(it->second);
      conns.erase(it);
      (void)uv_poll_stop(&conn->poll);
      SSL* ssl = conn->ssl;
      if (ssl != nullptr)
      {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        conn->ssl = nullptr;
      }
      ::close(fd);
      conn->fd = -1;
      auto* raw = conn.get();
      closing_conns.emplace(raw, std::move(conn));
      ++pending_uv_closes;
      uv_close(
        reinterpret_cast<uv_handle_t*>(&raw->poll), on_connection_poll_closed);
    }

    void accept_all()
    {
      for (;;)
      {
        sockaddr_storage peer{};
        socklen_t plen = sizeof(peer);
        const int cfd = accept4(
          listen_fd, reinterpret_cast<sockaddr*>(&peer), &plen, SOCK_NONBLOCK);
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

        auto c = std::make_unique<Conn>();
        c->owner = this;
        c->fd = cfd;
        c->id = (shared_next_id != nullptr) ? shared_next_id->fetch_add(1) :
                                              next_id++;

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
            // supplied (see set_server_cert).
            ::close(cfd);
            continue;
          }
          SSL* ssl = SSL_new(ctx);
          if (ssl == nullptr)
          {
            ::close(cfd);
            continue;
          }
          SSL_set_mode(
            ssl,
            SSL_MODE_ENABLE_PARTIAL_WRITE |
              SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
          if (SSL_set_fd(ssl, cfd) != 1)
          {
            SSL_free(ssl);
            ::close(cfd);
            continue;
          }
          SSL_set_accept_state(ssl);
          c->ssl = ssl;
        }

        const int poll_rc = uv_poll_init_socket(loop, &c->poll, cfd);
        if (poll_rc != 0)
        {
          if (c->ssl != nullptr)
          {
            SSL_free(c->ssl);
          }
          ::close(cfd);
          continue;
        }
        c->poll.data = c.get();
        const int start_rc =
          uv_poll_start(&c->poll, UV_READABLE, on_connection_poll);
        if (start_rc != 0)
        {
          if (c->ssl != nullptr)
          {
            SSL_free(c->ssl);
          }
          ::close(cfd);
          ++pending_uv_closes;
          c->fd = -1;
          auto* raw = c.get();
          closing_conns.emplace(raw, std::move(c));
          uv_close(
            reinterpret_cast<uv_handle_t*>(&raw->poll),
            on_connection_poll_closed);
          continue;
        }
        const auto cid = c->id;
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
      Conn& c = *it->second;
      c.last_active = std::chrono::steady_clock::now();
      bool alive = true;
      if (c.state == Conn::Handshaking)
      {
        alive = do_handshake(c);
      }
      else
      {
        if ((events & (UV_READABLE | UV_DISCONNECT)) != 0)
        {
          alive = do_read(c);
        }
        if (alive)
        {
          alive = do_write(c);
        }
      }

      if (!alive)
      {
        close_conn(fd);
        return;
      }
      finish_or_close(fd, c);
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
        self->close_conn(conn->fd);
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

    // Drain the cross-thread outbound queue on the libuv thread: append queued
    // plaintext to each connection and flush (with backpressure), or close.
    void drain_pending_out()
    {
      std::vector<OutItem> items;
      std::vector<std::pair<std::string, std::string>> certs;
      {
        std::lock_guard<std::mutex> g(out_mutex);
        std::swap(items, pending_out);
        std::swap(certs, pending_certs);
      }

      for (auto& [cert_pem, key_pem] : certs)
      {
        SSL_CTX* nc = build_server_ctx(cert_pem, key_pem);
        if (nc == nullptr)
        {
          logf("set_server_cert: build context failed");
          continue;
        }
        if (ctx != nullptr)
        {
          SSL_CTX_free(ctx);
        }
        ctx = nc;
      }

      for (auto& item : items)
      {
        auto fit = id_to_fd.find(item.id);
        if (fit == id_to_fd.end())
        {
          continue;
        }
        const int fd = fit->second;
        if (item.close)
        {
          auto cit = conns.find(fd);
          if (cit == conns.end())
          {
            continue;
          }
          Conn& c = *cit->second;
          // Graceful close: flush any buffered response before tearing the
          // connection down, so a large response queued just before
          // close_socket() is not truncated.
          c.close_after_flush = true;
          if (!do_write(c))
          {
            close_conn(fd);
            continue;
          }
          finish_or_close(fd, c);
          continue;
        }
        auto cit = conns.find(fd);
        if (cit == conns.end())
        {
          continue;
        }
        Conn& c = *cit->second;
        c.outbuf.insert(c.outbuf.end(), item.data.begin(), item.data.end());
        c.last_active = std::chrono::steady_clock::now();
        if (!do_write(c))
        {
          close_conn(fd);
          continue;
        }
        finish_or_close(fd, c);
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
        if (now - c->last_active > *idle_timeout)
        {
          to_close.push_back(fd);
        }
      }
      for (const int fd : to_close)
      {
        logf("closing idle connection on fd %d", fd);
        close_conn(fd);
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
      else
      {
        self->drain_pending_out();
      }
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
      if (stopping && pending_uv_closes == 0)
      {
        stopped = true;
        stopped_cv.notify_all();
      }
    }

    void close_server_handle(uv_handle_t* handle)
    {
      if (!uv_is_closing(handle))
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
      (void)uv_poll_stop(&listen_poll);
      if (listen_fd >= 0)
      {
        ::close(listen_fd);
        listen_fd = -1;
      }
      while (!conns.empty())
      {
        close_conn(conns.begin()->first);
      }
      if (idle_timer_initialised)
      {
        (void)uv_timer_stop(&idle_timer);
        close_server_handle(reinterpret_cast<uv_handle_t*>(&idle_timer));
        idle_timer_initialised = false;
      }
      if (listen_poll_initialised)
      {
        close_server_handle(reinterpret_cast<uv_handle_t*>(&listen_poll));
        listen_poll_initialised = false;
      }
      if (wake_handle_initialised)
      {
        close_server_handle(reinterpret_cast<uv_handle_t*>(&wake_handle));
        wake_handle_initialised = false;
      }
      std::lock_guard<std::mutex> guard(lifecycle_mutex);
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
      uv_loop_t* loop_ = uv_default_loop()) :
      plaintext(plaintext_),
      loop(loop_),
      on_data(std::move(on_data_)),
      on_close(std::move(on_close_)),
      verbose(verbose_),
      shared_next_id(shared_next_id_),
      idle_timeout(idle_timeout_)
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
        listen_fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
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
      stopped = false;
      stopping = false;
      shutdown_started = false;
      initialising_thread_id = std::this_thread::get_id();
      loop_thread_seen = false;
      started = true;
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
        (void)uv_async_send(&wake_handle);
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
          (void)uv_run(loop, UV_RUN_NOWAIT);
        }
      }
      if (std::this_thread::get_id() == loop_thread_id)
      {
        lock.unlock();
        request_stop_on_loop();
        return;
      }
      stopped_cv.wait(lock, [this]() { return stopped; });
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

    // Peer certificate (DER) for `conn_id`, or empty. MUST be called on the
    // loop thread (e.g. synchronously from within the OnData callback).
    std::vector<uint8_t> get_peer_cert(::tcp::ConnID conn_id)
    {
      auto fit = id_to_fd.find(conn_id);
      if (fit == id_to_fd.end())
      {
        return {};
      }
      auto cit = conns.find(fit->second);
      if (cit == conns.end() || cit->second->ssl == nullptr)
      {
        return {};
      }
      X509* cert = SSL_get_peer_certificate(cit->second->ssl);
      if (cert == nullptr)
      {
        return {};
      }
      std::vector<uint8_t> der;
      const int len = i2d_X509(cert, nullptr);
      if (len > 0)
      {
        der.resize(static_cast<size_t>(len));
        unsigned char* p = der.data();
        i2d_X509(cert, &p);
      }
      X509_free(cert);
      return der;
    }

  private:
    void cleanup()
    {
      if (listen_fd >= 0)
      {
        ::close(listen_fd);
        listen_fd = -1;
      }
      if (ctx != nullptr)
      {
        SSL_CTX_free(ctx);
        ctx = nullptr;
      }
    }
  };
}
