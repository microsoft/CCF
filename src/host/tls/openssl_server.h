// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

// Vertical-slice OpenSSL-native TLS server, validating the model for the RPC
// stack rewrite:
//   * OpenSSL owns the socket fd directly (SSL_set_fd on a non-blocking fd) -
//     no memory-BIO indirection, no libuv.
//   * Our own epoll loop drives readiness; the handshake and I/O run as a
//     non-blocking state machine.
//   * Real TCP backpressure falls out: a non-blocking SSL_write that returns
//     WANT_WRITE leaves the unsent plaintext buffered and arms EPOLLOUT.
//
// Scope/limits of this slice (deliberately minimal):
//   * Single epoll thread; the on_data callback is invoked synchronously on
//     that thread and replies by appending to the connection's outbound buffer.
//     The production target is SO_REUSEPORT + one epoll per worker, with
//     callbacks dispatched to the OrderedTasks pool (so replies would arrive
//     from another thread and wake the loop).
//   * Level-triggered epoll, for simplicity/correctness over raw throughput.
//   * No session caps / certs-per-interface / protocol handling - that policy
//     is harvested separately. This proves transport + threading + backpressure.

#include <arpa/inet.h>
#include <atomic>
#include <cerrno>
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
#include <stdexcept>
#include <string>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>

namespace asynchost
{
  class OpenSSLServer
  {
  public:
    // Invoked on the epoll thread with a complete chunk of decrypted bytes for
    // connection `conn_id`. The handler typically hands processing to a worker
    // (e.g. OrderedTasks) and later calls send()/close_connection() from that
    // thread - both are thread-safe and wake the loop.
    using OnData =
      std::function<void(uint64_t conn_id, std::vector<uint8_t> data)>;

    // Invoked on the epoll thread when a connection is torn down (peer
    // disconnect, error, or close_connection()). Lets an owner drop per-
    // connection state.
    using OnClose = std::function<void(uint64_t conn_id)>;

  private:
    static constexpr size_t read_chunk = 16384;

    struct Conn
    {
      int fd = -1;
      SSL* ssl = nullptr;
      uint64_t id = 0;
      enum State : uint8_t
      {
        Handshaking,
        Ready
      } state = Handshaking;
      // Outbound (client) connection: drives SSL_connect rather than SSL_accept.
      bool is_client = false;
      // Pending plaintext to be encrypted/written; out_off bytes already sent.
      std::vector<uint8_t> outbuf;
      size_t out_off = 0;
      // True when progress needs the socket to become writable (handshake
      // wants write, or there is buffered outbound data).
      bool want_write = false;
    };

    SSL_CTX* ctx = nullptr;
    // Lazily created client context for outbound connections.
    SSL_CTX* client_ctx = nullptr;
    // Plaintext (UNSECURED) interface: no TLS, raw socket I/O.
    bool plaintext = false;
    // ALPN protocol advertised by the server (wire format, length-prefixed),
    // e.g. "\x02h2" or "\x08http/1.1". Empty disables ALPN.
    std::string alpn_wire;
    int listen_fd = -1;
    int epoll_fd = -1;
    int stop_fd = -1;
    int wake_fd = -1;
    uint16_t bound_port = 0;
    OnData on_data;
    OnClose on_close;
    bool verbose = false;

    std::unordered_map<int, std::unique_ptr<Conn>> conns;
    std::unordered_map<uint64_t, int> id_to_fd;
    uint64_t next_id = 1;
    // Optional shared id source so multiple servers (one per interface) allocate
    // connection ids from a single global space - required for a global session
    // registry and reply routing.
    std::atomic<uint64_t>* shared_next_id = nullptr;

    // Cross-thread outbound queue: send()/close_connection() append here from
    // any thread and wake the loop, which drains it on the epoll thread.
    struct OutItem
    {
      uint64_t id = 0;
      std::vector<uint8_t> data;
      bool close = false;
    };
    std::mutex out_mutex;
    std::vector<OutItem> pending_out;

    // Cross-thread outbound connect requests (for client sessions).
    struct ConnectReq
    {
      int64_t id = 0;
      std::string host;
      std::string port;
    };
    std::vector<ConnectReq> pending_connects;

    // Cross-thread server-cert (re)load requests (deferred cert / rotation),
    // applied on the loop thread so `ctx` is only ever touched there.
    std::vector<std::pair<std::string, std::string>> pending_certs;

    std::thread loop_thread;
    std::atomic<bool> running{false};

    void logf(const char* fmt, ...) const
    {
      if (!verbose)
      {
        return;
      }
      va_list args; // NOLINT
      va_start(args, fmt);
      std::vfprintf(stderr, fmt, args);
      std::fputc('\n', stderr);
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
      SSL_CTX* ctx,
      const std::string& cert_pem,
      const std::string& key_pem)
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
    SSL_CTX* build_server_ctx(
      const std::string& cert_pem, const std::string& key_pem)
    {
      SSL_CTX* c = SSL_CTX_new(TLS_server_method());
      if (c == nullptr)
      {
        return nullptr;
      }
      SSL_CTX_set_min_proto_version(c, TLS1_2_VERSION);
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
      epoll_event ev{};
      ev.data.fd = c.fd;
      ev.events = EPOLLIN | (c.want_write ? EPOLLOUT : 0);
      epoll_ctl(epoll_fd, EPOLL_CTL_MOD, c.fd, &ev);
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
      const int r = c.is_client ? SSL_connect(c.ssl) : SSL_accept(c.ssl);
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
        // SSL_ERROR_ZERO_RETURN (clean close) or a fatal error.
        logf("conn %llu: read closed/err %d", (unsigned long long)c.id, e);
        return false;
      }
    }

    // Returns false if the connection should be closed. Implements backpressure:
    // a WANT_WRITE leaves the remaining plaintext buffered and arms EPOLLOUT.
    bool do_write(Conn& c)
    {
      if (c.ssl == nullptr)
      {
        return do_write_plaintext(c);
      }
      while (c.out_off < c.outbuf.size())
      {
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
      epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, nullptr);
      id_to_fd.erase(it->second->id);
      SSL* ssl = it->second->ssl;
      if (ssl != nullptr)
      {
        SSL_shutdown(ssl);
        SSL_free(ssl);
      }
      ::close(fd);
      conns.erase(it);
    }

    void accept_all()
    {
      for (;;)
      {
        sockaddr_in peer{};
        socklen_t plen = sizeof(peer);
        const int cfd = accept4(
          listen_fd,
          reinterpret_cast<sockaddr*>(&peer),
          &plen,
          SOCK_NONBLOCK);
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
          logf("accept error: %s", std::strerror(errno));
          break;
        }

        auto c = std::make_unique<Conn>();
        c->fd = cfd;
        c->id =
          (shared_next_id != nullptr) ? shared_next_id->fetch_add(1) : next_id++;

        if (plaintext)
        {
          // No TLS: ready to read/write raw bytes immediately.
          c->state = Conn::Ready;
        }
        else
        {
          if (ctx == nullptr)
          {
            // No server certificate yet - refuse (mirrors the old "Session
            // refused until cert present" behaviour).
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
            SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
          if (SSL_set_fd(ssl, cfd) != 1)
          {
            SSL_free(ssl);
            ::close(cfd);
            continue;
          }
          SSL_set_accept_state(ssl);
          c->ssl = ssl;
        }

        epoll_event ev{};
        ev.data.fd = cfd;
        ev.events = EPOLLIN;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, cfd, &ev) != 0)
        {
          if (c->ssl != nullptr)
          {
            SSL_free(c->ssl);
          }
          ::close(cfd);
          continue;
        }
        const uint64_t cid = c->id;
        conns.emplace(cfd, std::move(c));
        id_to_fd.emplace(cid, cfd);
        logf("accepted conn on fd %d", cfd);
      }
    }

    void on_conn_event(int fd, uint32_t events)
    {
      auto it = conns.find(fd);
      if (it == conns.end())
      {
        return;
      }
      Conn& c = *it->second;

      bool alive = true;
      if (c.state == Conn::Handshaking)
      {
        alive = do_handshake(c);
      }
      else
      {
        if ((events & (EPOLLIN | EPOLLERR | EPOLLHUP)) != 0)
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
      update_interest(c);
    }

    void wake() const
    {
      if (wake_fd >= 0)
      {
        const uint64_t one = 1;
        [[maybe_unused]] auto w = ::write(wake_fd, &one, sizeof(one));
      }
    }

    // Drain the cross-thread outbound queue on the epoll thread: append queued
    // plaintext to each connection and flush (with backpressure), or close.
    void drain_pending_out()
    {
      uint64_t counter = 0;
      while (::read(wake_fd, &counter, sizeof(counter)) > 0)
      {
        // Clear the eventfd counter.
      }

      std::vector<OutItem> items;
      std::vector<ConnectReq> connects;
      std::vector<std::pair<std::string, std::string>> certs;
      {
        std::lock_guard<std::mutex> g(out_mutex);
        std::swap(items, pending_out);
        std::swap(connects, pending_connects);
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

      for (auto& req : connects)
      {
        do_connect(req.id, req.host, req.port);
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
          close_conn(fd);
          continue;
        }
        auto cit = conns.find(fd);
        if (cit == conns.end())
        {
          continue;
        }
        Conn& c = *cit->second;
        c.outbuf.insert(c.outbuf.end(), item.data.begin(), item.data.end());
        if (!do_write(c))
        {
          close_conn(fd);
          continue;
        }
        update_interest(c);
      }
    }

    // Open an outbound client connection for `id` (loop thread). TLS client
    // handshake is driven by the normal epoll state machine (is_client).
    void do_connect(int64_t id, const std::string& host, const std::string& port)
    {
      if (client_ctx == nullptr)
      {
        client_ctx = SSL_CTX_new(TLS_client_method());
        if (client_ctx == nullptr)
        {
          logf("client SSL_CTX_new failed");
          if (on_close)
          {
            on_close(static_cast<uint64_t>(id));
          }
          return;
        }
        SSL_CTX_set_min_proto_version(client_ctx, TLS1_2_VERSION);
        // TODO: wire CA verification for outbound (create_client cert) before
        // production; currently the peer is not verified here.
        SSL_CTX_set_verify(client_ctx, SSL_VERIFY_NONE, nullptr);
      }

      addrinfo hints{};
      hints.ai_family = AF_UNSPEC;
      hints.ai_socktype = SOCK_STREAM;
      addrinfo* res = nullptr;
      if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0)
      {
        logf("getaddrinfo(%s:%s) failed", host.c_str(), port.c_str());
        if (on_close)
        {
          on_close(static_cast<uint64_t>(id));
        }
        return;
      }

      const int cfd =
        socket(res->ai_family, SOCK_STREAM | SOCK_NONBLOCK, res->ai_protocol);
      if (cfd < 0)
      {
        freeaddrinfo(res);
        if (on_close)
        {
          on_close(static_cast<uint64_t>(id));
        }
        return;
      }
      const int rc = ::connect(cfd, res->ai_addr, res->ai_addrlen);
      freeaddrinfo(res);
      if (rc != 0 && errno != EINPROGRESS)
      {
        ::close(cfd);
        if (on_close)
        {
          on_close(static_cast<uint64_t>(id));
        }
        return;
      }

      SSL* ssl = SSL_new(client_ctx);
      if (ssl == nullptr)
      {
        ::close(cfd);
        if (on_close)
        {
          on_close(static_cast<uint64_t>(id));
        }
        return;
      }
      SSL_set_mode(
        ssl,
        SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
      SSL_set_connect_state(ssl);
      if (SSL_set_fd(ssl, cfd) != 1)
      {
        SSL_free(ssl);
        ::close(cfd);
        if (on_close)
        {
          on_close(static_cast<uint64_t>(id));
        }
        return;
      }

      auto c = std::make_unique<Conn>();
      c->fd = cfd;
      c->ssl = ssl;
      c->id = static_cast<uint64_t>(id);
      c->is_client = true;

      epoll_event ev{};
      ev.data.fd = cfd;
      ev.events = EPOLLIN | EPOLLOUT;
      if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, cfd, &ev) != 0)
      {
        SSL_free(ssl);
        ::close(cfd);
        if (on_close)
        {
          on_close(static_cast<uint64_t>(id));
        }
        return;
      }
      conns.emplace(cfd, std::move(c));
      id_to_fd.emplace(id, cfd);
    }

    void run()
    {
      constexpr int max_events = 64;
      std::vector<epoll_event> events(max_events);
      while (running.load())
      {
        const int n =
          epoll_wait(epoll_fd, events.data(), max_events, /*timeout*/ -1);
        if (n < 0)
        {
          if (errno == EINTR)
          {
            continue;
          }
          logf("epoll_wait error: %s", std::strerror(errno));
          break;
        }

        for (int i = 0; i < n; ++i)
        {
          const int fd = events[i].data.fd;
          if (fd == stop_fd)
          {
            running.store(false);
            break;
          }
          if (fd == wake_fd)
          {
            drain_pending_out();
            continue;
          }
          if (fd == listen_fd)
          {
            accept_all();
            continue;
          }
          on_conn_event(fd, events[i].events);
        }
      }

      // Tear down all live connections on the loop thread.
      while (!conns.empty())
      {
        close_conn(conns.begin()->first);
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
      std::atomic<uint64_t>* shared_next_id_ = nullptr) :
      plaintext(plaintext_),
      on_data(std::move(on_data_)),
      on_close(std::move(on_close_)),
      verbose(verbose_),
      shared_next_id(shared_next_id_)
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

      listen_fd = socket(AF_INET, SOCK_STREAM, 0);
      if (listen_fd < 0)
      {
        cleanup();
        throw std::runtime_error("socket() failed");
      }
      const int one = 1;
      setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
      // SO_REUSEPORT is the idiom that will let each worker run its own
      // listening socket + epoll loop in the production design.
      setsockopt(listen_fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));

      sockaddr_in addr{};
      addr.sin_family = AF_INET;
      addr.sin_port = htons(port);
      if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1)
      {
        cleanup();
        throw std::runtime_error("inet_pton failed");
      }
      if (
        bind(
          listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0)
      {
        cleanup();
        throw std::runtime_error("bind() failed");
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

      // Read back the actual bound port (supports ephemeral port 0).
      sockaddr_in bound{};
      socklen_t blen = sizeof(bound);
      if (
        getsockname(
          listen_fd, reinterpret_cast<sockaddr*>(&bound), &blen) == 0)
      {
        bound_port = ntohs(bound.sin_port);
      }

      epoll_fd = epoll_create1(0);
      if (epoll_fd < 0)
      {
        cleanup();
        throw std::runtime_error("epoll_create1 failed");
      }
      stop_fd = eventfd(0, EFD_NONBLOCK);
      if (stop_fd < 0)
      {
        cleanup();
        throw std::runtime_error("eventfd failed");
      }
      wake_fd = eventfd(0, EFD_NONBLOCK);
      if (wake_fd < 0)
      {
        cleanup();
        throw std::runtime_error("eventfd (wake) failed");
      }

      epoll_event ev{};
      ev.data.fd = listen_fd;
      ev.events = EPOLLIN;
      epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &ev);
      ev.data.fd = stop_fd;
      epoll_ctl(epoll_fd, EPOLL_CTL_ADD, stop_fd, &ev);
      ev.data.fd = wake_fd;
      epoll_ctl(epoll_fd, EPOLL_CTL_ADD, wake_fd, &ev);
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
      running.store(true);
      loop_thread = std::thread([this]() { run(); });
    }

    void stop()
    {
      if (!running.exchange(false))
      {
        if (loop_thread.joinable())
        {
          loop_thread.join();
        }
        return;
      }
      if (stop_fd >= 0)
      {
        const uint64_t one = 1;
        [[maybe_unused]] auto w = ::write(stop_fd, &one, sizeof(one));
      }
      if (loop_thread.joinable())
      {
        loop_thread.join();
      }
    }

    // Thread-safe. Queue plaintext to be encrypted and written to `conn_id`.
    void send(uint64_t conn_id, const uint8_t* data, size_t len)
    {
      {
        std::lock_guard<std::mutex> g(out_mutex);
        pending_out.push_back(
          {conn_id, std::vector<uint8_t>(data, data + len), false});
      }
      wake();
    }

    // Thread-safe. Request that `conn_id` be torn down.
    void close_connection(uint64_t conn_id)
    {
      {
        std::lock_guard<std::mutex> g(out_mutex);
        pending_out.push_back({conn_id, {}, true});
      }
      wake();
    }

    // Thread-safe. Open an outbound client (TLS) connection bound to `id`.
    void connect(
      int64_t id, const std::string& host, const std::string& port)
    {
      {
        std::lock_guard<std::mutex> g(out_mutex);
        pending_connects.push_back({id, host, port});
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
    std::vector<uint8_t> get_peer_cert(uint64_t conn_id)
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
      if (wake_fd >= 0)
      {
        ::close(wake_fd);
        wake_fd = -1;
      }
      if (stop_fd >= 0)
      {
        ::close(stop_fd);
        stop_fd = -1;
      }
      if (epoll_fd >= 0)
      {
        ::close(epoll_fd);
        epoll_fd = -1;
      }
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
      if (client_ctx != nullptr)
      {
        SSL_CTX_free(client_ctx);
        client_ctx = nullptr;
      }
    }
  };
}
