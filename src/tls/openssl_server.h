// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "tls/openssl_connection_engine.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>

namespace ccf::tls
{
  class OpenSSLServer
  {
  public:
    using OnData = OpenSSLConnectionEngine::OnData;
    using OnClose = OpenSSLConnectionEngine::OnClose;
    using OnHandshake = OpenSSLConnectionEngine::OnHandshake;
    using LoopState = OpenSSLConnectionEngine::LoopState;
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

    // Everything about a server which is not a callback. Aggregate-initialised
    // at the call site so each setting is named, rather than being a run of
    // positional arguments where a transposition would compile silently.
    //
    // Every field has a default member initialiser, so a call site can name
    // only the settings it cares about without tripping
    // -Wmissing-field-initializers. That is also why the `= {}` on the string
    // members cannot be dropped, despite looking redundant on its own.
    // NOLINTBEGIN(readability-redundant-member-init)
    struct Config
    {
      // Address to bind. Resolved with getaddrinfo, so hostnames ("localhost")
      // and IPv6 literals ("::1") work, not just IPv4 literals. Port 0
      // requests an ephemeral port, which port() reports back once bound.
      std::string host = {};
      uint16_t port = 0;

      // Server certificate and key. May be empty for a TLS interface whose
      // certificate is not yet known - the interface then refuses connections
      // until set_server_cert() supplies one. Ignored when `plaintext` is set.
      std::string cert_pem = {};
      std::string key_pem = {};

      // ALPN protocol to advertise, e.g. "h2" or "http/1.1". Empty disables
      // ALPN.
      std::string alpn = {};

      // UNSECURED interface: no TLS at all, raw socket reads and writes.
      bool plaintext = false;

      // Close a connection after this much inactivity. nullopt keeps idle
      // connections open indefinitely.
      std::optional<std::chrono::milliseconds> idle_timeout = std::nullopt;

      // Shared connection-id source, so that servers on different interfaces
      // allocate ids from a single space - required for a global session
      // registry and reply routing. Null uses a per-server counter.
      std::atomic<::tcp::ConnID>* shared_next_id = nullptr;

      // Node-wide bound on inbound data which has been read but not yet
      // processed, shared with every other interface's transport. While it is
      // saturated this server stops reading. Null disables the gate.
      std::shared_ptr<InboundAdmission> inbound_admission = nullptr;

      // Loop to register this server's handles on.
      uv_loop_t* loop = uv_default_loop();

      OnHandshake on_handshake = {};
      // Linux TCP_USER_TIMEOUT, independent of application inactivity.
      // Unset preserves the operating system's defaults for RPC.
      std::optional<std::chrono::milliseconds> tcp_user_timeout = std::nullopt;
    };

    // NOLINTEND(readability-redundant-member-init)

  private:
    std::shared_ptr<OpenSSLConnectionEngine> engine;
    uv_loop_t* loop;
    std::shared_ptr<SSL_CTX> ctx;
    OnClose on_close;
    OnAccept on_accept;
    bool plaintext;
    std::optional<std::chrono::milliseconds> tcp_user_timeout;
    uv_poll_t* listen_poll = nullptr;
    int listen_fd = -1;
    uint16_t bound_port = 0;
    bool listening = false;
    std::string alpn_wire;
    ccf::ds::Mutex cert_mutex;
    std::vector<std::pair<std::string, std::string>> pending_certs
      CCF_GUARDED_BY(cert_mutex);

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

      const auto certs = ccf::crypto::split_x509_cert_bundle(cert_pem);
      if (certs.empty())
      {
        return false;
      }

      OpenSSL::Unique_BIO cbio(certs.front());
      // check_null defaults to false for this overload: a malformed PEM yields
      // a null pointer rather than an exception.
      OpenSSL::Unique_X509 cert(cbio, true);
      if (cert == nullptr)
      {
        return false;
      }
      OpenSSL::Unique_STACK_OF_X509 chain;
      for (auto it = certs.begin() + 1; it != certs.end(); ++it)
      {
        OpenSSL::Unique_BIO chain_bio(*it);
        OpenSSL::Unique_X509 chain_cert(chain_bio, true);
        if (chain_cert == nullptr || sk_X509_push(chain, chain_cert) <= 0)
        {
          return false;
        }
        (void)chain_cert.release();
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
      if (SSL_CTX_use_cert_and_key(ctx, cert, pkey, chain, 1) != 1)
      {
        return false;
      }

      return SSL_CTX_check_private_key(ctx) == 1;
    }

    // Build a server SSL_CTX (min TLS 1.2, ALPN if configured) and load the
    // cert/key. Returns nullptr on failure, having logged which step failed and
    // why. Called on the loop thread.
    //
    // This is the only place CCF's inbound TLS policy is defined. It is
    // asserted from the wire by src/tls/test/openssl_server_test.cpp and, for
    // a running service, by tests/tls_groups.py.
    std::shared_ptr<SSL_CTX> build_server_ctx(
      const std::string& cert_pem, const std::string& key_pem)
    {
      // So that anything reported below comes from this function rather than
      // from unrelated work previously done on this thread.
      ERR_clear_error();

      const auto fail = [](const char* step) {
        const auto error = ccf::crypto::OpenSSL::first_error();
        LOG_FAIL_FMT("Failed to build TLS context ({}): {}", step, error);
        return std::shared_ptr<SSL_CTX>{};
      };

      ccf::crypto::OpenSSL::Unique_SSL_CTX c(TLS_server_method());

      // Require at least TLS 1.2, support up to 1.3
      if (SSL_CTX_set_min_proto_version(c, TLS1_2_VERSION) != 1)
      {
        return fail("SSL_CTX_set_min_proto_version");
      }

      // Require a fresh authenticated key exchange for every connection.
      SSL_CTX_set_session_cache_mode(c, SSL_SESS_CACHE_OFF);
      if (SSL_CTX_set_num_tickets(c, 0) != 1)
      {
        return fail("SSL_CTX_set_num_tickets");
      }
      if (SSL_CTX_set_max_early_data(c, 0) != 1)
      {
        return fail("SSL_CTX_set_max_early_data");
      }

      // Disable renegotiation and stateless session tickets.
      SSL_CTX_set_options(
        c,
        SSL_OP_CIPHER_SERVER_PREFERENCE |
          SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION |
          SSL_OP_NO_RENEGOTIATION | SSL_OP_NO_TICKET);

      // Set cipher for TLS 1.2
      const auto* const cipher_list =
        "ECDHE-ECDSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES128-GCM-SHA256";
      if (SSL_CTX_set_cipher_list(c, cipher_list) != 1)
      {
        return fail("SSL_CTX_set_cipher_list");
      }

      // Set cipher for TLS 1.3
      const auto* const ciphersuites =
        "TLS_AES_256_GCM_SHA384:"
        "TLS_AES_128_GCM_SHA256";
      if (SSL_CTX_set_ciphersuites(c, ciphersuites) != 1)
      {
        return fail("SSL_CTX_set_ciphersuites");
      }

      // Prefer hybrid post-quantum groups when available, while retaining the
      // approved classical groups as fallbacks
      if (
        SSL_CTX_set1_groups_list(
          c,
          "?SecP384r1MLKEM1024:?SecP256r1MLKEM768:?X25519MLKEM768:"
          "P-521:P-384:P-256") != 1)
      {
        return fail("SSL_CTX_set1_groups_list");
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
        return fail("loading certificate and key");
      }
      return {c.release(), SSL_CTX_free};
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
          // The listening socket is level-triggered, so a persistent failure
          // (notably EMFILE once the process is out of file descriptors) is
          // re-reported on every loop iteration. Keep it out of the default
          // log for that reason.
          LOG_DEBUG_FMT(
            "accept4 failed: {}", std::generic_category().message(err));
          break;
        }

        if (const auto error = details::configure_tcp_connection(cfd))
        {
          LOG_FAIL_FMT(
            "setsockopt({}) failed for accepted RPC socket: {}",
            error->option,
            std::generic_category().message(error->error));
          details::close_socket(cfd);
          continue;
        }

        if (!details::set_user_timeout(cfd, tcp_user_timeout))
        {
          details::close_socket(cfd);
          continue;
        }

        const auto cid = engine->allocate_id();

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
            details::close_socket(cfd);
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

        if (!plaintext && ctx == nullptr)
        {
          LOG_DEBUG_FMT(
            "Refusing connection {}: no server certificate yet", cid);
          details::close_socket(cfd);
          release_admitted();
          continue;
        }
        if (!engine->adopt(
              {.id = cid,
               .fd = cfd,
               .tls_context = plaintext ? nullptr : ctx,
               .soft_limited = soft_limited}))
        {
          release_admitted();
          continue;
        }
        LOG_TRACE_FMT("Accepted connection {} on fd {}", cid, cfd);
      }
    }

    // Place the bound socket in the LISTEN state and arm its poll handle, if
    // the interface is ready to serve connections and is not already doing so.
    // Idempotent. Called from start() and, for an interface whose certificate
    // arrived later, from the loop thread once it has been applied.
    void begin_listening()
    {
      if (
        listening || listen_poll == nullptr || listen_fd < 0 ||
        (!plaintext && ctx == nullptr))
      {
        return;
      }
      if (listen(listen_fd, SOMAXCONN) != 0)
      {
        LOG_FAIL_FMT(
          "listen() failed on port {}: {}",
          bound_port,
          std::generic_category().message(errno));
        return;
      }

      const int rc = uv_poll_start(listen_poll, UV_READABLE, on_listen_poll);
      if (rc != 0)
      {
        LOG_FAIL_FMT(
          "uv_poll_start(listen) failed on port {}: {}",
          bound_port,
          uv_strerror(rc));
        return;
      }
      listening = true;
    }

    static void on_listen_poll(uv_poll_t* handle, int status, int events)
    {
      auto* self = static_cast<OpenSSLServer*>(handle->data);
      if (status < 0)
      {
        self->engine->shutdown_on_loop();
        return;
      }
      if ((events & UV_READABLE) != 0)
      {
        self->accept_all();
      }
    }

    void apply_certs()
    {
      std::vector<std::pair<std::string, std::string>> certs;
      {
        ccf::ds::MutexGuard guard(cert_mutex);
        certs.swap(pending_certs);
      }
      for (auto& [cert_pem, key_pem] : certs)
      {
        // This runs inside a libuv callback, so nothing may escape: an
        // operator-supplied cert which fails to parse must not terminate the
        // process, it must leave the previous context in place.
        try
        {
          // build_server_ctx() reports why it failed.
          auto nc = build_server_ctx(cert_pem, key_pem);
          if (nc == nullptr)
          {
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

      if (!certs.empty())
      {
        // A cert-deferred interface has been waiting for exactly this.
        begin_listening();
      }
    }

    void stop_listener()
    {
      if (listen_poll != nullptr)
      {
        (void)uv_poll_stop(listen_poll);
        details::close_handle(listen_poll);
      }
      listening = false;
      cleanup();
    }

  public:
    OpenSSLServer(
      Config config,
      OnData on_data_,
      OnClose on_close_ = {},
      OnAccept on_accept_ = {}) :
      loop(config.loop),
      on_close(std::move(on_close_)),
      on_accept(std::move(on_accept_)),
      plaintext(config.plaintext),
      tcp_user_timeout(config.tcp_user_timeout)
    {
      OpenSSLConnectionEngine::Config engine_config{
        .loop = loop,
        .idle_timeout = config.idle_timeout,
        .shared_next_id = config.shared_next_id,
        .inbound_admission = std::move(config.inbound_admission),
        .on_handshake = std::move(config.on_handshake),
        .on_wake = [this]() { apply_certs(); },
        .on_stop = [this]() { stop_listener(); }};
      engine = std::make_shared<OpenSSLConnectionEngine>(
        std::move(engine_config), std::move(on_data_), on_close);
      details::validate_user_timeout(tcp_user_timeout);
      if (!config.alpn.empty())
      {
        alpn_wire.push_back(static_cast<char>(config.alpn.size()));
        alpn_wire.append(config.alpn);
      }

      // Plaintext interfaces have no TLS context. TLS interfaces build their
      // context now if the cert is already available, or defer until
      // set_server_cert() (e.g. a joining node receiving the service cert).
      if (!plaintext && !config.cert_pem.empty())
      {
        ctx = build_server_ctx(config.cert_pem, config.key_pem);
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
      const std::string port_str = std::to_string(config.port);
      if (getaddrinfo(config.host.c_str(), port_str.c_str(), &hints, &res) != 0)
      {
        cleanup();
        throw std::runtime_error("getaddrinfo failed for " + config.host);
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
          details::close_socket(listen_fd);
          listen_fd = -1;
          continue;
        }
        if (bind(listen_fd, ai->ai_addr, ai->ai_addrlen) == 0)
        {
          bound_ok = true;
          break;
        }
        details::close_socket(listen_fd);
        listen_fd = -1;
      }
      freeaddrinfo(res);
      if (!bound_ok)
      {
        cleanup();
        throw std::runtime_error("bind() failed for " + config.host);
      }
      // Deliberately no listen() here. Binding reserves the port (and fixes an
      // ephemeral one, which port() reports), but the socket only enters the
      // LISTEN state once this interface can actually serve a connection - see
      // begin_listening(). Until then the kernel refuses inbound SYNs, so a
      // client fails to connect rather than completing a TCP handshake against
      // an interface which will immediately drop it.
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
      engine->start([this]() {
        auto poll = std::make_unique<uv_poll_t>();
        const int rc = uv_poll_init_socket(loop, poll.get(), listen_fd);
        if (rc != 0)
        {
          throw std::runtime_error(
            std::string("uv_poll_init_socket(listen) failed: ") +
            uv_strerror(rc));
        }
        listen_poll = poll.release();
        listen_poll->data = this;
        begin_listening();
      });
    }

    void stop(LoopState state = LoopState::NotRunning)
    {
      engine->stop(state);
    }

    void send(::tcp::ConnID id, std::vector<uint8_t>&& data)
    {
      engine->send(id, std::move(data));
    }

    void send(::tcp::ConnID id, const uint8_t* data, size_t size)
    {
      engine->send(id, data, size);
    }

    void close_connection(::tcp::ConnID id)
    {
      engine->close_connection(id);
    }

    void set_server_cert(const std::string& cert, const std::string& key)
    {
      {
        ccf::ds::MutexGuard guard(cert_mutex);
        pending_certs.emplace_back(cert, key);
      }
      engine->wake_owner();
    }

  private:
    void cleanup()
    {
      if (listen_fd >= 0)
      {
        details::close_socket(listen_fd);
        listen_fd = -1;
      }
      ctx.reset();
    }
  };
}
