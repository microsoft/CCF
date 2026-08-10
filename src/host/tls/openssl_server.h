// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

// OpenSSL-native TLS/plaintext TCP server for RPC interfaces. OpenSSL owns the
// socket fd directly. The host libuv loop reports readiness, while
// per-connection OrderedTasks drive non-blocking handshake, reads, writes, and
// graceful close away from the loop thread.

#include "ccf/crypto/openssl/openssl_wrappers.h"
#include "ds/internal_logger.h"
#include "host/tls/inbound_admission.h"
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
#include <cstdint>
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

  class OpenSSLServer : public std::enable_shared_from_this<OpenSSLServer>
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

    // Whether anything is running the libuv loop when stop() is called. See
    // stop() for why this has to be stated rather than inferred.
    enum class LoopState : uint8_t
    {
      Running,
      NotRunning,
    };

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
    };
    // NOLINTEND(readability-redundant-member-init)

  private:
    static constexpr size_t read_chunk = 16384;
    static constexpr size_t max_read_per_event = read_chunk * 4;

    // Heap-allocate a libuv handle whose lifetime is independent of this
    // server, and close it so that it frees itself.
    //
    // uv_close() is asynchronous: the close callback only runs when the loop
    // next runs, which may be long after the server has been destroyed - or
    // never, if node startup failed before the event loop was entered. If
    // handles were members, destruction would have to block until the loop had
    // drained them, which in turn would force the server to drive the loop
    // itself. Owning each handle separately means shutdown is fire-and-forget:
    // request the close, drop the handle, and let the loop reclaim it whenever
    // it next runs.
    //
    // Nothing dereferences handle->data after uv_close(), because libuv
    // guarantees no further callbacks for a handle beyond its close callback,
    // and that callback does nothing but free the handle.
    template <typename THandle>
    static THandle* new_handle()
    {
      // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
      return new THandle{};
    }

    template <typename THandle>
    static void close_handle(THandle*& handle)
    {
      if (handle == nullptr)
      {
        return;
      }
      auto* as_handle = reinterpret_cast<uv_handle_t*>(handle);
      handle = nullptr;
      if (uv_is_closing(as_handle) != 0)
      {
        return;
      }
      uv_close(as_handle, [](uv_handle_t* h) {
        // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
        delete reinterpret_cast<THandle*>(h);
      });
    }

    struct OutItem;

    struct Conn
    {
      OpenSSLServer* owner = nullptr;
      int fd = -1;
      uv_poll_t* poll = nullptr;
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
      // Set once, when the server is being torn down. Unlike close_requested
      // it is sticky, and it does not wait for buffered output to drain: a
      // peer which has stopped reading must not be able to keep the connection
      // (and so the shutdown) alive indefinitely.
      bool force_close = false;
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
      bool force_close = false;
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

    // Close a connection after this much inactivity (no I/O); nullopt disables
    // idle closure. A libuv timer wakes every idle_sweep_interval_ms to check.
    static constexpr int idle_sweep_interval_ms = 1000;
    std::optional<std::chrono::milliseconds> idle_timeout;

    // Node-wide inbound budget, shared with every other interface's transport.
    // Null disables the gate.
    std::shared_ptr<InboundAdmission> inbound_admission;
    std::optional<size_t> admission_token;

    [[nodiscard]] bool inbound_saturated() const
    {
      return inbound_admission != nullptr && inbound_admission->saturated();
    }

    // The subset of a connection's pending events which may be acted on now.
    // Read interest is withheld while the node holds more unprocessed inbound
    // data than it is willing to.
    [[nodiscard]] int actionable_events(const Conn& c) const
    {
      if (!inbound_saturated())
      {
        return c.pending_events;
      }
      return c.pending_events & ~UV_READABLE;
    }

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
    std::condition_variable teardown_cv;
    std::unordered_map<int, std::shared_ptr<Conn>> conns;
    std::unordered_map<::tcp::ConnID, int> id_to_fd;
    // Owned by the loop once closed - see new_handle()/close_handle().
    uv_async_t* wake_handle = nullptr;
    uv_timer_t* idle_timer = nullptr;
    uv_poll_t* listen_poll = nullptr;
    int listen_fd = -1;
    uint16_t bound_port = 0;
    // Whether the bound socket has been placed in the LISTEN state and its
    // poll handle armed. A TLS interface with no certificate stays bound but
    // not listening, so inbound connections are refused by the kernel rather
    // than accepted and dropped. Loop-thread only after start().
    bool listening = false;
    // Plaintext (UNSECURED) interface: no TLS, raw socket I/O.
    bool plaintext = false;
    bool started = false;
    bool stopping = false;
    // Set once the teardown has run: every connection dropped, every handle
    // handed to uv_close(), and the listening socket closed. The handles may
    // not have been reclaimed by the loop yet, but nothing here refers to
    // them any more, so the server is safe to destroy.
    bool torn_down = false;

    // Describe a failed SSL operation. SSL_get_error() only gives the
    // category: for SSL_ERROR_SSL the detail is in the (thread-local) error
    // queue, and for SSL_ERROR_SYSCALL it may be in errno instead. Consuming
    // the queue entry here also keeps it from being misattributed to the next
    // operation this worker performs.
    static std::string ssl_error_string(int ssl_error)
    {
      switch (ssl_error)
      {
        case SSL_ERROR_ZERO_RETURN:
          return "peer closed the TLS connection";

        case SSL_ERROR_SSL:
        case SSL_ERROR_SYSCALL:
        {
          const auto err = ERR_get_error();
          if (err != 0)
          {
            return ccf::crypto::OpenSSL::error_string(err);
          }
          if (ssl_error == SSL_ERROR_SYSCALL)
          {
            return fmt::format(
              "syscall failed: {}", std::generic_category().message(errno));
          }
          return "protocol error";
        }

        default:
          return fmt::format("SSL_get_error {}", ssl_error);
      }
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
    // cert/key. Returns nullptr on failure, having logged which step failed and
    // why. Called on the loop thread.
    //
    // This is the only place CCF's inbound TLS policy is defined. It is
    // asserted from the wire by src/host/test/openssl_server_test.cpp and, for
    // a running service, by tests/tls_groups.py.
    std::shared_ptr<SSL_CTX> build_server_ctx(
      const std::string& cert_pem, const std::string& key_pem)
    {
      // So that anything reported below comes from this function rather than
      // from unrelated work previously done on this thread.
      ERR_clear_error();

      const auto fail = [](const char* step) {
        LOG_FAIL_FMT(
          "Failed to build TLS context ({}): {}",
          step,
          ccf::crypto::OpenSSL::error_string(ERR_get_error()));
        return std::shared_ptr<SSL_CTX>{};
      };

      ccf::crypto::OpenSSL::Unique_SSL_CTX c(TLS_server_method());

      // Require at least TLS 1.2, support up to 1.3
      if (SSL_CTX_set_min_proto_version(c, TLS1_2_VERSION) != 1)
      {
        return fail("SSL_CTX_set_min_proto_version");
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

    void update_interest(Conn& c) const
    {
      if (c.poll == nullptr)
      {
        return;
      }
      int events = c.want_write ? UV_WRITABLE : 0;
      if (!inbound_saturated())
      {
        events |= UV_READABLE;
      }
      if (events == 0)
      {
        // uv_poll_start rejects an empty mask, and there is genuinely nothing
        // to wait for: this connection resumes when the node drops back under
        // its inbound budget, at which point every transport is woken.
        (void)uv_poll_stop(c.poll);
        return;
      }
      const int rc = uv_poll_start(c.poll, events, on_connection_poll);
      if (rc != 0)
      {
        // Should not happen. If it does the connection will make no further
        // progress, so it is worth reporting loudly rather than hiding.
        LOG_FAIL_FMT(
          "uv_poll_start failed for connection {}: {}", c.id, uv_strerror(rc));
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
        X509* cert = SSL_get1_peer_certificate(c.ssl);
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
        LOG_TRACE_FMT("Connection {}: handshake complete", c.id);
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
      // Entirely client-controlled (an unsupported cipher, a rejected
      // certificate, or simply a port scan), so this must stay at a level
      // which cannot be used to flood the log.
      LOG_DEBUG_FMT(
        "Connection {}: handshake failed: {}", c.id, ssl_error_string(e));
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
          compact_outbuf(c);
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

    // Release the already-written prefix of a partially flushed buffer, so a
    // large response which is draining slowly does not keep holding the bytes
    // the peer has already received. erase() would retain the original
    // capacity, so rebuild into a right-sized buffer instead. Called only when
    // a write has just stalled and the remainder is about to be held until the
    // socket becomes writable again - compacting a buffer we are about to
    // flush anyway would be pure overhead. Only worth the copy once most of
    // the buffer is consumed, which also bounds the total copying for one
    // response to O(its size).
    static void compact_outbuf(Conn& c)
    {
      if (c.out_off == 0 || c.out_off <= c.outbuf.size() / 2)
      {
        return;
      }
      std::vector<uint8_t> remaining(
        c.outbuf.data() + c.out_off, c.outbuf.data() + c.outbuf.size());
      c.outbuf = std::move(remaining);
      c.out_off = 0;
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
          compact_outbuf(c);
          return true;
        }
        if (e == SSL_ERROR_WANT_READ)
        {
          // A renegotiation needs to read before we can write more.
          return true;
        }
        // Usually just the peer having gone away mid-response, so again a
        // level which a client cannot use to flood the log.
        LOG_DEBUG_FMT(
          "Connection {}: write failed: {}", c.id, ssl_error_string(e));
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
      // closed the corresponding connection.
      std::lock_guard<std::mutex> guard(lifecycle_mutex);
      if (wake_handle != nullptr)
      {
        (void)uv_async_send(wake_handle);
      }
    }

    void drive_connection(std::shared_ptr<Conn> conn, DriveInput input)
    {
      bool alive = true;
      bool more_to_read = false;

      if (conn->ssl == nullptr && conn->accepted_ctx != nullptr)
      {
        ERR_clear_error();
        conn->ssl = SSL_new(conn->accepted_ctx.get());
        if (conn->ssl == nullptr || SSL_set_fd(conn->ssl, conn->fd) != 1)
        {
          LOG_FAIL_FMT(
            "Connection {}: failed to create SSL state: {}",
            conn->id,
            ccf::crypto::OpenSSL::error_string(ERR_get_error()));
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
        else if (conn->outbuf.empty())
        {
          // The common case is a single response with nothing still draining,
          // so take ownership of the buffer instead of copying it again.
          // outbuf is only ever emptied alongside out_off being reset, so
          // there is no consumed prefix to preserve here.
          conn->outbuf = std::move(command.data);
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
      if (input.force_close)
      {
        // The server is going away. Whatever could be written above has been,
        // but the connection is not held open waiting for more room.
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
      if (conn->poll != nullptr)
      {
        (void)uv_poll_stop(conn->poll);
      }
      conn->worker_active = true;
      DriveInput input;
      input.events = actionable_events(*conn);
      // Read interest which the inbound budget is currently withholding stays
      // pending rather than being discarded: it may be the only record that
      // OpenSSL is holding buffered data which will never produce another
      // readability event.
      conn->pending_events &= ~input.events;
      input.commands.swap(conn->pending_commands);
      input.close_requested = std::exchange(conn->close_requested, false);
      input.force_close = conn->force_close;
      // The worker keeps the server alive for the whole pass. complete_drive()
      // posts its result and only then touches lifecycle_mutex and
      // wake_handle; without this the loop could consume that result, finish
      // the teardown and let stop() return in between, destroying the server
      // underneath the worker.
      conn->tls_tasks->add_action(ccf::tasks::make_basic_action(
        [self = shared_from_this(), conn, input = std::move(input)]() mutable {
          self->drive_connection(conn, std::move(input));
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
      auto conn = it->second;
      if (on_close)
      {
        on_close(conn->id);
      }
      id_to_fd.erase(conn->id);
      conns.erase(it);

      if (conn->poll != nullptr)
      {
        (void)uv_poll_stop(conn->poll);
      }
      assert(conn->ssl == nullptr);
      // The poll handle frees itself, so the Conn can be dropped here rather
      // than being parked until the close callback runs.
      close_handle(conn->poll);
      ::close(fd);
      conn->fd = -1;
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

        c->poll = new_handle<uv_poll_t>();
        const int poll_rc = uv_poll_init_socket(loop, c->poll, cfd);
        if (poll_rc != 0)
        {
          LOG_FAIL_FMT(
            "uv_poll_init_socket failed for connection {}: {}",
            cid,
            uv_strerror(poll_rc));
          // Never registered with the loop, so free it directly rather than
          // going through uv_close.
          // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
          delete c->poll;
          c->poll = nullptr;
          ::close(cfd);
          release_admitted();
          continue;
        }
        c->poll->data = c.get();
        const int start_rc =
          uv_poll_start(c->poll, UV_READABLE, on_connection_poll);
        if (start_rc != 0)
        {
          LOG_FAIL_FMT(
            "uv_poll_start failed for connection {}: {}",
            cid,
            uv_strerror(start_rc));
          close_handle(c->poll);
          ::close(cfd);
          release_admitted();
          continue;
        }
        conns.emplace(cfd, std::move(c));
        id_to_fd.emplace(cid, cfd);
        LOG_TRACE_FMT("Accepted connection {} on fd {}", cid, cfd);
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

    static void on_connection_poll(uv_poll_t* handle, int status, int events)
    {
      auto* conn = static_cast<Conn*>(handle->data);
      auto* self = conn->owner;
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

    void wake()
    {
      std::lock_guard<std::mutex> guard(lifecycle_mutex);
      if (wake_handle != nullptr && !stopping)
      {
        (void)uv_async_send(wake_handle);
      }
    }

    // Place the bound socket in the LISTEN state and arm its poll handle, if
    // the interface is ready to serve connections and is not already doing so.
    // Idempotent. Called from start() and, for an interface whose certificate
    // arrived later, from the loop thread once it has been applied.
    void begin_listening()
    {
      if (listening || listen_poll == nullptr || listen_fd < 0)
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
          conn->force_close || conn->close_requested ||
          !conn->pending_commands.empty() || actionable_events(*conn) != 0)
        {
          dispatch_connection(conn);
        }
        else
        {
          update_interest(*conn);
        }
      }

      bool shutting_down = false;
      {
        std::lock_guard<std::mutex> guard(lifecycle_mutex);
        shutting_down = stopping && !torn_down;
      }
      if (shutting_down)
      {
        // Some of those connections may have just gone, which may be the last
        // thing shutdown was waiting for.
        tear_down_on_loop();
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
        auto it = conns.find(fd);
        if (it != conns.end())
        {
          LOG_DEBUG_FMT("Closing idle connection {}", it->second->id);
          it->second->close_requested = true;
          dispatch_connection(it->second);
        }
      }
    }

    static void on_listen_poll(uv_poll_t* handle, int status, int events)
    {
      auto* self = static_cast<OpenSSLServer*>(handle->data);
      if (status < 0)
      {
        self->tear_down_on_loop();
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
      // Always drain, including while shutting down: shutdown completes only
      // once every connection worker's completion has been processed and its
      // connection closed, and drain_pending_out() resumes the teardown once
      // it has done so.
      self->drain_pending_out();
    }

    static void on_idle_timer(uv_timer_t* handle)
    {
      auto* self = static_cast<OpenSSLServer*>(handle->data);
      self->sweep_idle();
    }

    // Begin, or resume, shutdown on the loop thread.
    //
    // The listener closes immediately and every live connection is marked for
    // forced close, but the server's own handles can only go once those
    // connections have actually gone: a connection whose worker is still
    // running is still reading and writing its socket, so neither its fd nor
    // its poll handle may be touched here. drain_pending_out() calls back in
    // as each worker completes, and the last call finishes the job.
    //
    // The close is forced rather than deferred until buffered output has
    // flushed, so that each connection takes exactly one further worker pass
    // and shutdown cannot be held up by a peer which has stopped reading.
    //
    // Nothing here waits for the uv close callbacks. Each handle owns itself
    // (see new_handle()), so once torn_down is set nothing refers to them any
    // more and the server is safe to destroy, whether or not the loop ever
    // runs again.
    void tear_down_on_loop()
    {
      {
        std::lock_guard<std::mutex> guard(lifecycle_mutex);
        if (torn_down)
        {
          return;
        }
        stopping = true;
      }

      if (listen_poll != nullptr)
      {
        (void)uv_poll_stop(listen_poll);
        close_handle(listen_poll);
      }
      listening = false;
      if (listen_fd >= 0)
      {
        ::close(listen_fd);
        listen_fd = -1;
      }

      for (auto& [fd, conn] : conns)
      {
        // force_close is sticky, so a connection already on its way out is not
        // dispatched again. Without that, a connection whose output cannot
        // drain would be re-dispatched on every completion, spinning the loop
        // thread and a worker for as long as its peer declined to read.
        if (conn->force_close)
        {
          continue;
        }
        conn->force_close = true;
        dispatch_connection(conn);
      }
      if (!conns.empty())
      {
        // Workers still own these connections. Finish when they report back.
        return;
      }

      if (idle_timer != nullptr)
      {
        (void)uv_timer_stop(idle_timer);
        close_handle(idle_timer);
      }

      {
        // Cleared under the lock, because send()/close_connection() and
        // complete_drive() consult it from other threads. Clearing it before
        // the uv_close() means no other thread can observe the handle as
        // usable once it is closing.
        std::lock_guard<std::mutex> guard(lifecycle_mutex);
        auto* wake = wake_handle;
        wake_handle = nullptr;
        close_handle(wake);

        torn_down = true;
        teardown_cv.notify_all();
      }
    }

    // Drive shutdown to completion when nothing is running the loop. Only this
    // server's own queues need servicing - no libuv work is required, and no
    // other thread can be inside the loop - so this never runs the loop
    // itself.
    void tear_down_without_loop()
    {
      for (;;)
      {
        tear_down_on_loop();
        {
          std::lock_guard<std::mutex> guard(lifecycle_mutex);
          if (torn_down)
          {
            return;
          }
        }

        // A connection worker is still running. Service the task board so it
        // can finish, then pick up its completion.
        auto task = ccf::tasks::get_main_job_board().get_task();
        if (task != nullptr)
        {
          ccf::tasks::try_do_task(*task);
        }
        else
        {
          std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        drain_pending_out();
      }
    }

  public:
    // `on_data` is required; `on_close` and `on_accept` are optional. These
    // stay as explicit parameters rather than joining Config so that on_data
    // cannot be omitted, and so a transposition is a compile error (their
    // signatures differ).
    OpenSSLServer(
      Config config,
      OnData on_data_,
      OnClose on_close_ = {},
      OnAccept on_accept_ = {}) :
      loop(config.loop),
      shared_next_id(config.shared_next_id),
      idle_timeout(config.idle_timeout),
      inbound_admission(std::move(config.inbound_admission)),
      on_data(std::move(on_data_)),
      on_close(std::move(on_close_)),
      on_accept(std::move(on_accept_)),
      plaintext(config.plaintext)
    {
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
      std::lock_guard<std::mutex> guard(lifecycle_mutex);
      if (started)
      {
        return;
      }

      // Mark the server started before any handle is created. If one of the
      // steps below throws, the handles which were already created are still
      // registered with the loop and must be closed, and stop() is a no-op
      // unless `started` is set.
      torn_down = false;
      stopping = false;
      started = true;
      listening = false;

      listen_poll = new_handle<uv_poll_t>();
      listen_poll->data = this;
      int rc = uv_poll_init_socket(loop, listen_poll, listen_fd);
      if (rc != 0)
      {
        throw std::runtime_error(
          std::string("uv_poll_init_socket(listen) failed: ") +
          uv_strerror(rc));
      }

      wake_handle = new_handle<uv_async_t>();
      wake_handle->data = this;
      rc = uv_async_init(loop, wake_handle, on_wake);
      if (rc != 0)
      {
        throw std::runtime_error(
          std::string("uv_async_init failed: ") + uv_strerror(rc));
      }

      if (idle_timeout.has_value())
      {
        idle_timer = new_handle<uv_timer_t>();
        idle_timer->data = this;
        rc = uv_timer_init(loop, idle_timer);
        if (rc != 0)
        {
          throw std::runtime_error(
            std::string("uv_timer_init failed: ") + uv_strerror(rc));
        }
        rc = uv_timer_start(
          idle_timer,
          on_idle_timer,
          idle_sweep_interval_ms,
          idle_sweep_interval_ms);
        if (rc != 0)
        {
          throw std::runtime_error(
            std::string("uv_timer_start failed: ") + uv_strerror(rc));
        }
      }

      // Only actually listens if this interface can serve a connection now; a
      // TLS interface still waiting for its certificate stays bound but
      // unlistening until set_server_cert() supplies one.
      begin_listening();

      if (inbound_admission != nullptr)
      {
        // Woken when the node drops back under its inbound budget, so that
        // this interface re-arms its reads even if the bytes which freed the
        // budget belonged to a different one.
        admission_token =
          inbound_admission->register_waker([weak = weak_from_this()]() {
            if (auto self = weak.lock())
            {
              self->wake();
            }
          });
      }
    }

    // Tear the server down. Idempotent, and safe to call from the destructor.
    //
    // The teardown itself must run where it cannot race the loop, and that is
    // not something this class can work out for itself: a loop which is
    // running only reveals itself when it first invokes a callback, and for an
    // interface which has seen no connections that may never happen. So the
    // caller states it.
    //
    // `loop_state` == Running: another thread is running the loop, so the
    // teardown is posted to it and this blocks until it has run.
    //
    // `loop_state` == NotRunning: nothing is running the loop and nothing
    // will - node startup failed before the event loop was entered, or this is
    // a test which never started one. The teardown runs inline, which is safe
    // precisely because no other thread can be inside the loop, and returns
    // without waiting: the handles own themselves, so their close callbacks
    // simply never run.
    void stop(LoopState loop_state = LoopState::NotRunning)
    {
      std::unique_lock<std::mutex> lock(lifecycle_mutex);
      if (!started || torn_down)
      {
        return;
      }

      if (admission_token.has_value())
      {
        inbound_admission->unregister_waker(*admission_token);
        admission_token.reset();
      }

      if (loop_state == LoopState::NotRunning)
      {
        lock.unlock();
        tear_down_without_loop();
        return;
      }

      if (!stopping)
      {
        stopping = true;
        // tear_down_on_loop() clears wake_handle under this same lock before
        // closing it, so this cannot signal a handle which is already closing.
        if (wake_handle != nullptr)
        {
          (void)uv_async_send(wake_handle);
        }
      }

      // The loop performs the teardown. Keep servicing the task board while
      // waiting, because an in-flight connection worker may need to complete
      // before the loop can finish with it, and this thread may be one of the
      // few able to run it.
      while (!torn_down)
      {
        lock.unlock();
        auto task = ccf::tasks::get_main_job_board().get_task();
        if (task != nullptr)
        {
          ccf::tasks::try_do_task(*task);
        }
        lock.lock();
        if (!torn_down && task == nullptr)
        {
          teardown_cv.wait_for(lock, std::chrono::milliseconds(1));
        }
      }
    }

    // Thread-safe. Queue plaintext to be encrypted and written to `conn_id`.
    // The buffer is taken rather than copied, so a response of any size crosses
    // this boundary without another allocation.
    void send(::tcp::ConnID conn_id, std::vector<uint8_t>&& data)
    {
      {
        std::lock_guard<std::mutex> g(out_mutex);
        pending_out.push_back({conn_id, std::move(data), false});
      }
      wake();
    }

    // Thread-safe. Queue a copy of plaintext to be encrypted and written to
    // `conn_id`.
    void send(::tcp::ConnID conn_id, const uint8_t* data, size_t len)
    {
      send(conn_id, std::vector<uint8_t>(data, data + len));
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
