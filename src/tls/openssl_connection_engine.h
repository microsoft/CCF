// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

// Connected TLS/plaintext sockets share polling, worker scheduling, buffering,
// and shutdown here. Listener policy and outbound dialing live in their owners.

#include "ccf/crypto/openssl/openssl_wrappers.h"
#include "ccf/crypto/pem.h"
#include "ccf/ds/locking.h"
#include "ds/internal_logger.h"
#include "tasks/ordered_tasks.h"
#include "tasks/task_system.h"
#include "tasks/worker.h"
#include "tcp/msg_types.h"
#include "tls/inbound_admission.h"
#include "tls/openssl_connection_utils.h"

#include <atomic>
#include <cassert>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
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

namespace ccf::tls
{
  // Socket setup and connection establishment live in the client/server.
  class OpenSSLConnectionEngine
    : public std::enable_shared_from_this<OpenSSLConnectionEngine>
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

    // Runs once on a worker after TLS establishment, before application reads
    // or queued writes. The SSL is borrowed for this call only. Returning false
    // rejects the peer. Policy (including certificate verification) belongs to
    // the owner; the engine does not relax the supplied context's policy.
    using OnHandshake = std::function<bool(::tcp::ConnID, SSL*, bool outgoing)>;

    // Whether anything is running the libuv loop when stop() is called. See
    // stop() for why this has to be stated rather than inferred.
    enum class LoopState : uint8_t
    {
      Running,
      NotRunning,
    };

    // Explicit defaults keep partial designated initializers warning-free.
    // NOLINTBEGIN(readability-redundant-member-init)
    struct Config
    {
      uv_loop_t* loop = uv_default_loop();
      std::optional<std::chrono::milliseconds> idle_timeout = std::nullopt;
      std::atomic<::tcp::ConnID>* shared_next_id = nullptr;
      std::shared_ptr<InboundAdmission> inbound_admission = nullptr;
      OnHandshake on_handshake = {};
      // Owner callbacks run on the loop and remain valid until stop returns.
      std::function<void()> on_wake = {};
      std::function<void()> on_stop = {};
      std::function<void(::tcp::ConnID, std::vector<uint8_t>, bool)>
        on_unconnected = {};
    };

    struct OutItem
    {
      ::tcp::ConnID id = 0;
      std::vector<uint8_t> data;
      bool close = false;
    };

    // adopt() consumes fd and poll even on failure. A non-null poll must be
    // initialized on this engine's loop and have no active worker.
    struct Socket
    {
      ::tcp::ConnID id = 0;
      int fd = -1;
      std::shared_ptr<SSL_CTX> tls_context = nullptr;
      bool outgoing = false;
      bool soft_limited = false;
      uv_poll_t* poll = nullptr;
      std::optional<std::chrono::milliseconds> handshake_timeout = std::nullopt;
      std::vector<OutItem> pending_commands = {};
    };

    // NOLINTEND(readability-redundant-member-init)

  private:
    static constexpr size_t read_chunk = 16384;
    static constexpr size_t max_read_per_event = read_chunk * 4;

    struct Conn
    {
      OpenSSLConnectionEngine* owner = nullptr;
      int fd = -1;
      uv_poll_t* poll = nullptr;
      std::shared_ptr<ccf::tasks::OrderedTasks> tls_tasks;
      std::shared_ptr<SSL_CTX> tls_context;
      SSL* ssl = nullptr;
      ::tcp::ConnID id = 0;
      // Admission decision from OnAccept, passed to OnData.
      bool soft_limited = false;
      bool outgoing = false;
      std::optional<std::chrono::steady_clock::time_point> handshake_deadline;

      enum class Establishment : uint8_t
      {
        Pending,
        Admitting,
        Cancelled
      };
      // The loop can cancel while a worker is inside SSL_do_handshake.
      // Admission claims this state before invoking owner callbacks, so a
      // close from those callbacks retains flush-before-close semantics.
      std::atomic<Establishment> establishment{Establishment::Pending};

      bool cancel_establishment()
      {
        auto expected = Establishment::Pending;
        return outgoing &&
          establishment.compare_exchange_strong(
            expected, Establishment::Cancelled);
      }

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
      int polled_events = 0;
      bool dirty_queued = false;
      std::vector<OutItem> pending_commands;
      int pending_events = 0;
      bool worker_active = false;
      bool close_requested = false;
      // Set on shutdown or idle expiry. Unlike close_requested it is sticky
      // and does not wait for buffered output to drain.
      bool force_close = false;
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

    uv_loop_t* loop = nullptr;
    std::atomic<::tcp::ConnID> next_id = 1;
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
    std::optional<size_t> admission_token CCF_GUARDED_BY(lifecycle_mutex);

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
    std::vector<OutItem> pending_out CCF_GUARDED_BY(out_mutex);
    std::vector<DriveResult> completed_drives CCF_GUARDED_BY(out_mutex);
    // Loop-owned connections affected by commands or worker completions.
    std::vector<std::shared_ptr<Conn>> dirty_connections;
    // Remember resumption even if saturation clears between loop passes.
    // Share the queue mutex so a coalesced wake cannot miss a later recheck.
    bool recheck_read_interest CCF_GUARDED_BY(out_mutex) = false;

    OnData on_data;
    OnClose on_close;
    OnHandshake on_handshake;
    std::function<void()> owner_wake;
    std::function<void()> owner_stop;
    std::function<void(::tcp::ConnID, std::vector<uint8_t>, bool)>
      on_unconnected;
    uv_timer_t* handshake_timer = nullptr;

    ccf::ds::Mutex out_mutex;
    // Notifications share handle lifetime protection; teardown is exclusive.
    ccf::ds::SharedMutex lifecycle_mutex;
    std::condition_variable_any teardown_cv;
    std::unordered_map<int, std::shared_ptr<Conn>> conns;
    std::unordered_map<::tcp::ConnID, int> id_to_fd;
    // Owned by the loop once closed - see details::close_handle().
    uv_async_t* wake_handle CCF_GUARDED_BY(lifecycle_mutex) = nullptr;
    uv_timer_t* idle_timer = nullptr;
    bool started CCF_GUARDED_BY(lifecycle_mutex) = false;
    // Writes require lifecycle_mutex; wake() can read before taking the lock.
    std::atomic<bool> stopping{false};
    // Set once the teardown has run: every connection dropped, every handle
    // handed to uv_close(). The handles may
    // not have been reclaimed by the loop yet, but nothing here refers to
    // them any more, so the engine is safe to destroy.
    bool torn_down CCF_GUARDED_BY(lifecycle_mutex) = false;

    void set_stopping(bool value) CCF_REQUIRES(lifecycle_mutex)
    {
      stopping.store(value, std::memory_order_release);
    }

    // Describe a failed SSL operation. SSL_get_error() only gives the
    // category: for SSL_ERROR_SSL the detail is in the (thread-local) error
    // queue, and for SSL_ERROR_SYSCALL it may be in errno instead. Reading the
    // oldest queued error here, then clearing the queue, also keeps its
    // entries from being misattributed to the next operation this worker
    // performs.
    static std::string ssl_error_string(int ssl_error)
    {
      switch (ssl_error)
      {
        case SSL_ERROR_ZERO_RETURN:
        {
          return "peer closed the TLS connection";
        }

        case SSL_ERROR_SSL:
        case SSL_ERROR_SYSCALL:
        {
          if (ERR_peek_error() != 0)
          {
            return ccf::crypto::OpenSSL::first_error();
          }
          if (ssl_error == SSL_ERROR_SYSCALL)
          {
            return fmt::format(
              "syscall failed: {}", std::generic_category().message(errno));
          }
          return "protocol error";
        }

        default:
        {
          return fmt::format("SSL_get_error {}", ssl_error);
        }
      }
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
      if (events == c.polled_events)
      {
        return;
      }
      if (events == 0)
      {
        // uv_poll_start rejects an empty mask, and there is genuinely nothing
        // to wait for: this connection resumes when the node drops back under
        // its inbound budget, at which point every transport is woken.
        (void)uv_poll_stop(c.poll);
        c.polled_events = 0;
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
      else
      {
        c.polled_events = events;
      }
    }

    // Returns false if the connection should be closed.
    bool do_handshake(Conn& c, bool& more_to_read)
    {
      // The error queue is thread-local and SSL_get_error() consults it. Clear
      // it before each operation because successive actions for this
      // connection may execute on different workers.
      ERR_clear_error();
      const int r = SSL_do_handshake(c.ssl);
      if (r == 1)
      {
        if (c.outgoing)
        {
          auto expected = Conn::Establishment::Pending;
          if (!c.establishment.compare_exchange_strong(
                expected, Conn::Establishment::Admitting))
          {
            return false;
          }
        }
        // With no post-handshake session tickets, the peer may wait for the
        // delayed ACK of its Finished before Nagle sends its first request.
        if (const auto error = details::request_tcp_quickack(c.fd))
        {
          LOG_DEBUG_FMT(
            "setsockopt({}) failed for connection {} after TLS handshake: {}",
            error->option,
            c.id,
            std::generic_category().message(error->error));
        }
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
        // Only completed handshakes reach this point. Ready connections do
        // not re-enter do_handshake(), so retries cannot duplicate this event.
        const auto* group = SSL_get0_group_name(c.ssl);
        LOG_INFO_FMT(
          "TLS handshake completed: connection_id={}, negotiated_group={}",
          c.id,
          group != nullptr ? group : "none");
        if (on_handshake && !on_handshake(c.id, c.ssl, c.outgoing))
        {
          LOG_DEBUG_FMT("Connection {}: rejected after TLS handshake", c.id);
          return false;
        }
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
      CCF_EXCLUDES(out_mutex, lifecycle_mutex)
    {
      {
        ccf::ds::MutexGuard guard(out_mutex);
        completed_drives.push_back(
          {std::move(conn),
           alive,
           more_to_read,
           std::chrono::steady_clock::now()});
      }
      // Unlike wake(), this must signal even while stopping: shutdown only
      // completes once the loop has observed every outstanding completion and
      // closed the corresponding connection.
      ccf::ds::SharedMutexReadGuard guard(lifecycle_mutex);
      notify_loop();
    }

    void drive_connection(std::shared_ptr<Conn> conn, DriveInput input)
    {
      if (
        input.force_close ||
        conn->establishment.load() == Conn::Establishment::Cancelled)
      {
        if (conn->ssl != nullptr)
        {
          ERR_clear_error();
          (void)SSL_shutdown(conn->ssl);
          SSL_free(conn->ssl);
          conn->ssl = nullptr;
        }
        complete_drive(std::move(conn), false, false);
        return;
      }
      bool alive = true;
      bool more_to_read = false;

      if (conn->ssl == nullptr && conn->tls_context != nullptr)
      {
        ERR_clear_error();
        conn->ssl = SSL_new(conn->tls_context.get());
        if (conn->ssl == nullptr || SSL_set_fd(conn->ssl, conn->fd) != 1)
        {
          const auto error = ccf::crypto::OpenSSL::first_error();
          LOG_FAIL_FMT(
            "Connection {}: failed to create SSL state: {}", conn->id, error);
          if (conn->ssl != nullptr)
          {
            SSL_free(conn->ssl);
            conn->ssl = nullptr;
          }
          complete_drive(std::move(conn), false, false);
          return;
        }
        SSL_set_mode(
          conn->ssl,
          SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE);
        if (conn->outgoing)
        {
          SSL_set_connect_state(conn->ssl);
        }
        else
        {
          SSL_set_accept_state(conn->ssl);
        }
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
        // Shutdown and idle expiry do not wait for buffered output to drain.
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
        conn->polled_events = 0;
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
      // The worker keeps the engine alive for the whole pass. complete_drive()
      // posts its result and only then touches lifecycle_mutex and
      // wake_handle; without this the loop could consume that result, finish
      // the teardown and let stop() return in between, destroying the engine
      // underneath the worker.
      conn->tls_tasks->add_action(ccf::tasks::make_basic_action(
        [self = shared_from_this(), conn, input = std::move(input)]() mutable {
          self->drive_connection(conn, std::move(input));
        },
        "OpenSSLConnectionEngine::drive_connection"));
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
        conn->polled_events = 0;
      }
      assert(conn->ssl == nullptr);
      // The poll handle frees itself, so the Conn can be dropped here rather
      // than being parked until the close callback runs.
      details::close_handle(conn->poll);
      details::close_socket(fd);
      conn->fd = -1;
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

    void notify_loop() CCF_REQUIRES_SHARED(lifecycle_mutex)
    {
      if (wake_handle != nullptr)
      {
        (void)uv_async_send(wake_handle);
      }
    }

    void wake() CCF_EXCLUDES(lifecycle_mutex)
    {
      if (stopping.load(std::memory_order_acquire))
      {
        return;
      }
      ccf::ds::SharedMutexReadGuard guard(lifecycle_mutex);
      if (!stopping.load(std::memory_order_relaxed))
      {
        notify_loop();
      }
    }

    void mark_dirty(const std::shared_ptr<Conn>& conn)
    {
      if (!conn->dirty_queued)
      {
        dirty_connections.push_back(conn);
        conn->dirty_queued = true;
      }
    }

    // Apply worker completions and cross-thread commands on the libuv thread.
    void drain_pending_out() CCF_EXCLUDES(out_mutex, lifecycle_mutex)
    {
      bool recheck_all = false;
      std::vector<OutItem> items;
      std::vector<DriveResult> completions;
      {
        ccf::ds::MutexGuard g(out_mutex);
        recheck_all = std::exchange(recheck_read_interest, false);
        std::swap(items, pending_out);
        std::swap(completions, completed_drives);
      }

      if (owner_wake && !stopping.load())
      {
        owner_wake();
      }

      for (auto& item : items)
      {
        auto fit = id_to_fd.find(item.id);
        if (fit == id_to_fd.end())
        {
          if (on_unconnected)
          {
            on_unconnected(item.id, std::move(item.data), item.close);
          }
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
          if (cit->second->cancel_establishment())
          {
            cit->second->force_close = true;
          }
        }
        else
        {
          cit->second->last_active = std::chrono::steady_clock::now();
          cit->second->pending_commands.push_back(std::move(item));
        }
        mark_dirty(cit->second);
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
        if (conn->state == Conn::Ready)
        {
          conn->handshake_deadline.reset();
        }
        if (!completion.alive)
        {
          close_conn(conn->fd);
        }
        else
        {
          if (completion.more_to_read)
          {
            // Data is buffered where polling cannot see it, so ask for another
            // pass explicitly. The loop below dispatches on pending_events.
            conn->pending_events |= UV_READABLE;
          }
          mark_dirty(conn);
        }
      }

      const auto service = [this](const std::shared_ptr<Conn>& conn) {
        if (conn->worker_active)
        {
          return;
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
      };
      if (recheck_all || inbound_saturated())
      {
        for (auto& conn : dirty_connections)
        {
          conn->dirty_queued = false;
        }
        for (auto& [fd, conn] : conns)
        {
          service(conn);
        }
      }
      else
      {
        for (auto& conn : dirty_connections)
        {
          conn->dirty_queued = false;
          const auto it = conns.find(conn->fd);
          if (it != conns.end() && it->second == conn)
          {
            service(conn);
          }
        }
      }
      dirty_connections.clear();

      bool shutting_down = false;
      {
        ccf::ds::SharedMutexReadGuard guard(lifecycle_mutex);
        shutting_down = stopping.load(std::memory_order_relaxed) && !torn_down;
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
          it->second->force_close = true;
          dispatch_connection(it->second);
        }
      }
    }

    void sweep_handshakes()
    {
      const auto now = std::chrono::steady_clock::now();
      bool handshaking = false;
      for (const auto& [fd, conn] : conns)
      {
        const auto deadline = conn->handshake_deadline;
        handshaking |= deadline.has_value();
        if (
          deadline.has_value() && now >= *deadline &&
          (!conn->outgoing || conn->cancel_establishment()))
        {
          conn->force_close = true;
          dispatch_connection(conn);
        }
      }
      if (!handshaking)
      {
        (void)uv_timer_stop(handshake_timer);
        details::close_handle(handshake_timer);
      }
    }

    bool start_handshake_timer()
    {
      if (handshake_timer != nullptr)
      {
        return true;
      }
      auto timer = std::make_unique<uv_timer_t>();
      const int rc = uv_timer_init(loop, timer.get());
      if (rc != 0)
      {
        LOG_FAIL_FMT("Handshake timer init: {}", uv_strerror(rc));
        return false;
      }
      handshake_timer = timer.release();
      handshake_timer->data = this;
      const int timer_rc = uv_timer_start(
        handshake_timer,
        [](uv_timer_t* timer) {
          static_cast<OpenSSLConnectionEngine*>(timer->data)
            ->sweep_handshakes();
        },
        10,
        10);
      if (timer_rc != 0)
      {
        LOG_FAIL_FMT("Handshake timer start: {}", uv_strerror(timer_rc));
        details::close_handle(handshake_timer);
        return false;
      }
      return true;
    }

    static void on_wake(uv_async_t* handle)
    {
      auto* self = static_cast<OpenSSLConnectionEngine*>(handle->data);
      // Always drain, including while shutting down: shutdown completes only
      // once every connection worker's completion has been processed and its
      // connection closed, and drain_pending_out() resumes the teardown once
      // it has done so.
      self->drain_pending_out();
    }

    static void on_idle_timer(uv_timer_t* handle)
    {
      auto* self = static_cast<OpenSSLConnectionEngine*>(handle->data);
      self->sweep_idle();
    }

    void finish_teardown() CCF_REQUIRES(lifecycle_mutex)
    {
      auto* wake = wake_handle;
      wake_handle = nullptr;
      details::close_handle(wake);
      torn_down = true;
      teardown_cv.notify_all();
    }

    // Begin, or resume, shutdown on the loop thread.
    //
    // The owner stops establishment and every live connection is marked for
    // forced close, but the engine's own handles can only go once those
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
    // more and the engine is safe to destroy, whether or not the loop ever
    // runs again.
    void tear_down_on_loop() CCF_EXCLUDES(lifecycle_mutex)
    {
      {
        ccf::ds::SharedMutexExclusiveGuard guard(lifecycle_mutex);
        if (torn_down)
        {
          return;
        }
        set_stopping(true);
      }

      if (owner_stop)
      {
        owner_stop();
      }
      if (handshake_timer != nullptr)
      {
        (void)uv_timer_stop(handshake_timer);
        details::close_handle(handshake_timer);
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
        (void)conn->cancel_establishment();
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
        details::close_handle(idle_timer);
      }

      {
        // Cleared under the lock, because send()/close_connection() and
        // complete_drive() consult it from other threads. Clearing it before
        // the uv_close() means no other thread can observe the handle as
        // usable once it is closing.
        ccf::ds::SharedMutexExclusiveGuard guard(lifecycle_mutex);
        finish_teardown();
      }
    }

    // Drive shutdown to completion when nothing is running the loop. Only this
    // engine's own queues need servicing - no libuv work is required, and no
    // other thread can be inside the loop - so this never runs the loop
    // itself.
    void tear_down_without_loop() CCF_EXCLUDES(out_mutex, lifecycle_mutex)
    {
      for (;;)
      {
        tear_down_on_loop();
        {
          ccf::ds::SharedMutexExclusiveGuard guard(lifecycle_mutex);
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
    // Thread-safe. Submission and stop publication share the lifecycle gate.
    // enqueue must only append to the owner's queue and must not call back
    // into this engine. Its work is consumed by Config::on_wake or on_stop.
    template <typename Enqueue>
    void submit(Enqueue&& enqueue) CCF_EXCLUDES(lifecycle_mutex)
    {
      ccf::ds::SharedMutexReadGuard guard(lifecycle_mutex);
      if (!started || stopping.load())
      {
        throw std::logic_error(
          "Connection submission requires a running engine");
      }
      std::forward<Enqueue>(enqueue)();
      notify_loop();
    }

    ::tcp::ConnID allocate_id()
    {
      return shared_next_id != nullptr ? shared_next_id->fetch_add(1) :
                                         next_id.fetch_add(1);
    }

    bool is_stopping() const
    {
      return stopping.load(std::memory_order_acquire);
    }

    // Loop-thread only, except during stop(NotRunning).
    void shutdown_on_loop()
    {
      tear_down_on_loop();
    }

    void wake_owner()
    {
      wake();
    }

    // Loop-thread only. Successful handoff owns all future socket I/O and
    // close notification. On failure the caller releases its admission/id.
    bool adopt(Socket socket)
    {
      auto conn = std::make_shared<Conn>();
      conn->owner = this;
      conn->id = socket.id;
      conn->fd = socket.fd;
      conn->tls_context = std::move(socket.tls_context);
      conn->outgoing = socket.outgoing;
      conn->soft_limited = socket.soft_limited;
      conn->pending_commands = std::move(socket.pending_commands);
      conn->poll = socket.poll;
      const auto fail = [&]() {
        details::close_handle(conn->poll);
        details::close_socket(conn->fd);
        return false;
      };
      if (conn->poll != nullptr)
      {
        (void)uv_poll_stop(conn->poll);
      }
      else
      {
        auto poll = std::make_unique<uv_poll_t>();
        const int rc = uv_poll_init_socket(loop, poll.get(), conn->fd);
        if (rc != 0)
        {
          LOG_FAIL_FMT(
            "uv_poll_init_socket failed for connection {}: {}",
            conn->id,
            uv_strerror(rc));
          details::close_socket(conn->fd);
          return false;
        }
        conn->poll = poll.release();
      }
      conn->poll->data = conn.get();
      if (socket.handshake_timeout)
      {
        if (!start_handshake_timer())
        {
          return fail();
        }
        conn->handshake_deadline =
          std::chrono::steady_clock::now() + *socket.handshake_timeout;
      }
      conn->tls_tasks = ccf::tasks::OrderedTasks::create(
        ccf::tasks::get_main_job_board(),
        "TLS connection " + std::to_string(conn->id));
      if (conn->tls_context == nullptr)
      {
        conn->state = Conn::Ready;
      }
      if (!conn->outgoing)
      {
        const int rc =
          uv_poll_start(conn->poll, UV_READABLE, on_connection_poll);
        if (rc != 0)
        {
          LOG_FAIL_FMT(
            "uv_poll_start failed for connection {}: {}",
            conn->id,
            uv_strerror(rc));
          return fail();
        }
        conn->polled_events = UV_READABLE;
      }
      conns.emplace(conn->fd, conn);
      id_to_fd.emplace(conn->id, conn->fd);
      if (conn->outgoing)
      {
        dispatch_connection(conn);
      }
      return true;
    }

    OpenSSLConnectionEngine(
      Config config, OnData on_data_, OnClose on_close_ = {}) :
      loop(config.loop),
      shared_next_id(config.shared_next_id),
      idle_timeout(config.idle_timeout),
      inbound_admission(std::move(config.inbound_admission)),
      on_data(std::move(on_data_)),
      on_close(std::move(on_close_)),
      on_handshake(std::move(config.on_handshake)),
      owner_wake(std::move(config.on_wake)),
      owner_stop(std::move(config.on_stop)),
      on_unconnected(std::move(config.on_unconnected))
    {}

    OpenSSLConnectionEngine(const OpenSSLConnectionEngine&) = delete;
    OpenSSLConnectionEngine& operator=(const OpenSSLConnectionEngine&) = delete;
    OpenSSLConnectionEngine(OpenSSLConnectionEngine&&) = delete;
    OpenSSLConnectionEngine& operator=(OpenSSLConnectionEngine&&) = delete;

    ~OpenSSLConnectionEngine()
    {
      stop();
    }

    void start(std::function<void()> owner_start = {})
      CCF_EXCLUDES(lifecycle_mutex)
    {
      ccf::ds::SharedMutexExclusiveGuard guard(lifecycle_mutex);
      if (started)
      {
        return;
      }

      // Mark the engine started before any handle is created. If one of the
      // steps below throws, the handles which were already created are still
      // registered with the loop and must be closed, and stop() is a no-op
      // unless `started` is set.
      torn_down = false;
      set_stopping(false);
      started = true;
      auto wake = std::make_unique<uv_async_t>();
      int rc = uv_async_init(loop, wake.get(), on_wake);
      if (rc != 0)
      {
        throw std::runtime_error(
          std::string("uv_async_init failed: ") + uv_strerror(rc));
      }
      wake_handle = wake.release();
      wake_handle->data = this;

      if (idle_timeout.has_value())
      {
        auto timer = std::make_unique<uv_timer_t>();
        rc = uv_timer_init(loop, timer.get());
        if (rc != 0)
        {
          throw std::runtime_error(
            std::string("uv_timer_init failed: ") + uv_strerror(rc));
        }
        idle_timer = timer.release();
        idle_timer->data = this;
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

      if (inbound_admission != nullptr)
      {
        // Woken when the node drops back under its inbound budget, so that
        // this interface re-arms its reads even if the bytes which freed the
        // budget belonged to a different one.
        admission_token =
          inbound_admission->register_waker([weak = weak_from_this()]() {
            if (auto self = weak.lock())
            {
              {
                ccf::ds::MutexGuard g(self->out_mutex);
                self->recheck_read_interest = true;
              }
              self->wake();
            }
          });
      }
      if (owner_start)
      {
        owner_start();
      }
    }

    // Tear the engine down. Idempotent, and safe to call from the destructor.
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
      CCF_EXCLUDES(out_mutex, lifecycle_mutex)
    {
      ccf::ds::SharedMutexExclusiveGuard lock(lifecycle_mutex);
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

      if (!stopping.load(std::memory_order_relaxed))
      {
        set_stopping(true);
        // tear_down_on_loop() clears wake_handle under this same lock before
        // closing it, so this cannot signal a handle which is already closing.
        notify_loop();
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
      CCF_EXCLUDES(out_mutex, lifecycle_mutex)
    {
      {
        ccf::ds::MutexGuard g(out_mutex);
        pending_out.push_back({conn_id, std::move(data), false});
      }
      wake();
    }

    // Thread-safe. Queue a copy of plaintext to be encrypted and written to
    // `conn_id`.
    void send(::tcp::ConnID conn_id, const uint8_t* data, size_t len)
      CCF_EXCLUDES(out_mutex, lifecycle_mutex)
    {
      send(conn_id, std::vector<uint8_t>(data, data + len));
    }

    // Thread-safe. Request that `conn_id` be torn down.
    void close_connection(::tcp::ConnID conn_id)
      CCF_EXCLUDES(out_mutex, lifecycle_mutex)
    {
      {
        ccf::ds::MutexGuard g(out_mutex);
        pending_out.push_back({conn_id, {}, true});
      }
      wake();
    }
  };
}
