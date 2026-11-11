// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "tls/openssl_connection_engine.h"

#include <cstring>
#include <netdb.h>
#include <openssl/x509_vfy.h>

namespace ccf::tls
{
  class OpenSSLClient : public std::enable_shared_from_this<OpenSSLClient>
  {
  public:
    using OnData = OpenSSLConnectionEngine::OnData;
    using OnClose = OpenSSLConnectionEngine::OnClose;
    using OnHandshake = OpenSSLConnectionEngine::OnHandshake;
    using LoopState = OpenSSLConnectionEngine::LoopState;

    // Explicit defaults keep partial designated initializers warning-free.
    // NOLINTBEGIN(readability-redundant-member-init)
    struct Config
    {
      uv_loop_t* loop = uv_default_loop();
      std::optional<std::chrono::milliseconds> idle_timeout = std::nullopt;
      std::atomic<::tcp::ConnID>* shared_next_id = nullptr;
      std::shared_ptr<InboundAdmission> inbound_admission = nullptr;
      // Optional. Runs once on a connection worker after each TLS handshake,
      // before any application reads or queued writes; returning false closes
      // the connection. See OpenSSLConnectionEngine::OnHandshake.
      OnHandshake on_handshake = {};
      std::optional<TrafficKeyPolicy> traffic_key_policy = std::nullopt;
      // See OpenSSLConnectionEngine::Config::max_queued_output. Output sent
      // while a connection is being established counts towards it too, from
      // the moment connect() returns its id.
      std::optional<size_t> max_queued_output = std::nullopt;
    };

    struct ConnectConfig
    {
      std::string host = {};
      uint16_t port = 0;
      // Optional local address/hostname, resolved asynchronously too.
      std::string source_host = {};
      uint16_t source_port = 0;
      // Configured by the owner before submission; do not mutate while in use.
      // connect() rejects a context which does not set SSL_VERIFY_PEER or has
      // no trusted certificate in its store, so a misconfigured owner fails
      // closed rather than connecting to an unauthenticated peer. A verify
      // callback which overrides failures is the owner's responsibility.
      std::shared_ptr<SSL_CTX> tls_context = nullptr;
      // Bounds each establishment phase separately, not the whole attempt:
      // target resolution, source resolution (if any), each TCP address
      // candidate, and the TLS handshake. An attempt with N address candidates
      // can therefore take up to (N + 3) times this before OnClose.
      std::chrono::milliseconds per_phase_timeout{5000};
      std::optional<std::chrono::milliseconds> tcp_user_timeout = std::nullopt;
    };

    // NOLINTEND(readability-redundant-member-init)

  private:
    struct Address
    {
      sockaddr_storage value{};
      socklen_t size = 0;
    };

    struct Dial
    {
      OpenSSLClient* owner = nullptr;
      ::tcp::ConnID id = 0;
      ConnectConfig config;
      std::vector<Address> targets;
      std::vector<Address> sources;
      size_t candidate = 0;
      int fd = -1;
      uv_poll_t* poll = nullptr;
      uv_getaddrinfo_t* resolver = nullptr;
      std::chrono::steady_clock::time_point deadline;
      std::vector<OpenSSLConnectionEngine::OutItem> pending_commands;
    };

    // libuv owns completion, even after cancellation or client destruction.
    struct Resolution
    {
      uv_getaddrinfo_t request{};
      std::weak_ptr<OpenSSLClient> owner;
      ::tcp::ConnID id = 0;
      bool source = false;
    };

    std::shared_ptr<OpenSSLConnectionEngine> engine;
    uv_loop_t* loop;
    OnClose on_close;
    ccf::ds::Mutex pending_mutex;
    std::vector<std::pair<::tcp::ConnID, ConnectConfig>> pending_connects
      CCF_GUARDED_BY(pending_mutex);
    std::unordered_map<::tcp::ConnID, std::unique_ptr<Dial>> dials;
    uv_timer_t* connect_timer = nullptr;

    // OpenSSL client contexts default to SSL_VERIFY_NONE, which completes the
    // handshake with any certificate. Require peer verification against at
    // least one explicitly loaded trust anchor instead.
    static void require_peer_verification(SSL_CTX* ctx)
    {
      if ((SSL_CTX_get_verify_mode(ctx) & SSL_VERIFY_PEER) == 0)
      {
        throw std::invalid_argument(
          "Outbound TLS context must set SSL_VERIFY_PEER");
      }
      auto* store = SSL_CTX_get_cert_store(ctx);

      struct FreeObjects
      {
        void operator()(STACK_OF(X509_OBJECT) * objs) const
        {
          sk_X509_OBJECT_pop_free(objs, X509_OBJECT_free);
        }
      };

      // get1 copies the objects under the store's lock, so this is safe while
      // other connections are handshaking with the same context.
      const std::unique_ptr<STACK_OF(X509_OBJECT), FreeObjects> objects(
        store != nullptr ? X509_STORE_get1_objects(store) : nullptr);
      if (objects != nullptr)
      {
        for (int i = 0; i < sk_X509_OBJECT_num(objects.get()); ++i)
        {
          if (
            X509_OBJECT_get_type(sk_X509_OBJECT_value(objects.get(), i)) ==
            X509_LU_X509)
          {
            return;
          }
        }
      }
      throw std::invalid_argument(
        "Outbound TLS context must trust at least one certificate");
    }

    void discard_candidate(Dial& dial)
    {
      if (dial.poll != nullptr)
      {
        (void)uv_poll_stop(dial.poll);
        details::close_handle(dial.poll);
      }
      if (dial.fd >= 0)
      {
        details::close_socket(dial.fd);
        dial.fd = -1;
      }
    }

    void cancel_dial(::tcp::ConnID id)
    {
      const auto it = dials.find(id);
      if (it == dials.end())
      {
        return;
      }
      auto& dial = *it->second;
      if (dial.resolver != nullptr)
      {
        // A racing callback owns its storage and checks the registry.
        (void)uv_cancel(reinterpret_cast<uv_req_t*>(dial.resolver));
      }
      discard_candidate(dial);
      dials.erase(it);
      abandon(id);
    }

    // Reports an id which will never be adopted, having first stopped the
    // engine accepting output for it.
    void abandon(::tcp::ConnID id)
    {
      engine->abandon_establishing(id);
      if (on_close)
      {
        on_close(id);
      }
    }

    void connected(::tcp::ConnID id)
    {
      auto& dial = *dials.at(id);
      OpenSSLConnectionEngine::Socket socket{
        .id = id,
        .fd = std::exchange(dial.fd, -1),
        .tls_context = std::move(dial.config.tls_context),
        .outgoing = true,
        .poll = std::exchange(dial.poll, nullptr),
        .handshake_timeout = dial.config.per_phase_timeout,
        .pending_commands = std::move(dial.pending_commands)};
      dials.erase(id);
      if (!engine->adopt(std::move(socket)) && on_close)
      {
        on_close(id);
      }
    }

    void next_candidate(::tcp::ConnID id)
    {
      auto& dial = *dials.at(id);
      discard_candidate(dial);
      while (dial.candidate < dial.targets.size())
      {
        const auto& target = dial.targets[dial.candidate++];
        const int family = target.value.ss_family;
        dial.fd = socket(family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (dial.fd < 0)
        {
          LOG_DEBUG_FMT(
            "Connection {}: socket failed: {}",
            id,
            std::generic_category().message(errno));
          continue;
        }
        bool bound =
          dial.config.source_host.empty() && dial.config.source_port == 0;
        for (const auto& source : dial.sources)
        {
          if (
            source.value.ss_family == family &&
            ::bind(
              dial.fd,
              reinterpret_cast<const sockaddr*>(&source.value),
              source.size) == 0)
          {
            bound = true;
            break;
          }
        }
        if (!bound)
        {
          LOG_DEBUG_FMT("Connection {}: source binding failed", id);
          discard_candidate(dial);
          continue;
        }
        if (const auto error = details::configure_tcp_connection(dial.fd))
        {
          LOG_FAIL_FMT(
            "Connection {}: setsockopt({}): {}",
            id,
            error->option,
            std::generic_category().message(error->error));
          discard_candidate(dial);
          continue;
        }
        if (!details::set_user_timeout(dial.fd, dial.config.tcp_user_timeout))
        {
          discard_candidate(dial);
          continue;
        }
        const int rc = ::connect(
          dial.fd,
          reinterpret_cast<const sockaddr*>(&target.value),
          target.size);
        if (rc != 0 && errno != EINPROGRESS)
        {
          LOG_DEBUG_FMT(
            "Connection {}: connect failed: {}",
            id,
            std::generic_category().message(errno));
          discard_candidate(dial);
          continue;
        }
        auto poll = std::make_unique<uv_poll_t>();
        const int init_rc = uv_poll_init_socket(loop, poll.get(), dial.fd);
        if (init_rc != 0)
        {
          LOG_FAIL_FMT(
            "Connection {}: poll init: {}", id, uv_strerror(init_rc));
          discard_candidate(dial);
          continue;
        }
        dial.poll = poll.release();
        dial.poll->data = &dial;
        dial.deadline =
          std::chrono::steady_clock::now() + dial.config.per_phase_timeout;
        if (rc == 0)
        {
          connected(id);
          return;
        }
        const int poll_rc = uv_poll_start(
          dial.poll, UV_WRITABLE, [](uv_poll_t* handle, int status, int) {
            auto* dial = static_cast<Dial*>(handle->data);
            auto* self = dial->owner;
            const auto id = dial->id;
            int error = 0;
            socklen_t size = sizeof(error);
            if (
              status < 0 ||
              getsockopt(dial->fd, SOL_SOCKET, SO_ERROR, &error, &size) != 0 ||
              error != 0)
            {
              LOG_DEBUG_FMT("Connection {}: candidate failed", id);
              self->next_candidate(id);
              return;
            }
            self->connected(id);
          });
        if (poll_rc == 0)
        {
          return;
        }
        LOG_FAIL_FMT("Connection {}: poll start: {}", id, uv_strerror(poll_rc));
        discard_candidate(dial);
      }
      LOG_DEBUG_FMT("Connection {}: all address candidates failed", id);
      cancel_dial(id);
    }

    void resolve(::tcp::ConnID id, bool source)
    {
      auto& dial = *dials.at(id);
      auto request = std::make_unique<Resolution>();
      request->owner = weak_from_this();
      request->id = id;
      request->source = source;
      request->request.data = request.get();
      addrinfo hints{};
      hints.ai_family = AF_UNSPEC;
      hints.ai_socktype = SOCK_STREAM;
      hints.ai_flags = source ? AI_PASSIVE : 0;
      const auto& host = source ? dial.config.source_host : dial.config.host;
      const auto port =
        std::to_string(source ? dial.config.source_port : dial.config.port);
      dial.deadline =
        std::chrono::steady_clock::now() + dial.config.per_phase_timeout;
      const int rc = uv_getaddrinfo(
        loop,
        &request->request,
        [](uv_getaddrinfo_t* req, int status, addrinfo* result) {
          std::unique_ptr<Resolution> request(
            static_cast<Resolution*>(req->data));
          const auto free_result =
            std::unique_ptr<addrinfo, decltype(&uv_freeaddrinfo)>(
              result, uv_freeaddrinfo);
          auto self = request->owner.lock();
          if (self == nullptr)
          {
            return;
          }
          const auto it = self->dials.find(request->id);
          if (it == self->dials.end())
          {
            return;
          }
          auto& dial = *it->second;
          dial.resolver = nullptr;
          if (status != 0 || self->engine->is_stopping())
          {
            LOG_DEBUG_FMT(
              "Connection {}: resolution ended: {}",
              request->id,
              uv_strerror(status));
            self->cancel_dial(request->id);
            return;
          }
          auto& addresses = request->source ? dial.sources : dial.targets;
          for (auto* ai = result; ai != nullptr; ai = ai->ai_next)
          {
            if (
              (ai->ai_family == AF_INET || ai->ai_family == AF_INET6) &&
              ai->ai_addrlen <= sizeof(sockaddr_storage))
            {
              Address address;
              address.size = ai->ai_addrlen;
              memcpy(&address.value, ai->ai_addr, ai->ai_addrlen);
              addresses.push_back(address);
            }
          }
          if (
            !request->source &&
            (!dial.config.source_host.empty() || dial.config.source_port != 0))
          {
            self->resolve(request->id, true);
          }
          else
          {
            self->next_candidate(request->id);
          }
        },
        host.empty() ? nullptr : host.c_str(),
        port.c_str(),
        &hints);
      if (rc != 0)
      {
        LOG_DEBUG_FMT(
          "Connection {}: resolver submission: {}", id, uv_strerror(rc));
        cancel_dial(id);
        return;
      }
      dial.resolver = &request.release()->request;
    }

    void sweep_connects()
    {
      const auto now = std::chrono::steady_clock::now();
      std::vector<::tcp::ConnID> expired;
      for (const auto& [id, dial] : dials)
      {
        if (now >= dial->deadline)
        {
          expired.push_back(id);
        }
      }
      for (const auto id : expired)
      {
        LOG_DEBUG_FMT("Connection {}: establishment timed out", id);
        if (dials.at(id)->resolver != nullptr)
        {
          cancel_dial(id);
        }
        else
        {
          next_candidate(id);
        }
      }
      if (dials.empty())
      {
        (void)uv_timer_stop(connect_timer);
        details::close_handle(connect_timer);
      }
    }

    bool start_connect_timer()
    {
      if (connect_timer != nullptr)
      {
        return true;
      }
      auto timer = std::make_unique<uv_timer_t>();
      const int rc = uv_timer_init(loop, timer.get());
      if (rc != 0)
      {
        LOG_FAIL_FMT("Outbound timer init: {}", uv_strerror(rc));
        return false;
      }
      connect_timer = timer.release();
      connect_timer->data = this;
      const int timer_rc = uv_timer_start(
        connect_timer,
        [](uv_timer_t* timer) {
          static_cast<OpenSSLClient*>(timer->data)->sweep_connects();
        },
        10,
        10);
      if (timer_rc != 0)
      {
        LOG_FAIL_FMT("Outbound timer start: {}", uv_strerror(timer_rc));
        details::close_handle(connect_timer);
        return false;
      }
      return true;
    }

    void start_connects()
    {
      std::vector<std::pair<::tcp::ConnID, ConnectConfig>> connects;
      {
        ccf::ds::MutexGuard guard(pending_mutex);
        connects.swap(pending_connects);
      }
      for (auto& [id, config] : connects)
      {
        if (!start_connect_timer())
        {
          abandon(id);
          continue;
        }
        auto dial = std::make_unique<Dial>();
        dial->owner = this;
        dial->id = id;
        dial->config = std::move(config);
        dials.emplace(id, std::move(dial));
        resolve(id, false);
      }
    }

    void stop_connects()
    {
      while (!dials.empty())
      {
        cancel_dial(dials.begin()->first);
      }
      std::vector<std::pair<::tcp::ConnID, ConnectConfig>> abandoned;
      {
        ccf::ds::MutexGuard guard(pending_mutex);
        abandoned.swap(pending_connects);
      }
      for (const auto& [id, config] : abandoned)
      {
        abandon(id);
      }
      if (connect_timer != nullptr)
      {
        (void)uv_timer_stop(connect_timer);
        details::close_handle(connect_timer);
      }
    }

    void unconnected(::tcp::ConnID id, std::vector<uint8_t> data, bool close)
    {
      const auto it = dials.find(id);
      if (it == dials.end())
      {
        return;
      }
      if (close)
      {
        cancel_dial(id);
      }
      else
      {
        it->second->pending_commands.push_back({id, std::move(data), false});
      }
    }

    // Private so every instance is created by create(). Resolver callbacks
    // hold weak_from_this(), which is empty unless a shared_ptr owns this.
    OpenSSLClient(Config config, OnData on_data_, OnClose on_close_) :
      loop(config.loop),
      on_close(std::move(on_close_))
    {
      OpenSSLConnectionEngine::Config engine_config{
        .loop = loop,
        .idle_timeout = config.idle_timeout,
        .shared_next_id = config.shared_next_id,
        .inbound_admission = std::move(config.inbound_admission),
        .on_handshake = std::move(config.on_handshake),
        .traffic_key_policy = config.traffic_key_policy,
        .max_queued_output = config.max_queued_output,
        .on_wake = [this]() { start_connects(); },
        .on_stop = [this]() { stop_connects(); },
        .on_unconnected =
          [this](::tcp::ConnID id, std::vector<uint8_t> data, bool close) {
            unconnected(id, std::move(data), close);
          }};
      engine = std::make_shared<OpenSSLConnectionEngine>(
        std::move(engine_config), std::move(on_data_), on_close);
    }

  public:
    static std::shared_ptr<OpenSSLClient> create(
      Config config, OnData on_data, OnClose on_close = {})
    {
      // make_shared cannot reach the private constructor.
      // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
      return std::shared_ptr<OpenSSLClient>(new OpenSSLClient(
        std::move(config), std::move(on_data), std::move(on_close)));
    }

    OpenSSLClient(const OpenSSLClient&) = delete;
    OpenSSLClient& operator=(const OpenSSLClient&) = delete;
    OpenSSLClient(OpenSSLClient&&) = delete;
    OpenSSLClient& operator=(OpenSSLClient&&) = delete;

    ~OpenSSLClient()
    {
      stop();
    }

    void start()
    {
      engine->start();
    }

    void stop(LoopState state = LoopState::NotRunning)
    {
      engine->stop(state);
    }

    // Thread-safe, and safe to call from OnClose. Each returned id receives
    // exactly one OnClose, including failed/cancelled attempts. TLS/admission
    // failures do not retry addresses. Returns nullopt, with no OnClose, if the
    // client has not been started or is stopping. Throws std::invalid_argument
    // for an invalid configuration, including a TLS context which would not
    // authenticate the peer (see ConnectConfig::tls_context).
    [[nodiscard]] std::optional<::tcp::ConnID> connect(ConnectConfig config)
    {
      details::validate_user_timeout(config.tcp_user_timeout);
      if (
        config.host.empty() || config.port == 0 ||
        config.tls_context == nullptr || config.per_phase_timeout.count() <= 0)
      {
        throw std::invalid_argument(
          "Invalid outbound TLS connection configuration");
      }
      require_peer_verification(config.tls_context.get());
      const auto id = engine->allocate_id();
      // Before the attempt is published: the loop may abandon it at once, and
      // output may be sent to the id as soon as it has been returned.
      engine->begin_establishing(id);
      const bool submitted = engine->try_submit([&]() {
        ccf::ds::MutexGuard guard(pending_mutex);
        pending_connects.emplace_back(id, std::move(config));
      });
      if (!submitted)
      {
        engine->abandon_establishing(id);
        return std::nullopt;
      }
      return id;
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
  };
}
