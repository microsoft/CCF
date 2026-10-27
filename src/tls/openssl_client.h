// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "tls/openssl_connection_engine.h"

#include <cstring>
#include <netdb.h>

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
      OnHandshake on_handshake = {};
    };

    struct ConnectConfig
    {
      std::string host = {};
      uint16_t port = 0;
      // Optional local address/hostname, resolved asynchronously too.
      std::string source_host = {};
      uint16_t source_port = 0;
      // Configured by the owner before submission; do not mutate while in use.
      std::shared_ptr<SSL_CTX> tls_context = nullptr;
      std::chrono::milliseconds timeout{5000};
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
        .handshake_timeout = dial.config.timeout,
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
        dial.deadline = std::chrono::steady_clock::now() + dial.config.timeout;
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
      dial.deadline = std::chrono::steady_clock::now() + dial.config.timeout;
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
          if (on_close)
          {
            on_close(id);
          }
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
        if (on_close)
        {
          on_close(id);
        }
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

  public:
    OpenSSLClient(Config config, OnData on_data_, OnClose on_close_ = {}) :
      loop(config.loop),
      on_close(std::move(on_close_))
    {
      OpenSSLConnectionEngine::Config engine_config{
        .loop = loop,
        .idle_timeout = config.idle_timeout,
        .shared_next_id = config.shared_next_id,
        .inbound_admission = std::move(config.inbound_admission),
        .on_handshake = std::move(config.on_handshake),
        .on_wake = [this]() { start_connects(); },
        .on_stop = [this]() { stop_connects(); },
        .on_unconnected =
          [this](::tcp::ConnID id, std::vector<uint8_t> data, bool close) {
            unconnected(id, std::move(data), close);
          }};
      engine = std::make_shared<OpenSSLConnectionEngine>(
        std::move(engine_config), std::move(on_data_), on_close);
    }

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

    // Thread-safe. Each returned id receives exactly one OnClose, including
    // failed/cancelled attempts. TLS/admission failures do not retry addresses.
    ::tcp::ConnID connect(ConnectConfig config)
    {
      details::validate_user_timeout(config.tcp_user_timeout);
      if (
        config.host.empty() || config.port == 0 ||
        config.tls_context == nullptr || config.timeout.count() <= 0)
      {
        throw std::invalid_argument(
          "Invalid outbound TLS connection configuration");
      }
      const auto id = engine->allocate_id();
      engine->submit([&]() {
        ccf::ds::MutexGuard guard(pending_mutex);
        pending_connects.emplace_back(id, std::move(config));
      });
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
