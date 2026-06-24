// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

// Bridges the OpenSSL-native transport (OpenSSLServer) to ccf::Session objects.
//
// This is the seam the real HTTP/HTTP2 sessions plug into once TLS lives in the
// connection layer:
//   * inbound plaintext from a connection -> ccf::Session::handle_incoming_data
//   * ccf::Session output (via ccf::SessionWriter) -> OpenSSLServer::send, which
//     encrypts + writes with backpressure
//   * connection teardown -> the owning session is dropped
//
// One ccf::Session is created per connection by a caller-supplied factory (e.g.
// "make an HTTPServerSession for this interface"). Sessions are created lazily
// on first inbound data and removed on close.
//
// Threading: OpenSSLServer invokes on_data/on_close on its epoll thread; the
// session may then process on OrderedTasks workers and reply via write_outbound
// from those threads. write_outbound/close_socket forward to OpenSSLServer's
// thread-safe send/close_connection, so this class is safe to call from any
// thread. The sessions map is guarded by a mutex.

#include "ccf/node/session.h"
#include "enclave/session_writer.h"
#include "host/tls/openssl_server.h"

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

namespace asynchost
{
  class OpenSSLSessionManager : public ccf::SessionWriter
  {
  public:
    // Creates the protocol session for a freshly seen connection. `writer` is
    // this manager - the session emits its (plaintext) output through it.
    // `peer_cert` is the client certificate (DER) captured at handshake, for
    // caller authentication.
    using SessionFactory = std::function<std::shared_ptr<ccf::Session>(
      ::tcp::ConnID conn_id,
      ccf::SessionWriter& writer,
      std::vector<uint8_t> peer_cert)>;

  private:
    std::unique_ptr<OpenSSLServer> server;
    SessionFactory factory;
    // Invoked (on the loop thread) when a connection's session is dropped, so an
    // owner can update per-interface counters/metrics.
    std::function<void(::tcp::ConnID)> on_session_closed;

    std::mutex sessions_mutex;
    std::unordered_map<::tcp::ConnID, std::shared_ptr<ccf::Session>> sessions;

    void on_data(uint64_t id, std::vector<uint8_t> data)
    {
      const auto conn_id = static_cast<::tcp::ConnID>(id);
      std::shared_ptr<ccf::Session> session;
      {
        std::lock_guard<std::mutex> guard(sessions_mutex);
        auto it = sessions.find(conn_id);
        if (it == sessions.end())
        {
          // Lazily create the session for a newly accepted connection. The
          // peer certificate is fetched here (on the loop thread) from the
          // handshaken connection.
          auto peer_cert = server->get_peer_cert(id);
          session = factory(conn_id, *this, std::move(peer_cert));
          if (session == nullptr)
          {
            // Factory refused (e.g. hard session cap) - tear the connection
            // down.
            server->close_connection(id);
            return;
          }
          sessions.emplace(conn_id, session);
        }
        else
        {
          session = it->second;
        }
      }

      if (session != nullptr)
      {
        session->handle_incoming_data({data.data(), data.size()});
      }
    }

    void on_close(uint64_t id)
    {
      const auto conn_id = static_cast<::tcp::ConnID>(id);
      bool had_session = false;
      {
        std::lock_guard<std::mutex> guard(sessions_mutex);
        had_session = sessions.erase(conn_id) > 0;
      }
      if (had_session && on_session_closed)
      {
        on_session_closed(conn_id);
      }
    }

  public:
    OpenSSLSessionManager(
      const std::string& cert_pem,
      const std::string& key_pem,
      const std::string& host,
      uint16_t port,
      SessionFactory factory_,
      const std::string& alpn = "",
      bool plaintext = false,
      bool verbose = false,
      std::atomic<uint64_t>* shared_next_id = nullptr,
      std::function<void(::tcp::ConnID)> on_session_closed_ = {}) :
      factory(std::move(factory_)),
      on_session_closed(std::move(on_session_closed_))
    {
      server = std::make_unique<OpenSSLServer>(
        cert_pem,
        key_pem,
        host,
        port,
        [this](uint64_t id, std::vector<uint8_t> data) {
          on_data(id, std::move(data));
        },
        [this](uint64_t id) { on_close(id); },
        alpn,
        plaintext,
        verbose,
        shared_next_id);
    }

    // The session for `id`, or nullptr. Thread-safe.
    std::shared_ptr<ccf::Session> get_session(::tcp::ConnID id)
    {
      std::lock_guard<std::mutex> guard(sessions_mutex);
      auto it = sessions.find(id);
      return it == sessions.end() ? nullptr : it->second;
    }

    // (Re)load this interface's server certificate (deferred cert / rotation).
    void set_server_cert(
      const std::string& cert_pem, const std::string& key_pem)
    {
      server->set_server_cert(cert_pem, key_pem);
    }

    // Register a pre-built session (used for outbound client sessions, whose
    // session is created before the connection is opened).
    void register_session(
      ::tcp::ConnID id, std::shared_ptr<ccf::Session> session)
    {
      std::lock_guard<std::mutex> guard(sessions_mutex);
      sessions.emplace(id, std::move(session));
    }

    // Open an outbound client connection bound to `id` (thread-safe).
    void connect(
      ::tcp::ConnID id, const std::string& host, const std::string& service)
    {
      server->connect(static_cast<int64_t>(id), host, service);
    }

    void start()
    {
      server->start();
    }

    void stop()
    {
      server->stop();
    }

    uint16_t port() const
    {
      return server->port();
    }

    // ccf::SessionWriter (callable from any thread).

    void write_outbound(
      ::tcp::ConnID id,
      std::span<const uint8_t> data,
      sockaddr /*addr*/ = {}) override
    {
      server->send(
        static_cast<uint64_t>(id), data.data(), data.size());
    }

    void close_socket(::tcp::ConnID id) override
    {
      {
        std::lock_guard<std::mutex> guard(sessions_mutex);
        sessions.erase(id);
      }
      server->close_connection(static_cast<uint64_t>(id));
    }
  };
}
