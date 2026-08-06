// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

// Bridges the OpenSSL-native transport (OpenSSLServer) to ccf::Session objects:
//
//   * inbound plaintext from a connection -> ccf::Session::handle_incoming_data
//   * ccf::Session output (via ccf::SessionWriter) -> OpenSSLServer::send,
//     which encrypts and writes with backpressure
//   * connection teardown -> the owning session is dropped
//
// One ccf::Session is created per connection by a caller-supplied factory (e.g.
// "make an HTTPServerSession for this interface"). Sessions are created lazily
// on first inbound data and removed on close.
//
// Note that admission control is deliberately *not* tied to the session: a
// connection is admitted (and counted) by the transport's OnAccept before any
// session exists, and released here in on_close, once per admitted connection.
// Tying it to the session would leave connections which complete the TLS
// handshake but never send a request entirely uncounted.
//
// Threading: OpenSSLServer invokes on_data on its TLS OrderedTasks worker and
// on_close on its loop thread. The session may dispatch again to its own
// OrderedTasks and reply via write_outbound from any worker. Every public
// method is therefore safe to call from any thread, and the connection map is
// guarded by a mutex.

#include "ccf/node/session.h"
#include "enclave/session_writer.h"
#include "host/tls/openssl_server.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
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
    // caller authentication. `soft_limited` is the admission decision taken
    // when the connection was accepted.
    using SessionFactory = std::function<std::shared_ptr<ccf::Session>(
      ::tcp::ConnID conn_id,
      ccf::SessionWriter& writer,
      std::vector<uint8_t> peer_cert,
      bool soft_limited)>;

  private:
    std::shared_ptr<OpenSSLServer> server;
    SessionFactory factory;
    // Invoked when an admitted connection is torn down, so an owner can
    // release whatever it reserved at accept time. Called on the loop thread
    // from on_close, exactly once per admitted connection.
    std::function<void(::tcp::ConnID)> on_connection_closed;

    struct ConnState
    {
      std::shared_ptr<ccf::Session> session;
      // The session asked for the connection to be closed. The transport
      // teardown is asynchronous, so bytes already in flight may still arrive;
      // they are dropped rather than being used to build a replacement
      // session for a connection which is going away.
      bool closing = false;
    };

    std::mutex conns_mutex;
    std::unordered_map<::tcp::ConnID, ConnState> conns;

    void on_data(
      ::tcp::ConnID conn_id,
      std::vector<uint8_t> data,
      const std::vector<uint8_t>& peer_cert,
      bool soft_limited)
    {
      std::shared_ptr<ccf::Session> session;
      {
        std::lock_guard<std::mutex> guard(conns_mutex);
        auto& state = conns[conn_id];
        if (state.closing)
        {
          return;
        }
        if (state.session == nullptr)
        {
          state.session = factory(conn_id, *this, peer_cert, soft_limited);
          if (state.session == nullptr)
          {
            // Factory refused - tear the connection down.
            state.closing = true;
            server->close_connection(conn_id);
            return;
          }
        }
        session = state.session;
      }

      session->handle_incoming_data({data.data(), data.size()});
    }

    void on_close(::tcp::ConnID conn_id)
    {
      {
        std::lock_guard<std::mutex> guard(conns_mutex);
        conns.erase(conn_id);
      }

      // Unconditional: the connection, not the session, is what was reserved
      // at accept time, and a connection which never sent a request has no
      // session to key off.
      if (on_connection_closed)
      {
        on_connection_closed(conn_id);
      }
    }

  public:
    // Takes the transport's own Config verbatim, so there is a single place
    // where a listening interface is described.
    OpenSSLSessionManager(
      OpenSSLServer::Config config,
      SessionFactory factory_,
      std::function<void(::tcp::ConnID)> on_connection_closed_ = {},
      OpenSSLServer::OnAccept on_accept = {}) :
      factory(std::move(factory_)),
      on_connection_closed(std::move(on_connection_closed_))
    {
      server = std::make_shared<OpenSSLServer>(
        std::move(config),
        [this](
          ::tcp::ConnID id,
          std::vector<uint8_t> data,
          const std::vector<uint8_t>& peer_cert,
          bool soft_limited) {
          on_data(id, std::move(data), peer_cert, soft_limited);
        },
        [this](::tcp::ConnID id) { on_close(id); },
        std::move(on_accept));
    }

    // The session for `id`, or nullptr. Thread-safe.
    std::shared_ptr<ccf::Session> get_session(::tcp::ConnID id)
    {
      std::lock_guard<std::mutex> guard(conns_mutex);
      auto it = conns.find(id);
      return it == conns.end() ? nullptr : it->second.session;
    }

    // (Re)load this interface's server certificate (deferred cert / rotation).
    void set_server_cert(
      const std::string& cert_pem, const std::string& key_pem)
    {
      server->set_server_cert(cert_pem, key_pem);
    }

    void start()
    {
      server->start();
    }

    void stop(
      OpenSSLServer::LoopState loop_state =
        OpenSSLServer::LoopState::NotRunning)
    {
      server->stop(loop_state);
    }

    uint16_t port() const
    {
      return server->port();
    }

    // ccf::SessionWriter (callable from any thread).

    void write_outbound(
      ::tcp::ConnID id,
      std::span<const uint8_t> data,
      const ccf::SessionEndpoint& /*peer*/ = {}) override
    {
      server->send(id, data.data(), data.size());
    }

    void close_socket(::tcp::ConnID id) override
    {
      {
        std::lock_guard<std::mutex> guard(conns_mutex);
        auto it = conns.find(id);
        if (it != conns.end())
        {
          it->second.closing = true;
          it->second.session.reset();
        }
      }
      // No release here: the connection's reservation is released by on_close
      // when the transport has actually torn it down, exactly once.
      server->close_connection(id);
    }
  };
}
