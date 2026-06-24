// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

// NOTE: This is a fresh, standalone rewrite that merges the responsibilities
// previously split across:
//   - src/enclave/rpc_sessions.h    (RPCSessions: ccf::Session lifecycle,
//                                     listening-interface limits, certs)
//   - src/host/rpc_connections.h    (RPCConnectionsImpl: libuv sockets, ConnID
//                                     allocation, socket <-> ringbuffer bridge)
//
// The host/enclave ringbuffer split was technical debt from SGX. With that gone
// we own both the libuv sockets and the ccf::Session objects in one place, and
// data flows directly:
//   inbound:  socket on_read --------------------> session.handle_incoming_data
//   outbound: session -> SessionWriter sink -> LoopExecutor -> socket.write
//
// This file is intentionally NOT yet added to the build. It is meant to be
// reviewed standalone and then plugged in (potentially behind a compile-time
// switch) once complete. It targets the *post-swap* session interfaces:
//   * Sessions are constructed with a `ccf::SessionWriter&` instead of a
//     `ringbuffer::AbstractWriterFactory&`.
//   * Session::handle_incoming_data receives raw socket bytes (no serialised
//     tcp_inbound / udp_inbound framing) plus the source address (used by
//     datagram transports, ignored by stream transports).
// Those session-side changes are deliberately left for the wiring step.
//
// Socket I/O is factored per transport into RPCSocketSet<TCP>/<UDP> (see
// rpc_socket_set.h); this manager owns one of each and holds all the shared
// session/interface/cert state. That composition is purely an in-process
// organisation detail - there is no ringbuffer or arms-length boundary.

#include "ccf/pal/locking.h"
#include "ccf/service/node_info_network.h"
#include "ds/internal_logger.h"
#include "enclave/no_more_sessions.h"
#include "enclave/session.h"
#include "enclave/session_writer.h"
#include "forwarder_types.h"
#include "host/loop_executor.h"
#include "host/rpc_socket_set.h"
#include "http/http2_session.h"
#include "http/http_session.h"
#include "node/rpc/custom_protocol_subsystem.h"
#include "node/session_metrics.h"
#include "quic/quic_session.h"
#include "rpc_handler.h"
#include "tls/cert.h"
#include "tls/client.h"
#include "tls/context.h"
#include "tls/plaintext_server.h"
#include "tls/server.h"

#include <atomic>
#include <map>
#include <memory>
#include <unordered_map>

namespace ccf
{
  using QUICSessionImpl = quic::QUICEchoSession;

  static constexpr size_t cm_max_open_sessions_soft_default = 1000;
  static constexpr size_t cm_max_open_sessions_hard_default = 1010;
  static const ccf::Endorsement cm_endorsement_default = {
    ccf::Authority::SERVICE};

  // Single owner of libuv sockets and ccf::Session objects for RPC traffic.
  //
  // Threading model:
  //   * The `sockets` map is only ever touched on the libuv loop thread
  //     (listen/connect/accept/on_read/write/close). It therefore needs no
  //     lock.
  //   * The `sessions`/`listening_interfaces`/`certs` maps are touched both on
  //     the loop thread (accept/close) and on session worker threads
  //     (reply_async/find_session). They are guarded by `lock`.
  //   * Sessions run their work on OrderedTasks worker threads and call back
  //     into write_outbound()/close_socket() from those threads. Those methods
  //     only enqueue onto the LoopExecutor, which is thread-safe, and the real
  //     socket operation runs later on the loop thread.
  class RPCConnectionManager
    : public std::enable_shared_from_this<RPCConnectionManager>,
      public ccf::SessionWriter,
      public ccf::SocketSetHost,
      public ccf::AbstractRPCResponder,
      public ::http::ErrorReporter
  {
  public:
    using ConnID = ::tcp::ConnID;

  private:
    struct ListenInterface
    {
      size_t open_sessions = 0;
      size_t peak_sessions = 0;
      size_t max_open_sessions_soft = 0;
      size_t max_open_sessions_hard = 0;
      ccf::Endorsement endorsement{};
      http::ParserConfiguration http_configuration;
      ccf::SessionMetrics::Errors errors{};
      ccf::ApplicationProtocol app_protocol;
    };

    std::shared_ptr<RPCMap> rpc_map;
    std::shared_ptr<asynchost::LoopExecutorImpl> loop_executor;

    std::shared_ptr<CustomProtocolSubsystem> custom_protocol_subsystem =
      nullptr;
    std::shared_ptr<CommitCallbackSubsystem> commit_callbacks_subsystem =
      nullptr;

    // Loop-thread-only socket ownership, split by transport.
    RPCSocketSet<asynchost::TCP> tcp_sockets;
    RPCSocketSet<asynchost::UDP> udp_sockets;

    ccf::pal::Mutex lock;
    std::map<ListenInterfaceID, ListenInterface> listening_interfaces;
    std::unordered_map<ListenInterfaceID, std::shared_ptr<::tls::Cert>> certs;
    std::unordered_map<
      ConnID,
      std::pair<ListenInterfaceID, std::shared_ptr<ccf::Session>>>
      sessions;
    size_t sessions_peak = 0;

    // Positive IDs: sockets accepted/listened on the host side.
    std::atomic<ConnID> next_server_id = 1;
    // Negative IDs: outbound client sessions created locally (was create_client
    // inside the enclave). Kept in a separate range to preserve the historical
    // convention relied upon elsewhere (e.g. forwarding).
    std::atomic<ConnID> next_client_id = -1;

    // ----- session construction ---------------------------------------------

    std::shared_ptr<ccf::Session> make_server_session(
      const std::string& app_protocol,
      ConnID id,
      const ListenInterfaceID& listen_interface_id,
      std::unique_ptr<tls::Context>&& ctx,
      const http::ParserConfiguration& parser_configuration)
    {
      // NOTE: post-swap, these session constructors take `*this` (a
      // ccf::SessionWriter&) where they previously took a
      // ringbuffer::AbstractWriterFactory&.
      if (app_protocol == "HTTP2")
      {
        return std::make_shared<::http::HTTP2ServerSession>(
          rpc_map,
          id,
          listen_interface_id,
          *this,
          std::move(ctx),
          parser_configuration,
          shared_from_this());
      }
      if (app_protocol == "HTTP1")
      {
        return std::make_shared<::http::HTTPServerSession>(
          rpc_map,
          id,
          listen_interface_id,
          *this,
          std::move(ctx),
          parser_configuration,
          shared_from_this(),
          commit_callbacks_subsystem);
      }
      if (custom_protocol_subsystem)
      {
        return custom_protocol_subsystem->create_session(
          app_protocol, id, std::move(ctx));
      }

      throw std::runtime_error(fmt::format(
        "unknown protocol '{}' and custom protocol subsystem missing",
        app_protocol));
    }

    std::shared_ptr<ccf::Session> make_capped_session(
      const ListenInterface& li,
      ConnID id,
      const ListenInterfaceID& listen_interface_id)
    {
      // NOTE: post-swap, these session constructors take `*this` (a
      // ccf::SessionWriter&) where they previously took a
      // ringbuffer::AbstractWriterFactory&.
      auto ctx = std::make_unique<::tls::Server>(certs[listen_interface_id]);
      if (li.app_protocol == "HTTP2")
      {
        return std::make_shared<NoMoreSessionsImpl<::http::HTTP2ServerSession>>(
          rpc_map,
          id,
          listen_interface_id,
          *this,
          std::move(ctx),
          li.http_configuration,
          shared_from_this());
      }
      return std::make_shared<NoMoreSessionsImpl<::http::HTTPServerSession>>(
        rpc_map,
        id,
        listen_interface_id,
        *this,
        std::move(ctx),
        li.http_configuration,
        shared_from_this(),
        commit_callbacks_subsystem);
    }

    ListenInterface& get_interface_from_interface_id(
      const ListenInterfaceID& id)
    {
      auto it = listening_interfaces.find(id);
      if (it != listening_interfaces.end())
      {
        return it->second;
      }
      throw std::logic_error(
        fmt::format("No RPC interface for interface ID {}", id));
    }

    ConnID get_next_client_id()
    {
      std::lock_guard<ccf::pal::Mutex> guard(lock);
      auto id = next_client_id--;
      const auto initial = id;

      if (next_client_id > 0)
      {
        next_client_id = -1;
      }

      while (sessions.find(id) != sessions.end())
      {
        id--;
        if (id > 0)
        {
          id = -1;
        }
        if (id == initial)
        {
          throw std::runtime_error("Exhausted all IDs for client sessions");
        }
      }
      return id;
    }

    // ----- outbound (loop thread, invoked via LoopExecutor) -----------------

    void write_on_loop(ConnID id, std::vector<uint8_t> data, sockaddr addr)
    {
      if (
        tcp_sockets.write(id, data, addr) || udp_sockets.write(id, data, addr))
      {
        return;
      }
      LOG_DEBUG_FMT(
        "Dropping {} outbound bytes for unknown socket {}", data.size(), id);
    }

    void close_on_loop(ConnID id)
    {
      tcp_sockets.stop(id);
      tcp_sockets.close(id);
      udp_sockets.stop(id);
      udp_sockets.close(id);
      remove_session(id);
    }

  public:
    RPCConnectionManager(
      std::shared_ptr<RPCMap> rpc_map_,
      std::shared_ptr<asynchost::LoopExecutorImpl> loop_executor_) :
      rpc_map(std::move(rpc_map_)),
      loop_executor(std::move(loop_executor_)),
      tcp_sockets(*this),
      udp_sockets(*this)
    {}

    void set_custom_protocol_subsystem(
      std::shared_ptr<CustomProtocolSubsystem> cpss)
    {
      custom_protocol_subsystem = std::move(cpss);
    }

    void set_commit_callbacks_subsystem(
      std::shared_ptr<CommitCallbackSubsystem> fcss)
    {
      commit_callbacks_subsystem = std::move(fcss);
    }

    // ----- SocketSetHost (loop thread) --------------------------------------

    ConnID get_next_server_id() override
    {
      return next_server_id++;
    }

    void on_socket_start(
      ConnID id, const ListenInterfaceID& interface_id, bool udp) override
    {
      accept(id, interface_id, udp);
    }

    void on_socket_inbound(
      ConnID id, const uint8_t* data, size_t len, sockaddr addr) override
    {
      auto session = find_session_for_inbound(id);
      if (session == nullptr)
      {
        LOG_DEBUG_FMT("Ignoring inbound for unknown session {}", id);
        return;
      }
      // Post-swap: handle_incoming_data takes raw bytes (no tcp_inbound /
      // udp_inbound frame) plus the source address. `addr` is meaningful for
      // datagram transports and ignored by stream sessions.
      session->handle_incoming_data({data, len}, addr);
    }

    void on_socket_gone(ConnID id) override
    {
      remove_session(id);
      // Defer the socket erase so we are not destroying the behaviour that is
      // currently executing this callback.
      loop_executor->enqueue([self = shared_from_this(), id]() {
        self->tcp_sockets.close(id);
        self->udp_sockets.close(id);
      });
    }

    // ----- SessionWriter (called from session worker threads) ---------------

    void write_outbound(
      ConnID id, std::span<const uint8_t> data, sockaddr addr = {}) override
    {
      std::vector<uint8_t> copy(data.begin(), data.end());
      loop_executor->enqueue(
        [self = shared_from_this(),
         id,
         copy = std::move(copy),
         addr]() mutable {
          self->write_on_loop(id, std::move(copy), addr);
        });
    }

    void close_socket(ConnID id) override
    {
      loop_executor->enqueue(
        [self = shared_from_this(), id]() { self->close_on_loop(id); });
    }

    // ----- AbstractRPCResponder ---------------------------------------------

    bool reply_async(
      ConnID id, bool terminate_after_send, std::vector<uint8_t>&& data)
      override
    {
      auto session = find_session(id);
      if (session == nullptr)
      {
        LOG_DEBUG_FMT("Refusing to reply to unknown session {}", id);
        return false;
      }

      LOG_DEBUG_FMT("Replying to session {}", id);
      session->send_data(std::move(data));

      if (terminate_after_send)
      {
        session->close_session();
      }
      return true;
    }

    // ----- ErrorReporter ----------------------------------------------------

    void report_parsing_error(const ListenInterfaceID& id) override
    {
      std::lock_guard<ccf::pal::Mutex> guard(lock);
      get_interface_from_interface_id(id).errors.parsing++;
    }

    void report_request_payload_too_large_error(
      const ListenInterfaceID& id) override
    {
      std::lock_guard<ccf::pal::Mutex> guard(lock);
      get_interface_from_interface_id(id).errors.request_payload_too_large++;
    }

    void report_request_header_too_large_error(
      const ListenInterfaceID& id) override
    {
      std::lock_guard<ccf::pal::Mutex> guard(lock);
      get_interface_from_interface_id(id).errors.request_header_too_large++;
    }

    // ----- interface configuration / certs ----------------------------------

    void update_listening_interface_options(
      const ccf::NodeInfoNetwork& node_info)
    {
      std::lock_guard<ccf::pal::Mutex> guard(lock);

      for (const auto& [name, interface] : node_info.rpc_interfaces)
      {
        auto& li = listening_interfaces[name];

        li.max_open_sessions_soft = interface.max_open_sessions_soft.value_or(
          cm_max_open_sessions_soft_default);
        li.max_open_sessions_hard = interface.max_open_sessions_hard.value_or(
          cm_max_open_sessions_hard_default);
        li.endorsement = interface.endorsement.value_or(cm_endorsement_default);
        li.http_configuration =
          interface.http_configuration.value_or(http::ParserConfiguration{});
        li.app_protocol = interface.app_protocol.value_or("HTTP1");

        LOG_INFO_FMT(
          "Setting max open sessions on interface \"{}\" ({}) to [{}, {}] and "
          "endorsement authority to {}",
          name,
          interface.bind_address,
          li.max_open_sessions_soft,
          li.max_open_sessions_hard,
          li.endorsement.authority);
      }
    }

    void set_node_cert(const ccf::crypto::Pem& cert_, const ccf::crypto::Pem& pk)
    {
      set_cert(ccf::Authority::NODE, cert_, pk);
    }

    void set_network_cert(
      const ccf::crypto::Pem& cert_, const ccf::crypto::Pem& pk)
    {
      set_cert(ccf::Authority::SERVICE, cert_, pk);
    }

    void set_cert(
      ccf::Authority authority,
      const ccf::crypto::Pem& cert_,
      const ccf::crypto::Pem& pk)
    {
      // Caller authentication is done by each frontend by looking up the
      // caller's certificate in the relevant store table; verification is not
      // required here.
      auto cert = std::make_shared<::tls::Cert>(
        nullptr, cert_, pk, std::nullopt, /*auth_required ==*/false);

      std::lock_guard<ccf::pal::Mutex> guard(lock);
      for (auto& [listen_interface_id, interface] : listening_interfaces)
      {
        if (interface.endorsement.authority == authority)
        {
          certs.insert_or_assign(listen_interface_id, cert);
        }
      }
    }

    ccf::SessionMetrics get_session_metrics()
    {
      ccf::SessionMetrics sm;
      std::lock_guard<ccf::pal::Mutex> guard(lock);

      sm.active = sessions.size();
      sm.peak = sessions_peak;
      for (const auto& [name, interface] : listening_interfaces)
      {
        sm.interfaces[name] = {
          interface.open_sessions,
          interface.peak_sessions,
          interface.max_open_sessions_soft,
          interface.max_open_sessions_hard,
          interface.errors};
      }
      return sm;
    }

    ccf::ApplicationProtocol get_app_protocol_main_interface() const
    {
      if (listening_interfaces.empty())
      {
        throw std::logic_error("No listening interface for this node");
      }
      return listening_interfaces.begin()->second.app_protocol;
    }

    // ----- listen / connect (loop thread) -----------------------------------

    bool listen(
      const std::string& host,
      const std::string& port,
      const ListenInterfaceID& name,
      bool udp = false)
    {
      const auto id = next_server_id++;
      if (udp)
      {
        return udp_sockets.listen(id, host, port, name);
      }
      return tcp_sockets.listen(id, host, port, name);
    }

    // ----- session lifecycle ------------------------------------------------

    std::shared_ptr<ccf::Session> find_session(ConnID id)
    {
      std::lock_guard<ccf::pal::Mutex> guard(lock);
      auto search = sessions.find(id);
      if (search == sessions.end())
      {
        return nullptr;
      }
      return search->second.second;
    }

    // Create a session for a newly started connection, applying per-interface
    // session caps. Runs on the loop thread (from on_socket_start).
    void accept(
      ConnID id, const ListenInterfaceID& listen_interface_id, bool udp)
    {
      std::lock_guard<ccf::pal::Mutex> guard(lock);

      if (sessions.find(id) != sessions.end())
      {
        throw std::logic_error(
          fmt::format("Duplicate conn ID received: {}", id));
      }

      auto it = listening_interfaces.find(listen_interface_id);
      if (it == listening_interfaces.end())
      {
        throw std::logic_error(fmt::format(
          "Can't accept RPC session {} from unknown interface {}",
          id,
          listen_interface_id));
      }
      auto& li = it->second;

      if (udp)
      {
        accept_udp(id, listen_interface_id, li);
        return;
      }

      const bool needs_cert = li.endorsement.authority != Authority::UNSECURED;
      if (needs_cert && certs.find(listen_interface_id) == certs.end())
      {
        LOG_DEBUG_FMT(
          "Refusing TLS session {} - interface {} has no certificate yet",
          id,
          listen_interface_id);
        close_socket(id);
        return;
      }

      if (li.open_sessions >= li.max_open_sessions_hard)
      {
        LOG_INFO_FMT(
          "Refusing session {} - {} sessions on interface {}, hard limit {}",
          id,
          li.open_sessions,
          listen_interface_id,
          li.max_open_sessions_hard);
        close_socket(id);
        return;
      }

      std::shared_ptr<ccf::Session> session;
      if (li.open_sessions >= li.max_open_sessions_soft)
      {
        LOG_INFO_FMT(
          "Soft-refusing session {} (503) - {} sessions on interface {}, soft "
          "limit {}",
          id,
          li.open_sessions,
          listen_interface_id,
          li.max_open_sessions_soft);
        session = make_capped_session(li, id, listen_interface_id);
      }
      else
      {
        LOG_DEBUG_FMT(
          "Accepting session {} on interface \"{}\"", id, listen_interface_id);

        std::unique_ptr<tls::Context> ctx;
        if (li.endorsement.authority == Authority::UNSECURED)
        {
          ctx = std::make_unique<nontls::PlaintextServer>();
        }
        else
        {
          ctx = std::make_unique<::tls::Server>(
            certs[listen_interface_id], li.app_protocol == "HTTP2");
        }

        session = make_server_session(
          li.app_protocol,
          id,
          listen_interface_id,
          std::move(ctx),
          li.http_configuration);
      }

      sessions.emplace(
        id, std::make_pair(listen_interface_id, std::move(session)));
      li.open_sessions++;
      li.peak_sessions = std::max(li.peak_sessions, li.open_sessions);
      sessions_peak = std::max(sessions_peak, sessions.size());
    }

    void remove_session(ConnID id)
    {
      std::lock_guard<ccf::pal::Mutex> guard(lock);
      LOG_DEBUG_FMT("Closing session {}", id);
      const auto search = sessions.find(id);
      if (search != sessions.end())
      {
        auto it = listening_interfaces.find(search->second.first);
        if (it != listening_interfaces.end())
        {
          it->second.open_sessions--;
        }
        sessions.erase(search);
      }
    }

    std::shared_ptr<ClientSession> create_client(
      const std::shared_ptr<::tls::Cert>& cert,
      const std::string& app_protocol = "HTTP1")
    {
      auto id = get_next_client_id();
      auto ctx = std::make_unique<::tls::Client>(cert);

      LOG_DEBUG_FMT("Creating client session {}", id);

      std::shared_ptr<ClientSession> session;
      if (app_protocol == "HTTP2")
      {
        session = std::make_shared<::http::HTTP2ClientSession>(
          id, *this, std::move(ctx));
      }
      else if (app_protocol == "HTTP1")
      {
        session = std::make_shared<::http::HTTPClientSession>(
          id, *this, std::move(ctx));
      }
      else
      {
        throw std::runtime_error("unsupported client application protocol");
      }

      {
        std::lock_guard<ccf::pal::Mutex> guard(lock);
        sessions.emplace(id, std::make_pair("", session));
        sessions_peak = std::max(sessions_peak, sessions.size());
      }
      return session;
    }

    // Open the outbound socket for a client session created via create_client.
    // Marshalled onto the loop thread.
    void connect(ConnID id, const std::string& host, const std::string& port)
    {
      loop_executor->enqueue([self = shared_from_this(), id, host, port]() {
        if (!self->tcp_sockets.connect(id, host, port))
        {
          self->on_socket_gone(id);
        }
      });
    }

  private:
    // ----- UDP / datagram helpers (loop thread) -----------------------------

    void accept_udp(
      ConnID id,
      const ListenInterfaceID& listen_interface_id,
      ListenInterface& li)
    {
      // Caller holds `lock`.
      LOG_DEBUG_FMT("New UDP endpoint {}", id);

      std::shared_ptr<ccf::Session> session;
      if (li.app_protocol == "QUIC")
      {
        session = std::make_shared<QUICSessionImpl>(
          rpc_map, id, listen_interface_id, *this);
      }
      else if (custom_protocol_subsystem)
      {
        // Custom protocol session is created lazily on the first inbound
        // datagram (the creation function may not be registered yet). Store a
        // nullptr placeholder so the interface mapping and caps are tracked.
        session = nullptr;
      }
      else
      {
        throw std::runtime_error(
          "unknown UDP protocol and custom protocol subsystem missing");
      }

      sessions.emplace(
        id, std::make_pair(listen_interface_id, std::move(session)));
      li.open_sessions++;
      li.peak_sessions = std::max(li.peak_sessions, li.open_sessions);
      sessions_peak = std::max(sessions_peak, sessions.size());
    }

    // Returns the session for `id`, lazily creating a custom-protocol datagram
    // session on first inbound if one was deferred at accept time. Works for
    // stream sessions too (which are always present, never deferred).
    std::shared_ptr<ccf::Session> find_session_for_inbound(ConnID id)
    {
      std::lock_guard<ccf::pal::Mutex> guard(lock);

      auto search = sessions.find(id);
      if (search == sessions.end())
      {
        return nullptr;
      }

      if (search->second.second != nullptr || !custom_protocol_subsystem)
      {
        return search->second.second;
      }

      // Deferred custom-protocol datagram session: create it now.
      const auto& interface_id = search->second.first;
      auto iit = listening_interfaces.find(interface_id);
      if (iit == listening_interfaces.end())
      {
        LOG_DEBUG_FMT(
          "Cannot create custom protocol session for {}: unknown interface {}",
          id,
          interface_id);
        return nullptr;
      }

      try
      {
        search->second.second = custom_protocol_subsystem->create_session(
          iit->second.app_protocol, id, nullptr);
      }
      catch (const std::exception& ex)
      {
        LOG_DEBUG_FMT(
          "Failure to create custom protocol session {}: {}", id, ex.what());
        return nullptr;
      }

      if (search->second.second == nullptr)
      {
        LOG_DEBUG_FMT("Failure to create custom protocol session {}", id);
      }
      return search->second.second;
    }
  };
}
