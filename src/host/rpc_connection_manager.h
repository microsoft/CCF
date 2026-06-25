// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

// Host-side, OpenSSL-native RPC connection manager.
//
// Replaces the SGX-era split of RPCSessions (enclave) + RPCConnectionsImpl
// (host) bridged over a ringbuffer. It owns one OpenSSL transport per listening
// interface (TLS terminated in the connection, see host/tls/openssl_server.h),
// creates the protocol session for each connection, applies per-interface
// session caps and certificates, and exposes outbound client creation. It
// implements ccf::AbstractRPCSessions so the node (NodeState/frontends) reaches
// it without depending on the transport backend.
//
// Cert-deferred listening: interfaces bind at startup even before their
// certificate exists (a joining node receives the service cert later). A TLS
// interface with no cert yet refuses connections until set_cert() supplies one;
// UNSECURED interfaces listen in plaintext.

#include "ccf/crypto/pem.h"
#include "ccf/service/node_info_network.h"
#include "ds/internal_logger.h"
#include "enclave/abstract_rpc_sessions.h"
#include "enclave/no_more_sessions.h"
#include "enclave/rpc_map.h"
#include "host/datagram_server.h"
#include "host/tls/openssl_session_manager.h"
#include "http/error_reporter.h"
#include "http/http2_session.h"
#include "http/http_session.h"
#include "node/session_metrics.h"
#include "tls/cert.h"

#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace ccf
{
  static constexpr size_t ocm_max_open_sessions_soft_default = 1000;
  static constexpr size_t ocm_max_open_sessions_hard_default = 1010;
  static const ccf::Endorsement ocm_endorsement_default = {
    ccf::Authority::SERVICE};

  class RPCConnectionManager
    : public std::enable_shared_from_this<RPCConnectionManager>,
      public ccf::AbstractRPCSessions,
      public ::http::ErrorReporter
  {
  private:
    struct ListenInterface
    {
      std::string name;
      size_t max_open_sessions_soft = ocm_max_open_sessions_soft_default;
      size_t max_open_sessions_hard = ocm_max_open_sessions_hard_default;
      ccf::Endorsement endorsement = ocm_endorsement_default;
      http::ParserConfiguration http_configuration;
      ccf::ApplicationProtocol app_protocol = "HTTP1";

      std::atomic<size_t> open_sessions{0};
      std::atomic<size_t> peak_sessions{0};
      std::atomic<size_t> err_parsing{0};
      std::atomic<size_t> err_payload_too_large{0};
      std::atomic<size_t> err_header_too_large{0};

      // The transport for this interface (created on listen()).
      std::unique_ptr<asynchost::OpenSSLSessionManager> bridge;
    };

    std::shared_ptr<RPCMap> rpc_map;
    std::shared_ptr<CustomProtocolSubsystem> custom_protocol_subsystem;
    std::shared_ptr<CommitCallbackSubsystem> commit_callbacks_subsystem;

    std::mutex interfaces_mutex;
    std::map<std::string, std::unique_ptr<ListenInterface>> interfaces;
    // Plaintext UDP echo servers, keyed by interface name. The pre-cutover UDP
    // "QUIC" interface was a plaintext echo stub; this preserves that until
    // OpenSSL-native QUIC is available (see host/datagram_server.h).
    std::map<std::string, std::unique_ptr<asynchost::DatagramServer>>
      udp_servers;
    // cert/key PEM per endorsement authority (for cert-deferred listening).
    std::map<ccf::Authority, std::pair<std::string, std::string>> certs;

    // Global connection-id source shared by all interface transports, so the
    // session registry / reply routing have a single id space.
    std::atomic<uint64_t> shared_conn_id{1};
    // Outbound client sessions use the negative range, matching the historical
    // convention relied upon by forwarding.
    std::atomic<int64_t> next_client_id{-1};

    std::shared_ptr<::http::ErrorReporter> error_reporter()
    {
      return shared_from_this();
    }

    // Build the protocol session for a connection on `li`, applying caps.
    // Returns nullptr to refuse (hard cap). Runs on the interface's loop thread.
    std::shared_ptr<ccf::Session> make_session(
      ListenInterface* li,
      ::tcp::ConnID conn_id,
      ccf::SessionWriter& writer,
      std::vector<uint8_t> peer_cert)
    {
      const size_t open = li->open_sessions.load();
      if (open >= li->max_open_sessions_hard)
      {
        LOG_INFO_FMT(
          "Refusing session {} on interface {} - {} open, hard limit {}",
          conn_id,
          li->name,
          open,
          li->max_open_sessions_hard);
        return nullptr;
      }

      const size_t now_open = ++li->open_sessions;
      size_t prev_peak = li->peak_sessions.load();
      while (now_open > prev_peak &&
             !li->peak_sessions.compare_exchange_weak(prev_peak, now_open))
      {
      }

      if (open >= li->max_open_sessions_soft)
      {
        LOG_INFO_FMT(
          "Soft-refusing session {} (503) on interface {} - {} open, soft "
          "limit {}",
          conn_id,
          li->name,
          open,
          li->max_open_sessions_soft);
        return make_capped_session(li, conn_id, writer, std::move(peer_cert));
      }

      return make_server_session(li, conn_id, writer, std::move(peer_cert));
    }

    std::shared_ptr<ccf::Session> make_server_session(
      ListenInterface* li,
      ::tcp::ConnID conn_id,
      ccf::SessionWriter& writer,
      std::vector<uint8_t> peer_cert)
    {
      if (li->app_protocol == "HTTP2")
      {
        return std::make_shared<::http::HTTP2ServerSession>(
          rpc_map,
          conn_id,
          li->name,
          writer,
          std::move(peer_cert),
          li->http_configuration,
          error_reporter());
      }
      if (li->app_protocol == "HTTP1")
      {
        return std::make_shared<::http::HTTPServerSession>(
          rpc_map,
          conn_id,
          li->name,
          writer,
          std::move(peer_cert),
          li->http_configuration,
          error_reporter(),
          commit_callbacks_subsystem);
      }
      throw std::runtime_error(fmt::format(
        "Unsupported application protocol '{}' (custom protocols are not "
        "supported on the OpenSSL RPC path)",
        li->app_protocol));
    }

    std::shared_ptr<ccf::Session> make_capped_session(
      ListenInterface* li,
      ::tcp::ConnID conn_id,
      ccf::SessionWriter& writer,
      std::vector<uint8_t> peer_cert)
    {
      if (li->app_protocol == "HTTP2")
      {
        return std::make_shared<NoMoreSessionsImpl<::http::HTTP2ServerSession>>(
          rpc_map,
          conn_id,
          li->name,
          writer,
          std::move(peer_cert),
          li->http_configuration,
          error_reporter());
      }
      return std::make_shared<NoMoreSessionsImpl<::http::HTTPServerSession>>(
        rpc_map,
        conn_id,
        li->name,
        writer,
        std::move(peer_cert),
        li->http_configuration,
        error_reporter(),
        commit_callbacks_subsystem);
    }

    asynchost::OpenSSLSessionManager* primary_bridge()
    {
      for (auto& [name, li] : interfaces)
      {
        if (li->bridge != nullptr)
        {
          return li->bridge.get();
        }
      }
      return nullptr;
    }

  public:
    explicit RPCConnectionManager(std::shared_ptr<RPCMap> rpc_map_) :
      rpc_map(std::move(rpc_map_))
    {}

    ~RPCConnectionManager() override
    {
      stop();
    }

    void stop()
    {
      std::lock_guard<std::mutex> guard(interfaces_mutex);
      for (auto& [name, li] : interfaces)
      {
        if (li->bridge != nullptr)
        {
          li->bridge->stop();
        }
      }
      for (auto& [name, server] : udp_servers)
      {
        server->stop();
      }
    }

    // Bind and start listening on `name` (which must have been configured via
    // update_listening_interface_options). Returns the bound port (supports
    // ephemeral port 0), or 0 on failure.
    uint16_t listen(
      const std::string& name,
      const std::string& host,
      const std::string& port)
    {
      std::lock_guard<std::mutex> guard(interfaces_mutex);
      auto it = interfaces.find(name);
      if (it == interfaces.end())
      {
        throw std::logic_error(fmt::format(
          "Cannot listen on unconfigured interface '{}'", name));
      }
      auto* li = it->second.get();

      const bool plaintext =
        li->endorsement.authority == ccf::Authority::UNSECURED;
      const std::string alpn =
        plaintext ? "" : (li->app_protocol == "HTTP2" ? "h2" : "http/1.1");

      std::string cert_pem;
      std::string key_pem;
      if (!plaintext)
      {
        auto c = certs.find(li->endorsement.authority);
        if (c != certs.end())
        {
          cert_pem = c->second.first;
          key_pem = c->second.second;
        }
      }

      auto factory =
        [this, li](
          ::tcp::ConnID cid,
          ccf::SessionWriter& w,
          std::vector<uint8_t> pc) {
          return make_session(li, cid, w, std::move(pc));
        };
      auto on_closed = [li](::tcp::ConnID) {
        size_t expected = li->open_sessions.load();
        while (expected > 0 &&
               !li->open_sessions.compare_exchange_weak(expected, expected - 1))
        {
        }
      };

      const uint16_t port_num = static_cast<uint16_t>(std::stoi(port));
      li->bridge = std::make_unique<asynchost::OpenSSLSessionManager>(
        cert_pem,
        key_pem,
        host,
        port_num,
        factory,
        alpn,
        plaintext,
        false,
        &shared_conn_id,
        on_closed);
      li->bridge->start();
      return li->bridge->port();
    }

    // Bind and start a plaintext UDP echo server for `name`. This preserves the
    // pre-cutover UDP echo stub (interfaces with protocol "udp").
    //
    // === QUIC EXTENSION POINT ===
    // A real QUIC interface would, instead of echoing, hand each datagram to an
    // OpenSSL QUIC listener (OpenSSL >= 3.5). The DatagramServer below is the
    // shared substrate for that (see host/datagram_server.h).
    uint16_t listen_udp(
      const std::string& name,
      const std::string& host,
      const std::string& port)
    {
      std::lock_guard<std::mutex> guard(interfaces_mutex);
      auto server = std::make_unique<asynchost::DatagramServer>(
        host,
        static_cast<uint16_t>(std::stoi(port)),
        [](
          const uint8_t* data,
          size_t len,
          const asynchost::DatagramServer::Reply& reply) {
          // Echo the datagram back to its sender.
          reply(data, len);
        });
      server->start();
      const uint16_t bound = server->port();
      udp_servers.emplace(name, std::move(server));
      return bound;
    }

    // ----- AbstractRPCSessions / AbstractRPCResponder -----------------------

    std::shared_ptr<ClientSession> create_client(
      const std::shared_ptr<::tls::Cert>& cert,
      const std::string& app_protocol = "HTTP1") override
    {
      const int64_t id = next_client_id.fetch_sub(1);

      asynchost::OpenSSLSessionManager* bridge = nullptr;
      {
        std::lock_guard<std::mutex> guard(interfaces_mutex);
        bridge = primary_bridge();
      }
      if (bridge == nullptr)
      {
        throw std::runtime_error(
          "Cannot create outbound client: no listening interface");
      }

      // The tls::Cert carries the peer CA (for server verification) and,
      // optionally, this node's client certificate to present. It configures
      // the outbound SSL when the connection is opened.
      auto connect_cb =
        [bridge, cert](int64_t cid, const std::string& h, const std::string& s) {
          bridge->connect(
            static_cast<::tcp::ConnID>(cid), h, s, [cert](SSL* ssl, SSL_CTX* ctx) {
              if (cert != nullptr)
              {
                cert->use(ssl, ctx);
              }
            });
        };

      std::shared_ptr<ClientSession> session;
      std::shared_ptr<ccf::Session> as_session;
      if (app_protocol == "HTTP2")
      {
        auto s = std::make_shared<::http::HTTP2ClientSession>(
          id, *bridge, connect_cb);
        session = s;
        as_session = s;
      }
      else
      {
        auto s = std::make_shared<::http::HTTPClientSession>(
          id, *bridge, connect_cb);
        session = s;
        as_session = s;
      }

      bridge->register_session(static_cast<::tcp::ConnID>(id), as_session);
      return session;
    }

    bool reply_async(
      int64_t id, bool terminate_after_reply, std::vector<uint8_t>&& data)
      override
    {
      std::vector<asynchost::OpenSSLSessionManager*> bridges;
      {
        std::lock_guard<std::mutex> guard(interfaces_mutex);
        for (auto& [name, li] : interfaces)
        {
          if (li->bridge != nullptr)
          {
            bridges.push_back(li->bridge.get());
          }
        }
      }

      for (auto* bridge : bridges)
      {
        auto session = bridge->get_session(id);
        if (session != nullptr)
        {
          session->send_data(std::move(data));
          if (terminate_after_reply)
          {
            session->close_session();
          }
          return true;
        }
      }
      LOG_DEBUG_FMT("Refusing to reply to unknown session {}", id);
      return false;
    }

    ccf::ApplicationProtocol get_app_protocol_main_interface() const override
    {
      // NB: const_cast to lock - the mutex is logically mutable here.
      auto& self = const_cast<RPCConnectionManager&>(*this);
      std::lock_guard<std::mutex> guard(self.interfaces_mutex);
      if (self.interfaces.empty())
      {
        throw std::logic_error("No listening interface for this node");
      }
      return self.interfaces.begin()->second->app_protocol;
    }

    ccf::SessionMetrics get_session_metrics() override
    {
      ccf::SessionMetrics sm;
      std::lock_guard<std::mutex> guard(interfaces_mutex);
      size_t active = 0;
      size_t peak = 0;
      for (auto& [name, li] : interfaces)
      {
        ccf::SessionMetrics::Errors errs;
        errs.parsing = li->err_parsing.load();
        errs.request_payload_too_large = li->err_payload_too_large.load();
        errs.request_header_too_large = li->err_header_too_large.load();

        sm.interfaces[name] = {
          li->open_sessions.load(),
          li->peak_sessions.load(),
          li->max_open_sessions_soft,
          li->max_open_sessions_hard,
          errs};

        active += li->open_sessions.load();
        peak += li->peak_sessions.load();
      }
      sm.active = active;
      sm.peak = peak;
      return sm;
    }

    void set_node_cert(
      const ccf::crypto::Pem& cert, const ccf::crypto::Pem& pk) override
    {
      set_cert(ccf::Authority::NODE, cert, pk);
    }

    void set_network_cert(
      const ccf::crypto::Pem& cert, const ccf::crypto::Pem& pk) override
    {
      set_cert(ccf::Authority::SERVICE, cert, pk);
    }

    void set_cert(
      ccf::Authority authority,
      const ccf::crypto::Pem& cert,
      const ccf::crypto::Pem& pk)
    {
      std::lock_guard<std::mutex> guard(interfaces_mutex);
      certs[authority] = {cert.str(), pk.str()};
      for (auto& [name, li] : interfaces)
      {
        if (li->endorsement.authority == authority && li->bridge != nullptr)
        {
          li->bridge->set_server_cert(cert.str(), pk.str());
        }
      }
    }

    void update_listening_interface_options(
      const ccf::NodeInfoNetwork& node_info) override
    {
      std::lock_guard<std::mutex> guard(interfaces_mutex);
      for (const auto& [name, interface] : node_info.rpc_interfaces)
      {
        // UDP interfaces use the datagram echo path (listen_udp), not the TCP
        // session machinery.
        if (interface.protocol == "udp")
        {
          continue;
        }
        auto it = interfaces.find(name);
        if (it == interfaces.end())
        {
          it = interfaces.emplace(name, std::make_unique<ListenInterface>())
                 .first;
          it->second->name = name;
        }
        auto* li = it->second.get();

        li->max_open_sessions_soft = interface.max_open_sessions_soft.value_or(
          ocm_max_open_sessions_soft_default);
        li->max_open_sessions_hard = interface.max_open_sessions_hard.value_or(
          ocm_max_open_sessions_hard_default);
        li->endorsement =
          interface.endorsement.value_or(ocm_endorsement_default);
        li->http_configuration =
          interface.http_configuration.value_or(http::ParserConfiguration{});
        li->app_protocol = interface.app_protocol.value_or("HTTP1");

        LOG_INFO_FMT(
          "Setting max open sessions on interface \"{}\" ({}) to [{}, {}] and "
          "endorsement authority to {}",
          name,
          interface.bind_address,
          li->max_open_sessions_soft,
          li->max_open_sessions_hard,
          li->endorsement.authority);
      }
    }

    void set_custom_protocol_subsystem(
      std::shared_ptr<CustomProtocolSubsystem> cpss) override
    {
      custom_protocol_subsystem = std::move(cpss);
    }

    void set_commit_callbacks_subsystem(
      std::shared_ptr<CommitCallbackSubsystem> fcss) override
    {
      commit_callbacks_subsystem = std::move(fcss);
    }

    // ----- ErrorReporter ----------------------------------------------------

    void report_parsing_error(const ccf::ListenInterfaceID& id) override
    {
      std::lock_guard<std::mutex> guard(interfaces_mutex);
      auto it = interfaces.find(id);
      if (it != interfaces.end())
      {
        it->second->err_parsing++;
      }
    }

    void report_request_payload_too_large_error(
      const ccf::ListenInterfaceID& id) override
    {
      std::lock_guard<std::mutex> guard(interfaces_mutex);
      auto it = interfaces.find(id);
      if (it != interfaces.end())
      {
        it->second->err_payload_too_large++;
      }
    }

    void report_request_header_too_large_error(
      const ccf::ListenInterfaceID& id) override
    {
      std::lock_guard<std::mutex> guard(interfaces_mutex);
      auto it = interfaces.find(id);
      if (it != interfaces.end())
      {
        it->second->err_header_too_large++;
      }
    }
  };
}
