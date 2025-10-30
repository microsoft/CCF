// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/http_responder.h"
#include "ccf/pal/locking.h"
#include "ccf/service/node_info_network.h"
#include "ds/internal_logger.h"
#include "ds/serialized.h"
#include "enclave/session.h"
#include "forwarder_types.h"
#include "http/http2_session.h"
#include "http/http_session.h"
#include "node/session_metrics.h"
// NB: This should be HTTP3 including QUIC, but this is
// ok for now, as we only have an echo service for now
#include "http/responder_lookup.h"
#include "node/rpc/custom_protocol_subsystem.h"
#include "quic/quic_session.h"
#include "rpc_handler.h"
#include "tls/cert.h"
#include "tls/client.h"
#include "tls/context.h"
#include "tls/plaintext_server.h"
#include "tls/server.h"
#include "udp/msg_types.h"

#include <limits>
#include <map>
#include <stdexcept>
#include <unordered_map>

namespace ccf
{
  using QUICSessionImpl = quic::QUICEchoSession;

  static constexpr size_t max_open_sessions_soft_default = 1000;
  static constexpr size_t max_open_sessions_hard_default = 1010;
  static const ccf::Endorsement endorsement_default = {ccf::Authority::SERVICE};

  class RPCSessions : public std::enable_shared_from_this<RPCSessions>,
                      public AbstractRPCResponder,
                      public ::http::ErrorReporter,
                      public ::http::ResponderLookup
  {
  private:
    struct ListenInterface
    {
      size_t open_sessions;
      size_t peak_sessions;
      size_t max_open_sessions_soft;
      size_t max_open_sessions_hard;
      ccf::Endorsement endorsement;
      http::ParserConfiguration http_configuration;
      ccf::SessionMetrics::Errors errors;
      ccf::ApplicationProtocol app_protocol;
    };
    std::map<ListenInterfaceID, ListenInterface> listening_interfaces;

    ringbuffer::AbstractWriterFactory& writer_factory;
    ringbuffer::WriterPtr to_host = nullptr;
    std::shared_ptr<RPCMap> rpc_map;
    std::unordered_map<ListenInterfaceID, std::shared_ptr<::tls::Cert>> certs;
    std::shared_ptr<CustomProtocolSubsystem> custom_protocol_subsystem;

    ccf::pal::Mutex lock;
    std::unordered_map<
      ccf::tls::ConnID,
      std::pair<ListenInterfaceID, std::shared_ptr<ccf::Session>>>
      sessions;
    size_t sessions_peak = 0;

    // Negative sessions are reserved for those originating from
    // the enclave via create_client().
    std::atomic<ccf::tls::ConnID> next_client_session_id = -1;

    template <typename Base>
    class NoMoreSessionsImpl : public Base
    {
    public:
      template <typename... Ts>
      NoMoreSessionsImpl(Ts&&... ts) : Base(std::forward<Ts>(ts)...)
      {}

      void handle_incoming_data_thread(std::vector<uint8_t>&& data) override
      {
        Base::tls_io->recv_buffered(data.data(), data.size());

        if (Base::tls_io->get_status() == ccf::SessionStatus::ready)
        {
          // Send response describing soft session limit
          Base::send_odata_error_response(ccf::ErrorDetails{
            HTTP_STATUS_SERVICE_UNAVAILABLE,
            ccf::errors::SessionCapExhausted,
            "Service is currently busy and unable to serve new connections"});

          // Close connection
          Base::tls_io->close();
        }
      }
    };

    ccf::tls::ConnID get_next_client_id()
    {
      auto id = next_client_session_id--;
      const auto initial = id;

      if (next_client_session_id > 0)
        next_client_session_id = -1;

      while (sessions.find(id) != sessions.end())
      {
        id--;

        if (id > 0)
          id = -1;

        if (id == initial)
        {
          throw std::runtime_error(
            "Exhausted all IDs for enclave client sessions");
        }
      }

      return id;
    }

    ListenInterface& get_interface_from_interface_id(
      const ccf::ListenInterfaceID& id)
    {
      auto it = listening_interfaces.find(id);
      if (it != listening_interfaces.end())
      {
        return it->second;
      }

      throw std::logic_error(
        fmt::format("No RPC interface for interface ID {}", id));
    }

    std::shared_ptr<ccf::Session> make_server_session(
      const std::string& app_protocol,
      ccf::tls::ConnID id,
      const ListenInterfaceID& listen_interface_id,
      std::unique_ptr<tls::Context>&& ctx,
      const http::ParserConfiguration& parser_configuration)
    {
      if (app_protocol == "HTTP2")
      {
        return std::make_shared<::http::HTTP2ServerSession>(
          rpc_map,
          id,
          listen_interface_id,
          writer_factory,
          std::move(ctx),
          parser_configuration,
          shared_from_this(),
          *this);
      }
      else if (app_protocol == "HTTP1")
      {
        return std::make_shared<::http::HTTPServerSession>(
          rpc_map,
          id,
          listen_interface_id,
          writer_factory,
          std::move(ctx),
          parser_configuration,
          shared_from_this());
      }
      else if (custom_protocol_subsystem)
      {
        return custom_protocol_subsystem->create_session(
          app_protocol, id, std::move(ctx));
      }
      else
      {
        throw std::runtime_error(fmt::format(
          "unknown protocol '{}' and custom protocol subsystem missing",
          app_protocol));
      }
    }

  public:
    RPCSessions(
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::shared_ptr<RPCMap> rpc_map_) :
      writer_factory(writer_factory),
      rpc_map(rpc_map_),
      custom_protocol_subsystem(nullptr)
    {
      to_host = writer_factory.create_writer_to_outside();
    }

    void set_custom_protocol_subsystem(
      std::shared_ptr<CustomProtocolSubsystem> cpss)
    {
      custom_protocol_subsystem = cpss;
    }

    void report_parsing_error(const ccf::ListenInterfaceID& id) override
    {
      std::lock_guard<ccf::pal::Mutex> guard(lock);
      get_interface_from_interface_id(id).errors.parsing++;
    }

    void report_request_payload_too_large_error(
      const ccf::ListenInterfaceID& id) override
    {
      std::lock_guard<ccf::pal::Mutex> guard(lock);
      get_interface_from_interface_id(id).errors.request_payload_too_large++;
    }

    void report_request_header_too_large_error(
      const ccf::ListenInterfaceID& id) override
    {
      std::lock_guard<ccf::pal::Mutex> guard(lock);
      get_interface_from_interface_id(id).errors.request_header_too_large++;
    }

    void update_listening_interface_options(
      const ccf::NodeInfoNetwork& node_info)
    {
      std::lock_guard<ccf::pal::Mutex> guard(lock);

      for (const auto& [name, interface] : node_info.rpc_interfaces)
      {
        auto& li = listening_interfaces[name];

        li.max_open_sessions_soft = interface.max_open_sessions_soft.value_or(
          max_open_sessions_soft_default);

        li.max_open_sessions_hard = interface.max_open_sessions_hard.value_or(
          max_open_sessions_hard_default);

        li.endorsement = interface.endorsement.value_or(endorsement_default);

        li.http_configuration =
          interface.http_configuration.value_or(http::ParserConfiguration{});

        li.app_protocol = interface.app_protocol.value_or("HTTP1");

        LOG_INFO_FMT(
          "Setting max open sessions on interface \"{}\" ({}) to [{}, "
          "{}] and endorsement authority to {}",
          name,
          interface.bind_address,
          li.max_open_sessions_soft,
          li.max_open_sessions_hard,
          li.endorsement.authority);
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
      // Note: this is a temporary function to conveniently find out which
      // protocol to use when creating client endpoints (e.g. for join
      // protocol). This can be removed once the HTTP and HTTP/2 endpoints have
      // been merged.
      if (listening_interfaces.empty())
      {
        throw std::logic_error("No listening interface for this node");
      }

      return listening_interfaces.begin()->second.app_protocol;
    }

    void set_node_cert(
      const ccf::crypto::Pem& cert_, const ccf::crypto::Pem& pk)
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
      // Caller authentication is done by each frontend by looking up
      // the caller's certificate in the relevant store table. The caller
      // certificate does not have to be signed by a known CA (nullptr) and
      // verification is not required here.
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

    void accept(
      ccf::tls::ConnID id,
      const ListenInterfaceID& listen_interface_id,
      bool udp = false)
    {
      std::lock_guard<ccf::pal::Mutex> guard(lock);

      if (sessions.find(id) != sessions.end())
      {
        throw std::logic_error(
          fmt::format("Duplicate conn ID received inside enclave: {}", id));
      }

      auto it = listening_interfaces.find(listen_interface_id);
      if (it == listening_interfaces.end())
      {
        throw std::logic_error(fmt::format(
          "Can't accept new RPC session {} - comes from unknown listening "
          "interface {}",
          id,
          listen_interface_id));
      }

      auto& per_listen_interface = it->second;

      if (
        per_listen_interface.endorsement.authority != Authority::UNSECURED &&
        certs.find(listen_interface_id) == certs.end())
      {
        LOG_DEBUG_FMT(
          "Refusing TLS session {} inside the enclave - interface {} "
          "has no TLS certificate yet",
          id,
          listen_interface_id);

        RINGBUFFER_WRITE_MESSAGE(
          ::tcp::tcp_stop, to_host, id, std::string("Session refused"));
      }
      else if (
        per_listen_interface.open_sessions >=
        per_listen_interface.max_open_sessions_hard)
      {
        LOG_INFO_FMT(
          "Refusing TLS session {} inside the enclave - already have {} "
          "sessions from interface {} and limit is {}",
          id,
          per_listen_interface.open_sessions,
          listen_interface_id,
          per_listen_interface.max_open_sessions_hard);

        RINGBUFFER_WRITE_MESSAGE(
          ::tcp::tcp_stop, to_host, id, std::string("Session refused"));
      }
      else if (
        per_listen_interface.open_sessions >=
        per_listen_interface.max_open_sessions_soft)
      {
        LOG_INFO_FMT(
          "Soft refusing session {} (returning 503) inside the enclave - "
          "already have {} sessions from interface {} and limit is {}",
          id,
          per_listen_interface.open_sessions,
          listen_interface_id,
          per_listen_interface.max_open_sessions_soft);

        auto ctx = std::make_unique<::tls::Server>(certs[listen_interface_id]);
        std::shared_ptr<Session> capped_session;
        if (per_listen_interface.app_protocol == "HTTP2")
        {
          capped_session =
            std::make_shared<NoMoreSessionsImpl<::http::HTTP2ServerSession>>(
              rpc_map,
              id,
              listen_interface_id,
              writer_factory,
              std::move(ctx),
              per_listen_interface.http_configuration,
              shared_from_this(),
              *this);
        }
        else
        {
          capped_session =
            std::make_shared<NoMoreSessionsImpl<::http::HTTPServerSession>>(
              rpc_map,
              id,
              listen_interface_id,
              writer_factory,
              std::move(ctx),
              per_listen_interface.http_configuration,
              shared_from_this());
        }
        sessions.insert(std::make_pair(
          id, std::make_pair(listen_interface_id, std::move(capped_session))));
        per_listen_interface.open_sessions++;
        per_listen_interface.peak_sessions = std::max(
          per_listen_interface.peak_sessions,
          per_listen_interface.open_sessions);
      }
      else
      {
        LOG_DEBUG_FMT(
          "Accepting a session {} inside the enclave from interface \"{}\"",
          id,
          listen_interface_id);

        if (udp)
        {
          LOG_DEBUG_FMT("New UDP endpoint at {}", id);
          if (per_listen_interface.app_protocol == "QUIC")
          {
            auto session = std::make_shared<QUICSessionImpl>(
              rpc_map, id, listen_interface_id, writer_factory);
            sessions.insert(std::make_pair(
              id, std::make_pair(listen_interface_id, std::move(session))));
          }
          else if (custom_protocol_subsystem)
          {
            // We know it's a custom protocol, but the session creation function
            // hasn't been registered yet, so we keep a nullptr until the first
            // udp::udp_inbound message.
            sessions.insert(
              std::make_pair(id, std::make_pair(listen_interface_id, nullptr)));
          }
          else
          {
            throw std::runtime_error(
              "unknown UDP protocol and custom protocol subsystem missing");
          }
          per_listen_interface.open_sessions++;
          per_listen_interface.peak_sessions = std::max(
            per_listen_interface.peak_sessions,
            per_listen_interface.open_sessions);
        }
        else
        {
          std::unique_ptr<tls::Context> ctx;
          if (
            per_listen_interface.endorsement.authority == Authority::UNSECURED)
          {
            ctx = std::make_unique<nontls::PlaintextServer>();
          }
          else
          {
            ctx = std::make_unique<::tls::Server>(
              certs[listen_interface_id],
              per_listen_interface.app_protocol == "HTTP2");
          }

          auto session = make_server_session(
            per_listen_interface.app_protocol,
            id,
            listen_interface_id,
            std::move(ctx),
            per_listen_interface.http_configuration);

          sessions.insert(std::make_pair(
            id, std::make_pair(listen_interface_id, std::move(session))));
          per_listen_interface.open_sessions++;
          per_listen_interface.peak_sessions = std::max(
            per_listen_interface.peak_sessions,
            per_listen_interface.open_sessions);
        }
      }

      sessions_peak = std::max(sessions_peak, sessions.size());
    }

    std::shared_ptr<Session> find_session(ccf::tls::ConnID id)
    {
      std::lock_guard<ccf::pal::Mutex> guard(lock);

      auto search = sessions.find(id);
      if (search == sessions.end())
      {
        return nullptr;
      }

      return search->second.second;
    }

    bool reply_async(
      ccf::tls::ConnID id,
      bool terminate_after_send,
      std::vector<uint8_t>&& data) override
    {
      auto session = find_session(id);
      if (session == nullptr)
      {
        LOG_DEBUG_FMT("Refusing to reply to unknown session {}", id);
        return false;
      }

      LOG_DEBUG_FMT("Replying to session {}", id);

      session->send_data(data);

      if (terminate_after_send)
      {
        session->close_session();
      }

      return true;
    }

    void remove_session(ccf::tls::ConnID id)
    {
      std::lock_guard<ccf::pal::Mutex> guard(lock);
      LOG_DEBUG_FMT("Closing a session inside the enclave: {}", id);
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
      else
      {
        // Enclave doesn't know this ID, but host is still talking about it.
        // Continue with the normal closure flow
        RINGBUFFER_WRITE_MESSAGE(::tcp::tcp_closed, to_host, id);
      }
    }

    std::shared_ptr<ClientSession> create_client(
      const std::shared_ptr<::tls::Cert>& cert,
      const std::string& app_protocol = "HTTP1")
    {
      std::lock_guard<ccf::pal::Mutex> guard(lock);
      auto ctx = std::make_unique<::tls::Client>(cert);
      auto id = get_next_client_id();

      LOG_DEBUG_FMT("Creating a new client session inside the enclave: {}", id);

      // There are no limits on outbound client sessions (we do not check any
      // session caps here). We expect this type of session to be rare and
      // want it to succeed even when we are busy.
      if (app_protocol == "HTTP2")
      {
        auto session = std::make_shared<::http::HTTP2ClientSession>(
          id, writer_factory, std::move(ctx));
        sessions.insert(std::make_pair(id, std::make_pair("", session)));
        sessions_peak = std::max(sessions_peak, sessions.size());
        return session;
      }
      else if (app_protocol == "HTTP1")
      {
        auto session = std::make_shared<::http::HTTPClientSession>(
          id, writer_factory, std::move(ctx));
        sessions.insert(std::make_pair(id, std::make_pair("", session)));
        sessions_peak = std::max(sessions_peak, sessions.size());
        return session;
      }
      else
      {
        throw std::runtime_error("unsupported client application protocol");
      }
    }

    std::shared_ptr<ClientSession> create_unencrypted_client()
    {
      std::lock_guard<ccf::pal::Mutex> guard(lock);
      auto id = get_next_client_id();
      auto session = std::make_shared<::http::UnencryptedHTTPClientSession>(
        id, writer_factory);
      sessions.insert(std::make_pair(id, std::make_pair("", session)));
      sessions_peak = std::max(sessions_peak, sessions.size());
      return session;
    }

    void register_message_handlers(
      messaging::Dispatcher<ringbuffer::Message>& disp)
    {
      DISPATCHER_SET_MESSAGE_HANDLER(
        disp, ::tcp::tcp_start, [this](const uint8_t* data, size_t size) {
          auto [new_tls_id, listen_interface_name] =
            ringbuffer::read_message<::tcp::tcp_start>(data, size);
          accept(new_tls_id, listen_interface_name);
        });

      DISPATCHER_SET_MESSAGE_HANDLER(
        disp, ::tcp::tcp_inbound, [this](const uint8_t* data, size_t size) {
          auto id = serialized::peek<ccf::tls::ConnID>(data, size);

          auto session = find_session(id);
          if (session == nullptr)
          {
            LOG_DEBUG_FMT(
              "Ignoring tls_inbound for unknown or refused session: {}", id);
            return;
          }

          session->handle_incoming_data({data, size});
        });

      DISPATCHER_SET_MESSAGE_HANDLER(
        disp, ::tcp::tcp_close, [this](const uint8_t* data, size_t size) {
          auto [id] = ringbuffer::read_message<::tcp::tcp_close>(data, size);
          remove_session(id);
        });

      DISPATCHER_SET_MESSAGE_HANDLER(
        disp, udp::udp_start, [this](const uint8_t* data, size_t size) {
          auto [new_id, listen_interface_name] =
            ringbuffer::read_message<udp::udp_start>(data, size);
          accept(new_id, listen_interface_name, true);
        });

      DISPATCHER_SET_MESSAGE_HANDLER(
        disp, udp::udp_inbound, [this](const uint8_t* data, size_t size) {
          auto id = serialized::peek<int64_t>(data, size);

          std::shared_ptr<Session> session;
          {
            std::lock_guard<ccf::pal::Mutex> guard(lock);

            auto search = sessions.find(id);
            if (search == sessions.end())
            {
              LOG_DEBUG_FMT(
                "Ignoring udp::udp_inbound for unknown or refused session: {}",
                id);
              return;
            }
            else if (!search->second.second && custom_protocol_subsystem)
            {
              LOG_DEBUG_FMT("Creating custom UDP session {}", id);

              try
              {
                const auto& conn_id = search->first;
                const auto& interface_id = search->second.first;

                auto iit = listening_interfaces.find(interface_id);
                if (iit == listening_interfaces.end())
                {
                  LOG_DEBUG_FMT(
                    "Failure to create custom protocol session because of "
                    "unknown interface '{}', ignoring udp::udp_inbound for "
                    "session: "
                    "{}",
                    interface_id,
                    id);
                }

                const auto& interface = iit->second;

                search->second.second =
                  custom_protocol_subsystem->create_session(
                    interface.app_protocol, conn_id, nullptr);

                if (!search->second.second)
                {
                  LOG_DEBUG_FMT(
                    "Failure to create custom protocol session, ignoring "
                    "udp::udp_inbound for session: {}",
                    id);
                  return;
                }
              }
              catch (const std::exception& ex)
              {
                LOG_DEBUG_FMT(
                  "Failure to create custom protocol session: {}", ex.what());
                return;
              }
            }

            session = search->second.second;
          }

          session->handle_incoming_data({data, size});
        });
    }
  };
}
