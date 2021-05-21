// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/logger.h"
#include "ds/serialized.h"
#include "forwarder_types.h"
#include "http/http_endpoint.h"
#include "node/node_info_network.h"
#include "node/session_metrics.h"
#include "rpc_handler.h"
#include "tls/cert.h"
#include "tls/client.h"
#include "tls/context.h"
#include "tls/server.h"

#include <limits>
#include <unordered_map>

namespace enclave
{
  using ServerEndpointImpl = http::HTTPServerEndpoint;
  using ClientEndpointImpl = http::HTTPClientEndpoint;

  class RPCSessions : public AbstractRPCResponder
  {
  private:
    using ListenInterfaceID = std::string;

    struct ListenInterface
    {
      size_t open_sessions;
      size_t peak_sessions;
      size_t max_open_sessions_soft;
      size_t max_open_sessions_hard;
    };
    std::map<ListenInterfaceID, ListenInterface> listening_interfaces;

    ringbuffer::AbstractWriterFactory& writer_factory;
    ringbuffer::WriterPtr to_host = nullptr;
    std::shared_ptr<RPCMap> rpc_map;
    std::shared_ptr<tls::Cert> cert;

    SpinLock lock;
    std::unordered_map<
      tls::ConnID,
      std::pair<ListenInterfaceID, std::shared_ptr<Endpoint>>>
      sessions;
    size_t sessions_peak;

    // Negative sessions are reserved for those originating from
    // the enclave via create_client().
    std::atomic<tls::ConnID> next_client_session_id = -1;

    class NoMoreSessionsEndpointImpl : public enclave::TLSEndpoint
    {
    public:
      NoMoreSessionsEndpointImpl(
        tls::ConnID session_id,
        ringbuffer::AbstractWriterFactory& writer_factory,
        std::unique_ptr<tls::Context> ctx) :
        enclave::TLSEndpoint(session_id, writer_factory, std::move(ctx))
      {}

      void recv(const uint8_t* data, size_t size) override
      {
        recv_buffered(data, size);

        if (get_status() == Status::ready)
        {
          // Send HTTP response describing soft session limit
          auto http_response = http::Response(HTTP_STATUS_SERVICE_UNAVAILABLE);
          http_response.set_header(
            http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
          const auto response_body = fmt::format(
            "Service is currently busy and unable to serve new connections");
          http_response.set_body(
            (const uint8_t*)response_body.data(), response_body.size());
          send(http_response.build_response());

          // Close connection
          close();
        }
      }

      void send(std::vector<uint8_t>&& data) override
      {
        send_raw(std::move(data));
      }
    };

    tls::ConnID get_next_id()
    {
      auto id = next_client_session_id--;

      if (next_client_session_id > 0)
        next_client_session_id = -1;

      while (sessions.find(id) != sessions.end())
      {
        id--;

        if (id > 0)
          id = -1;
      }

      return id;
    }

  public:
    RPCSessions(
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::shared_ptr<RPCMap> rpc_map_) :
      writer_factory(writer_factory),
      rpc_map(rpc_map_)
    {
      to_host = writer_factory.create_writer_to_outside();
    }

    void update_listening_interface_caps(const ccf::NodeInfoNetwork& node_info)
    {
      std::lock_guard<SpinLock> guard(lock);

      for (const auto& interface : node_info.rpc_interfaces)
      {
        const auto interface_name = fmt::format(
          "{}:{}", interface.rpc_address.hostname, interface.rpc_address.port);
        LOG_INFO_FMT(
          "Setting max open sessions on interface {} to [{}, {}]",
          interface_name,
          interface.max_open_sessions_soft,
          interface.max_open_sessions_hard);
        auto& li = listening_interfaces[interface_name];
        li.max_open_sessions_soft = interface.max_open_sessions_soft;
        li.max_open_sessions_hard = interface.max_open_sessions_hard;
      }
    }

    ccf::SessionMetrics get_session_metrics()
    {
      ccf::SessionMetrics sm;
      std::lock_guard<SpinLock> guard(lock);

      sm.active = sessions.size();
      sm.peak = sessions_peak;

      for (const auto& [name, interface] : listening_interfaces)
      {
        sm.interfaces[name] = {interface.open_sessions,
                               interface.peak_sessions,
                               interface.max_open_sessions_soft,
                               interface.max_open_sessions_hard};
      }

      return sm;
    }

    void set_cert(const crypto::Pem& cert_, const crypto::Pem& pk)
    {
      std::lock_guard<SpinLock> guard(lock);

      // Caller authentication is done by each frontend by looking up
      // the caller's certificate in the relevant store table. The caller
      // certificate does not have to be signed by a known CA (nullptr,
      // tls::auth_optional).
      cert = std::make_shared<tls::Cert>(
        nullptr, cert_, pk, nullb, tls::auth_optional);
    }

    void accept(tls::ConnID id, const ListenInterfaceID& listen_interface_id)
    {
      std::lock_guard<SpinLock> guard(lock);

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
        per_listen_interface.open_sessions >=
        per_listen_interface.max_open_sessions_hard)
      {
        LOG_INFO_FMT(
          "Refusing session {} inside the enclave - already have {} sessions "
          "from interface {} and limit is {}",
          id,
          listen_interface_id,
          per_listen_interface.open_sessions,
          per_listen_interface.max_open_sessions_hard);

        RINGBUFFER_WRITE_MESSAGE(
          tls::tls_stop, to_host, id, std::string("Session refused"));
      }
      else if (
        per_listen_interface.open_sessions >=
        per_listen_interface.max_open_sessions_soft)
      {
        LOG_INFO_FMT(
          "Soft refusing session {} inside the enclave - already have {} "
          "sessions from interface {} and limit is {}",
          id,
          listen_interface_id,
          per_listen_interface.open_sessions,
          per_listen_interface.max_open_sessions_soft);

        auto ctx = std::make_unique<tls::Server>(cert);
        auto capped_session = std::make_shared<NoMoreSessionsEndpointImpl>(
          id, writer_factory, std::move(ctx));
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
          "Accepting a session {} inside the enclave from interface {}",
          listen_interface_id,
          id);
        auto ctx = std::make_unique<tls::Server>(cert);

        auto session = std::make_shared<ServerEndpointImpl>(
          rpc_map, id, writer_factory, std::move(ctx));
        sessions.insert(std::make_pair(
          id, std::make_pair(listen_interface_id, std::move(session))));
        per_listen_interface.open_sessions++;
        per_listen_interface.peak_sessions = std::max(
          per_listen_interface.peak_sessions,
          per_listen_interface.open_sessions);
      }

      sessions_peak = std::max(sessions_peak, sessions.size());
    }

    bool reply_async(tls::ConnID id, std::vector<uint8_t>&& data) override
    {
      std::lock_guard<SpinLock> guard(lock);

      auto search = sessions.find(id);
      if (search == sessions.end())
      {
        LOG_DEBUG_FMT("Refusing to reply to unknown session {}", id);
        return false;
      }

      LOG_DEBUG_FMT("Replying to session {}", id);

      search->second.second->send(std::move(data));
      return true;
    }

    void remove_session(tls::ConnID id)
    {
      std::lock_guard<SpinLock> guard(lock);
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
    }

    std::shared_ptr<ClientEndpoint> create_client(
      std::shared_ptr<tls::Cert> cert)
    {
      std::lock_guard<SpinLock> guard(lock);
      auto ctx = std::make_unique<tls::Client>(cert);
      auto id = get_next_id();

      LOG_INFO_FMT("Creating a new client session inside the enclave: {}", id);

      auto session = std::make_shared<ClientEndpointImpl>(
        id, writer_factory, std::move(ctx));

      // There are no limits on outbound client sessions (we do not check any
      // session caps here). We expect this type of session to be rare and want
      // it to succeed even when we are busy.
      sessions.insert(std::make_pair(id, std::make_pair("", session)));

      sessions_peak = std::max(sessions_peak, sessions.size());

      return session;
    }

    void register_message_handlers(
      messaging::Dispatcher<ringbuffer::Message>& disp)
    {
      DISPATCHER_SET_MESSAGE_HANDLER(
        disp, tls::tls_start, [this](const uint8_t* data, size_t size) {
          auto [new_tls_id, listen_interface_name] =
            ringbuffer::read_message<tls::tls_start>(data, size);
          accept(new_tls_id, listen_interface_name);
        });

      DISPATCHER_SET_MESSAGE_HANDLER(
        disp, tls::tls_inbound, [this](const uint8_t* data, size_t size) {
          auto [id, body] =
            ringbuffer::read_message<tls::tls_inbound>(data, size);

          auto search = sessions.find(id);
          if (search == sessions.end())
          {
            LOG_DEBUG_FMT(
              "Ignoring tls_inbound for unknown or refused session: {}", id);
            return;
          }

          search->second.second->recv(body.data, body.size);
        });

      DISPATCHER_SET_MESSAGE_HANDLER(
        disp, tls::tls_close, [this](const uint8_t* data, size_t size) {
          auto [id] = ringbuffer::read_message<tls::tls_close>(data, size);
          remove_session(id);
        });
    }
  };
}
