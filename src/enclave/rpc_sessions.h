// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/logger.h"
#include "ds/serialized.h"
#include "forwarder_types.h"
#include "http/http_endpoint.h"
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
    std::shared_ptr<RPCMap> rpc_map;
    std::shared_ptr<tls::Cert> cert;

    SpinLock lock;
    std::unordered_map<size_t, std::shared_ptr<Endpoint>> sessions;

    // Upper half of sessions range is reserved for those originating from
    // the enclave via create_client().
    std::atomic<size_t> next_client_session_id =
      std::numeric_limits<size_t>::max() / 2;

    ringbuffer::AbstractWriterFactory& writer_factory;

  public:
    RPCSessions(
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::shared_ptr<RPCMap> rpc_map_) :
      writer_factory(writer_factory),
      rpc_map(rpc_map_)
    {}

    void set_cert(CBuffer cert_, const tls::Pem& pk)
    {
      std::lock_guard<SpinLock> guard(lock);

      // Caller authentication is done by each frontend by looking up
      // the caller's certificate in the relevant store table. The caller
      // certificate does not have to be signed by a known CA (nullptr,
      // tls::auth_optional).
      cert = std::make_shared<tls::Cert>(
        nullptr, cert_, pk, nullb, tls::auth_optional);
    }

    void accept(size_t id)
    {
      std::lock_guard<SpinLock> guard(lock);

      if (sessions.find(id) != sessions.end())
        throw std::logic_error(
          "Duplicate conn ID received inside enclave: " + std::to_string(id));

      LOG_DEBUG_FMT("Accepting a session inside the enclave: {}", id);
      auto ctx = std::make_unique<tls::Server>(cert);

      auto session = std::make_shared<ServerEndpointImpl>(
        rpc_map, id, writer_factory, std::move(ctx));
      sessions.insert(std::make_pair(id, std::move(session)));
    }

    bool reply_async(size_t id, const std::vector<uint8_t>& data) override
    {
      std::lock_guard<SpinLock> guard(lock);

      auto search = sessions.find(id);
      if (search == sessions.end())
      {
        LOG_FAIL_FMT("Replying to unknown session {}", id);
        return false;
      }

      LOG_DEBUG_FMT("Replying to session {}", id);

      search->second->send(data);
      return true;
    }

    void remove_session(size_t id)
    {
      std::lock_guard<SpinLock> guard(lock);
      LOG_DEBUG_FMT("Closing a session inside the enclave: {}", id);
      sessions.erase(id);
    }

    std::shared_ptr<ClientEndpoint> create_client(
      std::shared_ptr<tls::Cert> cert)
    {
      std::lock_guard<SpinLock> guard(lock);
      auto ctx = std::make_unique<tls::Client>(cert);
      auto id = ++next_client_session_id;

      LOG_DEBUG_FMT("Creating a new client session inside the enclave: {}", id);

      auto session = std::make_shared<ClientEndpointImpl>(
        id, writer_factory, std::move(ctx));
      sessions.insert(std::make_pair(id, session));
      return session;
    }

    void register_message_handlers(
      messaging::Dispatcher<ringbuffer::Message>& disp)
    {
      DISPATCHER_SET_MESSAGE_HANDLER(
        disp, tls::tls_start, [this](const uint8_t* data, size_t size) {
          auto [id] = ringbuffer::read_message<tls::tls_start>(data, size);
          accept(id);
        });

      DISPATCHER_SET_MESSAGE_HANDLER(
        disp, tls::tls_inbound, [this](const uint8_t* data, size_t size) {
          auto [id, body] =
            ringbuffer::read_message<tls::tls_inbound>(data, size);

          auto search = sessions.find(id);
          if (search == sessions.end())
          {
            throw std::logic_error(
              "tls_inbound for unknown session: " + std::to_string(id));
          }

          search->second->recv(body.data, body.size);
        });

      DISPATCHER_SET_MESSAGE_HANDLER(
        disp, tls::tls_close, [this](const uint8_t* data, size_t size) {
          auto [id] = ringbuffer::read_message<tls::tls_close>(data, size);
          remove_session(id);
        });
    }
  };
}
