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
    size_t max_open_sessions_soft = 1000;
    size_t max_open_sessions_hard = 1100;

    ringbuffer::AbstractWriterFactory& writer_factory;
    ringbuffer::WriterPtr to_host = nullptr;
    std::shared_ptr<RPCMap> rpc_map;
    std::shared_ptr<tls::Cert> cert;

    std::mutex lock;
    std::unordered_map<size_t, std::shared_ptr<Endpoint>> sessions;
    size_t sessions_peak;

    // Upper half of sessions range is reserved for those originating from
    // the enclave via create_client().
    std::atomic<size_t> next_client_session_id =
      std::numeric_limits<size_t>::max() / 2;

    class NoMoreSessionsEndpointImpl : public enclave::TLSEndpoint
    {
    public:
      NoMoreSessionsEndpointImpl(
        size_t session_id,
        ringbuffer::AbstractWriterFactory& writer_factory,
        std::unique_ptr<tls::Context> ctx) :
        enclave::TLSEndpoint(session_id, writer_factory, std::move(ctx))
      {}

      static void recv_cb(std::unique_ptr<threading::Tmsg<SendRecvMsg>> msg)
      {
        reinterpret_cast<NoMoreSessionsEndpointImpl*>(msg->data.self.get())
          ->recv_(msg->data.data.data(), msg->data.data.size());
      }

      void recv(const uint8_t* data, size_t size) override
      {
        auto msg = std::make_unique<threading::Tmsg<SendRecvMsg>>(&recv_cb);
        msg->data.self = this->shared_from_this();
        msg->data.data.assign(data, data + size);

        threading::ThreadMessaging::thread_messaging.add_task(
          execution_thread, std::move(msg));
      }

      void recv_(const uint8_t* data, size_t size)
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

  public:
    RPCSessions(
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::shared_ptr<RPCMap> rpc_map_) :
      writer_factory(writer_factory),
      rpc_map(rpc_map_)
    {
      to_host = writer_factory.create_writer_to_outside();
    }

    void set_max_open_sessions(size_t soft_cap, size_t hard_cap)
    {
      std::lock_guard<std::mutex> guard(lock);
      max_open_sessions_soft = soft_cap;
      max_open_sessions_hard = hard_cap;

      LOG_INFO_FMT("Setting max open sessions to [{}, {}]", soft_cap, hard_cap);
    }

    void get_stats(
      size_t& current, size_t& peak, size_t& soft_cap, size_t& hard_cap)
    {
      std::lock_guard<std::mutex> guard(lock);
      current = sessions.size();
      peak = sessions_peak;
      soft_cap = max_open_sessions_soft;
      hard_cap = max_open_sessions_hard;
    }

    void set_cert(const crypto::Pem& cert_, const crypto::Pem& pk)
    {
      std::lock_guard<std::mutex> guard(lock);

      // Caller authentication is done by each frontend by looking up
      // the caller's certificate in the relevant store table. The caller
      // certificate does not have to be signed by a known CA (nullptr,
      // tls::auth_optional).
      cert = std::make_shared<tls::Cert>(
        nullptr, cert_, pk, nullb, tls::auth_optional);
    }

    void accept(size_t id)
    {
      std::lock_guard<std::mutex> guard(lock);

      if (sessions.find(id) != sessions.end())
        throw std::logic_error(
          "Duplicate conn ID received inside enclave: " + std::to_string(id));

      if (sessions.size() >= max_open_sessions_hard)
      {
        LOG_INFO_FMT(
          "Refusing a session inside the enclave - already have {} sessions "
          "and limit is {}: {}",
          sessions.size(),
          max_open_sessions_hard,
          id);

        RINGBUFFER_WRITE_MESSAGE(
          tls::tls_stop, to_host, id, std::string("Session refused"));
      }
      else if (sessions.size() >= max_open_sessions_soft)
      {
        LOG_INFO_FMT(
          "Soft refusing a session inside the enclave - already have {} "
          "sessions and limit is {}: {}",
          sessions.size(),
          max_open_sessions_soft,
          id);

        auto ctx = std::make_unique<tls::Server>(cert);
        auto capped_session = std::make_shared<NoMoreSessionsEndpointImpl>(
          id, writer_factory, std::move(ctx));
        sessions.insert(std::make_pair(id, std::move(capped_session)));
      }
      else
      {
        LOG_DEBUG_FMT("Accepting a session inside the enclave: {}", id);
        auto ctx = std::make_unique<tls::Server>(cert);

        auto session = std::make_shared<ServerEndpointImpl>(
          rpc_map, id, writer_factory, std::move(ctx));
        sessions.insert(std::make_pair(id, std::move(session)));
      }

      sessions_peak = std::max(sessions_peak, sessions.size());
    }

    bool reply_async(size_t id, std::vector<uint8_t>&& data) override
    {
      std::lock_guard<std::mutex> guard(lock);

      auto search = sessions.find(id);
      if (search == sessions.end())
      {
        LOG_DEBUG_FMT("Refusing to reply to unknown session {}", id);
        return false;
      }

      LOG_DEBUG_FMT("Replying to session {}", id);

      search->second->send(std::move(data));
      return true;
    }

    void remove_session(size_t id)
    {
      std::lock_guard<std::mutex> guard(lock);
      LOG_DEBUG_FMT("Closing a session inside the enclave: {}", id);
      sessions.erase(id);
    }

    std::shared_ptr<ClientEndpoint> create_client(
      std::shared_ptr<tls::Cert> cert)
    {
      std::lock_guard<std::mutex> guard(lock);
      auto ctx = std::make_unique<tls::Client>(cert);
      auto id = ++next_client_session_id;

      LOG_DEBUG_FMT("Creating a new client session inside the enclave: {}", id);

      auto session = std::make_shared<ClientEndpointImpl>(
        id, writer_factory, std::move(ctx));

      // We do not check the open sessions limit here, because we expect
      // this type of session to be rare and want it to succeed even when we are
      // busy.
      sessions.insert(std::make_pair(id, session));

      sessions_peak = std::max(sessions_peak, sessions.size());

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
            LOG_DEBUG_FMT(
              "Ignoring tls_inbound for unknown or refused session: {}", id);
            return;
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
