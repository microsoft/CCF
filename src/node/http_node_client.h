// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "enclave/rpc_map.h"
#include "enclave/rpc_sessions.h"
#include "node/node_client.h"

#include <chrono>

#include <optional>

namespace ccf
{
  class HTTPNodeClient : public NodeClient
  {
  public:
    HTTPNodeClient(
      std::shared_ptr<enclave::RPCMap> rpc_map_,
      std::shared_ptr<enclave::RPCSessions> rpc_sessions_,
      crypto::KeyPairPtr node_sign_kp_,
      const crypto::Pem& self_signed_node_cert_,
      const std::optional<crypto::Pem>& endorsed_node_cert_) :
      NodeClient(
        rpc_map_,
        rpc_sessions_,
        node_sign_kp_,
        self_signed_node_cert_,
        endorsed_node_cert_)
    {}

    virtual ~HTTPNodeClient() {}

    class InternalClientEndpoint : public enclave::Endpoint
    {
    public:
      InternalClientEndpoint()
      {
        response.status = HTTP_STATUS_CONTINUE;
      }

      virtual ~InternalClientEndpoint() {}

      virtual void recv(const uint8_t* data, size_t size)
      {
        throw std::logic_error("unexpected recv in internal client endpoint");
      }

      virtual void send(std::vector<uint8_t>&& data)
      {
        http::SimpleResponseProcessor processor;
        http::ResponseParser parser(processor);
        parser.execute(data.data(), data.size());

        if (processor.received.size() != 1)
        {
          LOG_DEBUG_FMT("unexpected HTTP response, dropping response");
          return;
        }

        response = std::move(processor.received.front());
      }

      http::SimpleResponseProcessor::Response response;
    };

    virtual bool make_request(
      http::Request& request,
      std::optional<
        std::function<bool(const http::SimpleResponseProcessor::Response&)>>
        response_callback = std::nullopt) override
    {
      LOG_DEBUG_FMT("RPC to {}", request.get_path());

      const auto& node_cert = endorsed_node_cert.has_value() ?
        endorsed_node_cert.value() :
        self_signed_node_cert;
      auto node_cert_der = crypto::cert_pem_to_der(node_cert);
      const auto key_id = crypto::Sha256Hash(node_cert_der).hex_str();
      http::sign_request(request, node_sign_kp, key_id);

      std::vector<uint8_t> packed = request.build_request();

      auto endpoint = std::make_shared<InternalClientEndpoint>();
      auto session_id = rpc_sessions->add_session(endpoint);
      auto session_ctx =
        std::make_shared<enclave::SessionContext>(session_id, node_cert.raw());
      auto ctx = enclave::make_rpc_context(session_ctx, packed);
      // ctx->execute_on_node = true;

      const auto actor_opt = http::extract_actor(*ctx);
      if (!actor_opt.has_value())
      {
        throw std::logic_error("Unable to get actor");
      }

      const auto actor = rpc_map->resolve(actor_opt.value());
      auto frontend_opt = rpc_map->find(actor);
      if (!frontend_opt.has_value())
      {
        throw std::logic_error(
          "RpcMap::find returned invalid (empty) frontend");
      }

      auto frontend = frontend_opt.value();
      frontend->process(ctx);
      
      if (response_callback) 
      {
        threading::retry_until(
          [rpc_sessions = NodeClient::rpc_sessions,
          ctx,
          response_callback,
          endpoint,
          frontend]() {
            switch (endpoint->response.status)
            {
              case HTTP_STATUS_CONTINUE:
                // Just continue to monitor
                return false;
              case HTTP_STATUS_OK:
              case HTTP_STATUS_NO_CONTENT:
                // OK, handle response
                if (response_callback)
                {
                  response_callback.value()(endpoint->response);
                }
                rpc_sessions->remove_session(ctx->session->client_session_id);
                return true;
              default:
                // Error: report and resubmit
                std::string str(
                  (char*)endpoint->response.body.data(),
                  endpoint->response.body.size());
                LOG_INFO_FMT(
                  "resubmitting failed RPC to {}{}: {}",
                  ctx->get_request_path(),
                  ctx->get_request_query(),
                  str);
                ctx->reset_response();
                ctx->set_response_status(HTTP_STATUS_CONTINUE);
                frontend->process(ctx);
            }
            return false;
          },
          std::chrono::milliseconds(100));        
      }
      else if (ctx->get_response_status() != HTTP_STATUS_OK)
      {
        auto ser_res = ctx->serialise_response();
        std::string str((char*)ser_res.data(), ser_res.size());
        LOG_DEBUG_FMT("Request failed: {}", str);      
        return false;
      }

      return true;
    }
  };
}
