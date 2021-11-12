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
      std::optional<std::function<bool(bool, std::vector<uint8_t>)>>
        response_callback = std::nullopt) const override
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
      auto result = frontend->process(ctx);

      if (ctx->get_response_status() == HTTP_STATUS_OK)
      {
        if (response_callback.has_value())
        {
          if (result.has_value())
          {
            LOG_TRACE_FMT("CLIENT: have immediate result");
            response_callback.value()(true, result.value());
          }
          else
          {
            LOG_TRACE_FMT("CLIENT: submitting response check task");
            threading::retry_until(
              [endpoint, response_callback]() {
                if (endpoint->response.status == HTTP_STATUS_CONTINUE)
                {
                  LOG_TRACE_FMT("CLIENT: continue waiting for response");
                  return false;
                }
                return response_callback.value()(
                  endpoint->response.status == HTTP_STATUS_OK,
                  endpoint->response.body);
              },
              std::chrono::milliseconds(100));
          }
        }

        return true;
      }
      else
      {
        auto ser_res = ctx->serialise_response();
        std::string str((char*)ser_res.data(), ser_res.size());
        LOG_DEBUG_FMT("Request failed: {}", str);
        if (response_callback.has_value())
        {
          response_callback.value()(false, ser_res);
        }
        return false;
      }
    }
  };
}
