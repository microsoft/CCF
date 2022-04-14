// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "node/node_client.h"

#include <chrono>

namespace ccf
{
  class HTTPNodeClient : public NodeClient
  {
  public:
    HTTPNodeClient(
      std::shared_ptr<ccf::RPCMap> rpc_map,
      crypto::KeyPairPtr node_sign_kp,
      const crypto::Pem& self_signed_node_cert_,
      const std::optional<crypto::Pem>& endorsed_node_cert_) :
      NodeClient(
        rpc_map, node_sign_kp, self_signed_node_cert_, endorsed_node_cert_)
    {}

    virtual ~HTTPNodeClient() {}

    virtual bool make_request(http::Request& request) override
    {
      const auto& node_cert = endorsed_node_cert.has_value() ?
        endorsed_node_cert.value() :
        self_signed_node_cert;
      auto node_cert_der = crypto::cert_pem_to_der(node_cert);
      const auto key_id = crypto::Sha256Hash(node_cert_der).hex_str();

      http::sign_request(request, node_sign_kp, key_id);

      std::vector<uint8_t> packed = request.build_request();

      auto node_session = std::make_shared<ccf::SessionContext>(
        ccf::InvalidSessionId, node_cert.raw());
      auto ctx = ccf::make_rpc_context(node_session, packed);
      ctx->execute_on_node = false;

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

      auto rs = ctx->get_response_status();

      if (rs != HTTP_STATUS_OK)
      {
        auto ser_res = ctx->serialise_response();
        std::string str((char*)ser_res.data(), ser_res.size());
        LOG_DEBUG_FMT("Request failed: {}", str);
      }

      return rs == HTTP_STATUS_OK;
    }
  };
}
