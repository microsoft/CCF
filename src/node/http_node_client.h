// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "node/node_client.h"
#include "node/rpc/http_rpc_context.h"

#include <chrono>

namespace ccf
{
  class HTTPNodeClient : public NodeClient
  {
  public:
    HTTPNodeClient(
      std::shared_ptr<ccf::RPCMap> rpc_map,
      ccf::crypto::ECKeyPairPtr node_sign_kp,
      std::function<ccf::crypto::Pem()> get_node_certificate_) :
      NodeClient(
        std::move(rpc_map),
        std::move(node_sign_kp),
        std::move(get_node_certificate_))
    {}

    ~HTTPNodeClient() override = default;

    bool make_request(::http::Request& request) override
    {
      const auto node_cert = get_node_certificate();

      std::vector<uint8_t> packed = request.build_request();

      auto node_session = std::make_shared<ccf::SessionContext>(
        ccf::InvalidSessionId, node_cert.raw());
      auto ctx = ccf::make_rpc_context(node_session, packed);

      std::shared_ptr<ccf::RpcHandler> search =
        ::http::fetch_rpc_handler(ctx, rpc_map);

      search->process(ctx);

      auto rs = ctx->get_response_status();

      if (rs != HTTP_STATUS_OK)
      {
        auto ser_res = ctx->serialise_response();
        std::string str(
          reinterpret_cast<char*>(ser_res.data()), ser_res.size());
        LOG_DEBUG_FMT("Request failed: {}", str);
      }

      return rs == HTTP_STATUS_OK;
    }
  };
}
