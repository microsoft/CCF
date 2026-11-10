// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/pem.h"
#include "consensus/aft/cft_types.h"
#include "http/http_builder.h"
#include "node/rpc/rpc_map.h"

#include <functional>

namespace ccf
{
  class NodeClient
  {
  protected:
    std::shared_ptr<ccf::RPCMap> rpc_map;
    const std::function<ccf::crypto::Pem()> get_node_certificate;

  public:
    NodeClient(
      std::shared_ptr<ccf::RPCMap> rpc_map_,
      std::function<ccf::crypto::Pem()> get_node_certificate_) :
      rpc_map(std::move(rpc_map_)),
      get_node_certificate(std::move(get_node_certificate_))
    {}

    virtual ~NodeClient() = default;

    virtual bool make_request(::http::Request& request) = 0;
  };
}
