// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/pem.h"
#include "consensus/aft/raft_types.h"
#include "enclave/rpc_map.h"
#include "http/http_builder.h"

namespace ccf
{
  class NodeClient
  {
  protected:
    std::shared_ptr<ccf::RPCMap> rpc_map;
    ccf::crypto::ECKeyPairPtr node_sign_kp;
    const ccf::crypto::Pem& self_signed_node_cert;
    const std::optional<ccf::crypto::Pem>& endorsed_node_cert = std::nullopt;

  public:
    NodeClient(
      std::shared_ptr<ccf::RPCMap> rpc_map_,
      ccf::crypto::ECKeyPairPtr node_sign_kp_,
      const ccf::crypto::Pem& self_signed_node_cert_,
      const std::optional<ccf::crypto::Pem>& endorsed_node_cert_) :
      rpc_map(std::move(rpc_map_)),
      node_sign_kp(std::move(node_sign_kp_)),
      self_signed_node_cert(self_signed_node_cert_),
      endorsed_node_cert(endorsed_node_cert_)
    {}

    virtual ~NodeClient() = default;

    virtual bool make_request(::http::Request& request) = 0;
  };
}
