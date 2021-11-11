// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/aft/raft_types.h"
#include "crypto/pem.h"
#include "enclave/rpc_map.h"
#include "enclave/rpc_sessions.h"

namespace ccf
{
  class NodeClient
  {
  protected:
    std::shared_ptr<enclave::RPCMap> rpc_map;
    std::shared_ptr<enclave::RPCSessions> rpc_sessions;
    crypto::KeyPairPtr node_sign_kp;
    const crypto::Pem& self_signed_node_cert;
    const std::optional<crypto::Pem>& endorsed_node_cert = std::nullopt;

  public:
    NodeClient(
      std::shared_ptr<enclave::RPCMap> rpc_map_,
      std::shared_ptr<enclave::RPCSessions> rpc_sessions_,
      crypto::KeyPairPtr node_sign_kp_,
      const crypto::Pem& self_signed_node_cert_,
      const std::optional<crypto::Pem>& endorsed_node_cert_) :
      rpc_map(rpc_map_),
      rpc_sessions(rpc_sessions_),
      node_sign_kp(node_sign_kp_),
      self_signed_node_cert(self_signed_node_cert_),
      endorsed_node_cert(endorsed_node_cert_)
    {}

    virtual ~NodeClient() {}

    virtual bool make_request(
      http::Request& request,
      std::optional<std::function<bool(bool, std::vector<uint8_t>)>>
        response_callback = std::nullopt) const = 0;
  };
}
