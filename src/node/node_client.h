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
    crypto::KeyPairPtr node_sign_kp;
    const crypto::Pem& self_signed_node_cert;
    const std::optional<crypto::Pem>& endorsed_node_cert = std::nullopt;

  public:
    NodeClient(
      std::shared_ptr<ccf::RPCMap> rpc_map_,
      crypto::KeyPairPtr node_sign_kp_,
      const crypto::Pem& self_signed_node_cert_,
      const std::optional<crypto::Pem>& endorsed_node_cert_) :
      rpc_map(rpc_map_),
      node_sign_kp(node_sign_kp_),
      self_signed_node_cert(self_signed_node_cert_),
      endorsed_node_cert(endorsed_node_cert_)
    {}

    virtual ~NodeClient() {}

    virtual void make_request_async(http::Request& request,
      ccf::RpcHandler::DoneCB&& done_cb) = 0;
  };
}
