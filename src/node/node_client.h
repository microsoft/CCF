// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/aft/raft_types.h"
#include "crypto/pem.h"
#include "enclave/rpc_sessions.h"

using namespace ccf;

namespace aft
{
  class NodeClient
  {
  protected:
    std::shared_ptr<enclave::RPCMap> rpc_map;
    crypto::KeyPairPtr node_sign_kp;
    const crypto::Pem& node_cert;

  public:
    NodeClient(
      std::shared_ptr<enclave::RPCMap> rpc_map_,
      crypto::KeyPairPtr node_sign_kp_,
      const crypto::Pem& node_cert_) :
      rpc_map(rpc_map_),
      node_sign_kp(node_sign_kp_),
      node_cert(node_cert_)
    {}

    virtual void schedule_submit_orc(
      const NodeId& from, kv::ReconfigurationId rid) = 0;
  };
}
