// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "ds/json.h"
#include "node/calltypes.h"
#include "node/rpc/calltypes.h"

namespace ccf
{
  DECLARE_REQUIRED_JSON_FIELDS(StartNetwork::In, tx0, id)
  DECLARE_REQUIRED_JSON_FIELDS(StartNetwork::Out, network_cert, tx0_sig)
  DECLARE_REQUIRED_JSON_FIELDS(JoinNetwork::In, network_cert, hostname, service)
  DECLARE_REQUIRED_JSON_FIELDS(NetworkSecrets::Secret, cert, priv_key, master)
  DECLARE_REQUIRED_JSON_FIELDS(JoinNetworkNodeToNode::In, raw_fresh_key)
  DECLARE_REQUIRED_JSON_FIELDS(
    JoinNetworkNodeToNode::Out, id, network_secrets, version)

  DECLARE_REQUIRED_JSON_FIELDS(GetCommit::Out, term, commit)
  DECLARE_REQUIRED_JSON_FIELDS(
    GetTxHist::Out, low, high, overflow, underflow, histogram)
}
