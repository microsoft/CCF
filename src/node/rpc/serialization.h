// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "ds/json.h"
#include "node/calltypes.h"

namespace ccf
{
  ADD_JSON_TRANSLATORS(StartNetwork::In, tx0, id)
  ADD_JSON_TRANSLATORS(StartNetwork::Out, network_cert, tx0_sig)
  ADD_JSON_TRANSLATORS(JoinNetwork::In, network_cert, hostname, service)
  ADD_JSON_TRANSLATORS(JoinNetwork::Out, id)
  ADD_JSON_TRANSLATORS(NetworkSecrets::Secret, cert, priv_key, master)
  ADD_JSON_TRANSLATORS(JoinNetworkNodeToNode::In, raw_fresh_key)
  ADD_JSON_TRANSLATORS(JoinNetworkNodeToNode::Out, id, network_secrets, version)
  ADD_JSON_TRANSLATORS(GetCommit::Out, term, commit)
  ADD_JSON_TRANSLATORS(GetMetrics::Out, metrics)
}
