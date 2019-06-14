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
  DECLARE_REQUIRED_JSON_FIELDS(JoinNetwork::Out, id)

  DECLARE_JSON_ENUM(
    GetSignedIndex::State,
    {{GetSignedIndex::State::ReadingPublicLedger, "readingPublicLedger"},
     {GetSignedIndex::State::AwaitingRecovery, "awaitingRecovery"},
     {GetSignedIndex::State::ReadingPrivateLedger, "readingPrivateLedger"},
     {GetSignedIndex::State::PartOfNetwork, "partOfNetwork"},
     {GetSignedIndex::State::PartOfPublicNetwork, "partOfPublicNetwork"}})
  DECLARE_REQUIRED_JSON_FIELDS(GetSignedIndex::Out, state, signed_index)

  DECLARE_REQUIRED_JSON_FIELDS(SetRecoveryNodes::In, nodes)

  DECLARE_REQUIRED_JSON_FIELDS(GetQuotes::Quote, node_id, raw)
  DECLARE_OPTIONAL_JSON_FIELDS(GetQuotes::Quote, error, mrenclave)
  DECLARE_REQUIRED_JSON_FIELDS(GetQuotes::Out, quotes)

  DECLARE_REQUIRED_JSON_FIELDS(NetworkSecrets::Secret, cert, priv_key, master)

  DECLARE_REQUIRED_JSON_FIELDS(JoinNetworkNodeToNode::In, raw_fresh_key)
  DECLARE_REQUIRED_JSON_FIELDS(
    JoinNetworkNodeToNode::Out, id, network_secrets, version)

  DECLARE_REQUIRED_JSON_FIELDS(GetCommit::In)
  DECLARE_OPTIONAL_JSON_FIELDS(GetCommit::In, commit)
  DECLARE_REQUIRED_JSON_FIELDS(GetCommit::Out, term, commit)

  DECLARE_REQUIRED_JSON_FIELDS(
    GetMetrics::HistogramResults, low, high, overflow, underflow, buckets)
  DECLARE_REQUIRED_JSON_FIELDS(GetMetrics::Out, histogram, tx_rates)

  DECLARE_REQUIRED_JSON_FIELDS(
    GetLeaderInfo::Out, leader_id, leader_host, leader_port)

  DECLARE_REQUIRED_JSON_FIELDS(ListMethods::Out, methods)

  DECLARE_REQUIRED_JSON_FIELDS(GetSchema::In, method)
  DECLARE_REQUIRED_JSON_FIELDS(GetSchema::Out, params_schema, result_schema)
}
