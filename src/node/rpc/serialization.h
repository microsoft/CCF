// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "ds/json.h"
#include "node/calltypes.h"
#include "node/rpc/calltypes.h"

namespace ccf
{
  DECLARE_JSON_TYPE(StartNetwork::In)
  DECLARE_JSON_REQUIRED_FIELDS(StartNetwork::In, tx0, id)
  DECLARE_JSON_TYPE(StartNetwork::Out)
  DECLARE_JSON_REQUIRED_FIELDS(StartNetwork::Out, network_cert, tx0_sig)

  DECLARE_JSON_TYPE(JoinNetwork::In)
  DECLARE_JSON_REQUIRED_FIELDS(JoinNetwork::In, network_cert, hostname, service)
  DECLARE_JSON_TYPE(JoinNetwork::Out)
  DECLARE_JSON_REQUIRED_FIELDS(JoinNetwork::Out, id)

  DECLARE_JSON_ENUM(
    GetSignedIndex::State,
    {{GetSignedIndex::State::ReadingPublicLedger, "readingPublicLedger"},
     {GetSignedIndex::State::AwaitingRecovery, "awaitingRecovery"},
     {GetSignedIndex::State::ReadingPrivateLedger, "readingPrivateLedger"},
     {GetSignedIndex::State::PartOfNetwork, "partOfNetwork"},
     {GetSignedIndex::State::PartOfPublicNetwork, "partOfPublicNetwork"}})
  DECLARE_JSON_TYPE(GetSignedIndex::Out)
  DECLARE_JSON_REQUIRED_FIELDS(GetSignedIndex::Out, state, signed_index)

  DECLARE_JSON_TYPE(SetRecoveryNodes::In)
  DECLARE_JSON_REQUIRED_FIELDS(SetRecoveryNodes::In, nodes)

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(GetQuotes::Quote)
  DECLARE_JSON_REQUIRED_FIELDS(GetQuotes::Quote, node_id, raw)
  DECLARE_JSON_OPTIONAL_FIELDS(GetQuotes::Quote, error, mrenclave)
  DECLARE_JSON_TYPE(GetQuotes::Out)
  DECLARE_JSON_REQUIRED_FIELDS(GetQuotes::Out, quotes)

  DECLARE_JSON_TYPE(NetworkSecrets::Secret)
  DECLARE_JSON_REQUIRED_FIELDS(NetworkSecrets::Secret, cert, priv_key, master)

  DECLARE_JSON_TYPE(JoinNetworkNodeToNode::In)
  DECLARE_JSON_REQUIRED_FIELDS(JoinNetworkNodeToNode::In, raw_fresh_key)
  DECLARE_JSON_TYPE(JoinNetworkNodeToNode::Out)
  DECLARE_JSON_REQUIRED_FIELDS(
    JoinNetworkNodeToNode::Out, id, network_secrets, version)

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(GetCommit::In)
  DECLARE_JSON_REQUIRED_FIELDS(GetCommit::In)
  DECLARE_JSON_OPTIONAL_FIELDS(GetCommit::In, commit)
  DECLARE_JSON_TYPE(GetCommit::Out)
  DECLARE_JSON_REQUIRED_FIELDS(GetCommit::Out, term, commit)

  DECLARE_JSON_TYPE(GetMetrics::HistogramResults)
  DECLARE_JSON_REQUIRED_FIELDS(
    GetMetrics::HistogramResults, low, high, overflow, underflow, buckets)
  DECLARE_JSON_TYPE(GetMetrics::Out)
  DECLARE_JSON_REQUIRED_FIELDS(GetMetrics::Out, histogram, tx_rates)

  DECLARE_JSON_TYPE(GetLeaderInfo::Out)
  DECLARE_JSON_REQUIRED_FIELDS(
    GetLeaderInfo::Out, leader_id, leader_host, leader_port)

  DECLARE_JSON_TYPE(GetNetworkInfo::NodeInfo)
  DECLARE_JSON_REQUIRED_FIELDS(GetNetworkInfo::NodeInfo, node_id, host, port)
  DECLARE_JSON_TYPE(GetNetworkInfo::Out)
  DECLARE_JSON_REQUIRED_FIELDS(GetNetworkInfo::Out, nodes, leader_id)

  DECLARE_JSON_TYPE(ListMethods::Out)
  DECLARE_JSON_REQUIRED_FIELDS(ListMethods::Out, methods)

  DECLARE_JSON_TYPE(GetSchema::In)
  DECLARE_JSON_REQUIRED_FIELDS(GetSchema::In, method)
  DECLARE_JSON_TYPE(GetSchema::Out)
  DECLARE_JSON_REQUIRED_FIELDS(GetSchema::Out, params_schema, result_schema)
}
