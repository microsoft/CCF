// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "ds/json.h"
#include "enclave/interface.h"
#include "node/rpc/call_types.h"

namespace ccf
{
  DECLARE_JSON_ENUM(
    GetSignedIndex::State,
    {{GetSignedIndex::State::ReadingPublicLedger, "readingPublicLedger"},
     {GetSignedIndex::State::ReadingPrivateLedger, "readingPrivateLedger"},
     {GetSignedIndex::State::PartOfNetwork, "partOfNetwork"},
     {GetSignedIndex::State::PartOfPublicNetwork, "partOfPublicNetwork"}})
  DECLARE_JSON_TYPE(GetSignedIndex::Out)
  DECLARE_JSON_REQUIRED_FIELDS(GetSignedIndex::Out, state, signed_index)

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(GetQuotes::Quote)
  DECLARE_JSON_REQUIRED_FIELDS(GetQuotes::Quote, node_id, raw)
  DECLARE_JSON_OPTIONAL_FIELDS(GetQuotes::Quote, error, mrenclave)
  DECLARE_JSON_TYPE(GetQuotes::Out)
  DECLARE_JSON_REQUIRED_FIELDS(GetQuotes::Out, quotes)

  DECLARE_JSON_TYPE(JoinNetworkNodeToNode::In)
  DECLARE_JSON_REQUIRED_FIELDS(
    JoinNetworkNodeToNode::In,
    node_info_network,
    quote,
    public_encryption_key,
    consensus_type)

  DECLARE_JSON_TYPE(NetworkIdentity)
  DECLARE_JSON_REQUIRED_FIELDS(NetworkIdentity, cert, priv_key)

  DECLARE_JSON_TYPE(LedgerSecret)
  DECLARE_JSON_REQUIRED_FIELDS(LedgerSecret, master)
  DECLARE_JSON_TYPE(LedgerSecrets)
  DECLARE_JSON_REQUIRED_FIELDS(LedgerSecrets, secrets_map)
  DECLARE_JSON_TYPE(NetworkEncryptionKey)
  DECLARE_JSON_REQUIRED_FIELDS(NetworkEncryptionKey, private_raw)
  DECLARE_JSON_TYPE(JoinNetworkNodeToNode::Out::NetworkInfo)
  DECLARE_JSON_REQUIRED_FIELDS(
    JoinNetworkNodeToNode::Out::NetworkInfo,
    ledger_secrets,
    identity,
    encryption_key)
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(JoinNetworkNodeToNode::Out)
  DECLARE_JSON_REQUIRED_FIELDS(
    JoinNetworkNodeToNode::Out,
    node_status,
    node_id,
    public_only,
    consensus_type)
  DECLARE_JSON_OPTIONAL_FIELDS(JoinNetworkNodeToNode::Out, network_info)

  DECLARE_JSON_TYPE(CreateNetworkNodeToNode::In)
  DECLARE_JSON_REQUIRED_FIELDS(
    CreateNetworkNodeToNode::In,
    members_info,
    gov_script,
    node_cert,
    network_cert,
    quote,
    public_encryption_key,
    code_digest,
    node_info_network,
    consensus_type,
    recovery_threshold)

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

  DECLARE_JSON_TYPE(GetPrimaryInfo::Out)
  DECLARE_JSON_REQUIRED_FIELDS(
    GetPrimaryInfo::Out, primary_id, primary_host, primary_port)

  DECLARE_JSON_TYPE(GetNetworkInfo::NodeInfo)
  DECLARE_JSON_REQUIRED_FIELDS(GetNetworkInfo::NodeInfo, node_id, host, port)
  DECLARE_JSON_TYPE(GetNetworkInfo::Out)
  DECLARE_JSON_REQUIRED_FIELDS(GetNetworkInfo::Out, nodes, primary_id)

  DECLARE_JSON_TYPE(CallerInfo)
  DECLARE_JSON_REQUIRED_FIELDS(CallerInfo, caller_id);

  DECLARE_JSON_TYPE(WhoIs::In)
  DECLARE_JSON_REQUIRED_FIELDS(WhoIs::In, cert);

  DECLARE_JSON_TYPE(ListMethods::Out)
  DECLARE_JSON_REQUIRED_FIELDS(ListMethods::Out, methods)

  DECLARE_JSON_TYPE(GetSchema::In)
  DECLARE_JSON_REQUIRED_FIELDS(GetSchema::In, method)
  DECLARE_JSON_TYPE(GetSchema::Out)
  DECLARE_JSON_REQUIRED_FIELDS(GetSchema::Out, params_schema, result_schema)

  DECLARE_JSON_TYPE(GetReceipt::In)
  DECLARE_JSON_REQUIRED_FIELDS(GetReceipt::In, commit)
  DECLARE_JSON_TYPE(GetReceipt::Out)
  DECLARE_JSON_REQUIRED_FIELDS(GetReceipt::Out, receipt)

  DECLARE_JSON_TYPE(VerifyReceipt::In)
  DECLARE_JSON_REQUIRED_FIELDS(VerifyReceipt::In, receipt)
  DECLARE_JSON_TYPE(VerifyReceipt::Out)
  DECLARE_JSON_REQUIRED_FIELDS(VerifyReceipt::Out, valid)
}