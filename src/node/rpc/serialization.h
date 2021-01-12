// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "ds/json.h"
#include "enclave/consensus_type.h"
#include "enclave/interface.h"
#include "node/code_id.h"
#include "node/rpc/call_types.h"

namespace ccf
{
  DECLARE_JSON_ENUM(
    ccf::State,
    {{ccf::State::uninitialized, "uninitialized"},
     {ccf::State::initialized, "initialized"},
     {ccf::State::pending, "pending"},
     {ccf::State::partOfPublicNetwork, "partOfPublicNetwork"},
     {ccf::State::partOfNetwork, "partOfNetwork"},
     {ccf::State::readingPublicLedger, "readingPublicLedger"},
     {ccf::State::readingPrivateLedger, "readingPrivateLedger"},
     {ccf::State::verifyingSnapshot, "verifyingSnapshot"}})
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(GetState::Out)
  DECLARE_JSON_REQUIRED_FIELDS(GetState::Out, id, state, last_signed_seqno)
  DECLARE_JSON_OPTIONAL_FIELDS(
    GetState::Out, recovery_target_seqno, last_recovered_seqno)

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
  DECLARE_JSON_TYPE(LedgerSecrets::VersionedLedgerSecret)
  DECLARE_JSON_REQUIRED_FIELDS(
    LedgerSecrets::VersionedLedgerSecret, version, secret)
  DECLARE_JSON_TYPE(LedgerSecrets)
  DECLARE_JSON_REQUIRED_FIELDS(LedgerSecrets, secrets_list)

  DECLARE_JSON_TYPE(JoinNetworkNodeToNode::Out::NetworkInfo)
  DECLARE_JSON_REQUIRED_FIELDS(
    JoinNetworkNodeToNode::Out::NetworkInfo,
    public_only,
    last_recovered_signed_idx,
    consensus_type,
    ledger_secrets,
    identity)
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(JoinNetworkNodeToNode::Out)
  DECLARE_JSON_REQUIRED_FIELDS(JoinNetworkNodeToNode::Out, node_status, node_id)
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

  DECLARE_JSON_TYPE(GetCommit::Out)
  DECLARE_JSON_REQUIRED_FIELDS(GetCommit::Out, view, seqno)

  DECLARE_JSON_TYPE(GetTxStatus::In)
  DECLARE_JSON_REQUIRED_FIELDS(GetTxStatus::In, view, seqno)
  DECLARE_JSON_TYPE(GetTxStatus::Out)
  DECLARE_JSON_REQUIRED_FIELDS(GetTxStatus::Out, status)

  DECLARE_JSON_TYPE(GetPrimaryInfo::Out)
  DECLARE_JSON_REQUIRED_FIELDS(
    GetPrimaryInfo::Out, primary_id, primary_host, primary_port, current_view)

  DECLARE_JSON_TYPE(GetNetworkInfo::NodeInfo)
  DECLARE_JSON_REQUIRED_FIELDS(GetNetworkInfo::NodeInfo, node_id, host, port)
  DECLARE_JSON_TYPE(GetNetworkInfo::Out)
  DECLARE_JSON_REQUIRED_FIELDS(GetNetworkInfo::Out, nodes, primary_id)

  DECLARE_JSON_TYPE(GetNodesByRPCAddress::In)
  DECLARE_JSON_REQUIRED_FIELDS(GetNodesByRPCAddress::In, host, port)
  DECLARE_JSON_TYPE(GetNodesByRPCAddress::NodeInfo)
  DECLARE_JSON_REQUIRED_FIELDS(GetNodesByRPCAddress::NodeInfo, node_id, status)
  DECLARE_JSON_TYPE(GetNodesByRPCAddress::Out)
  DECLARE_JSON_REQUIRED_FIELDS(GetNodesByRPCAddress::Out, nodes)

  DECLARE_JSON_TYPE(CallerInfo)
  DECLARE_JSON_REQUIRED_FIELDS(CallerInfo, caller_id)

  DECLARE_JSON_TYPE(GetUserId::In)
  DECLARE_JSON_REQUIRED_FIELDS(GetUserId::In, cert)

  DECLARE_JSON_TYPE(EndpointMetrics::Metric)
  DECLARE_JSON_REQUIRED_FIELDS(EndpointMetrics::Metric, calls, errors, failures)
  DECLARE_JSON_TYPE(EndpointMetrics::Out)
  DECLARE_JSON_REQUIRED_FIELDS(EndpointMetrics::Out, metrics)

  DECLARE_JSON_TYPE(GetReceipt::In)
  DECLARE_JSON_REQUIRED_FIELDS(GetReceipt::In, commit)
  DECLARE_JSON_TYPE(GetReceipt::Out)
  DECLARE_JSON_REQUIRED_FIELDS(GetReceipt::Out, receipt)

  DECLARE_JSON_TYPE(VerifyReceipt::In)
  DECLARE_JSON_REQUIRED_FIELDS(VerifyReceipt::In, receipt)
  DECLARE_JSON_TYPE(VerifyReceipt::Out)
  DECLARE_JSON_REQUIRED_FIELDS(VerifyReceipt::Out, valid)

  DECLARE_JSON_TYPE(GetCode::Version)
  DECLARE_JSON_REQUIRED_FIELDS(GetCode::Version, digest, status)
  DECLARE_JSON_TYPE(GetCode::Out)
  DECLARE_JSON_REQUIRED_FIELDS(GetCode::Out, versions)

  DECLARE_JSON_TYPE(MemoryUsage::Out)
  DECLARE_JSON_REQUIRED_FIELDS(
    MemoryUsage::Out,
    max_total_heap_size,
    current_allocated_heap_size,
    peak_allocated_heap_size)
}