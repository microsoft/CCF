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
    {{ccf::State::uninitialized, "Uninitialized"},
     {ccf::State::initialized, "Initialized"},
     {ccf::State::pending, "Pending"},
     {ccf::State::partOfPublicNetwork, "PartOfPublicNetwork"},
     {ccf::State::partOfNetwork, "PartOfNetwork"},
     {ccf::State::readingPublicLedger, "ReadingPublicLedger"},
     {ccf::State::readingPrivateLedger, "ReadingPrivateLedger"},
     {ccf::State::verifyingSnapshot, "VerifyingSnapshot"}})
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(GetState::Out)
  DECLARE_JSON_REQUIRED_FIELDS(
    GetState::Out, node_id, state, last_signed_seqno, startup_seqno)
  DECLARE_JSON_OPTIONAL_FIELDS(
    GetState::Out, recovery_target_seqno, last_recovered_seqno)

  DECLARE_JSON_TYPE(GetVersion::Out)
  DECLARE_JSON_REQUIRED_FIELDS(GetVersion::Out, ccf_version, quickjs_version)

  DECLARE_JSON_TYPE(JoinNetworkNodeToNode::In)
  DECLARE_JSON_REQUIRED_FIELDS(
    JoinNetworkNodeToNode::In,
    node_info_network,
    quote_info,
    public_encryption_key,
    consensus_type,
    startup_seqno)

  DECLARE_JSON_TYPE(NetworkIdentity)
  DECLARE_JSON_REQUIRED_FIELDS(NetworkIdentity, cert, priv_key)

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
    constitution,
    node_id,
    node_cert,
    network_cert,
    quote_info,
    public_encryption_key,
    code_digest,
    node_info_network,
    configuration)

  DECLARE_JSON_TYPE(GetCommit::Out)
  DECLARE_JSON_REQUIRED_FIELDS(GetCommit::Out, transaction_id)

  DECLARE_JSON_TYPE(GetTxStatus::Out)
  DECLARE_JSON_REQUIRED_FIELDS(GetTxStatus::Out, transaction_id, status)

  DECLARE_JSON_TYPE(GetNetworkInfo::Out)
  DECLARE_JSON_REQUIRED_FIELDS(
    GetNetworkInfo::Out,
    service_status,
    service_certificate,
    current_view,
    primary_id)

  DECLARE_JSON_TYPE(GetNode::NodeInfo)
  DECLARE_JSON_REQUIRED_FIELDS(
    GetNode::NodeInfo,
    node_id,
    status,
    host,
    port,
    local_host,
    local_port,
    primary)

  DECLARE_JSON_TYPE(GetNodes::Out)
  DECLARE_JSON_REQUIRED_FIELDS(GetNodes::Out, nodes)

  DECLARE_JSON_TYPE(EndpointMetrics::Entry)
  DECLARE_JSON_REQUIRED_FIELDS(
    EndpointMetrics::Entry, path, method, calls, errors, failures, retries)
  DECLARE_JSON_TYPE(EndpointMetrics::Out)
  DECLARE_JSON_REQUIRED_FIELDS(EndpointMetrics::Out, metrics)

  DECLARE_JSON_TYPE(VerifyReceipt::In)
  DECLARE_JSON_REQUIRED_FIELDS(VerifyReceipt::In, receipt)
  DECLARE_JSON_TYPE(VerifyReceipt::Out)
  DECLARE_JSON_REQUIRED_FIELDS(VerifyReceipt::Out, valid)

  DECLARE_JSON_TYPE(GetCode::Version)
  DECLARE_JSON_REQUIRED_FIELDS(GetCode::Version, digest, status)
  DECLARE_JSON_TYPE(GetCode::Out)
  DECLARE_JSON_REQUIRED_FIELDS(GetCode::Out, versions)

  DECLARE_JSON_TYPE(GetRecoveryShare::Out)
  DECLARE_JSON_REQUIRED_FIELDS(GetRecoveryShare::Out, encrypted_share)

  DECLARE_JSON_TYPE(SubmitRecoveryShare::In)
  DECLARE_JSON_REQUIRED_FIELDS(SubmitRecoveryShare::In, share)
  DECLARE_JSON_TYPE(SubmitRecoveryShare::Out)
  DECLARE_JSON_REQUIRED_FIELDS(SubmitRecoveryShare::Out, message)

  DECLARE_JSON_TYPE(MemoryUsage::Out)
  DECLARE_JSON_REQUIRED_FIELDS(
    MemoryUsage::Out,
    max_total_heap_size,
    current_allocated_heap_size,
    peak_allocated_heap_size)
}