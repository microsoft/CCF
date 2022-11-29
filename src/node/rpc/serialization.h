// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "ccf/service/tables/code_id.h"
#include "enclave/consensus_type.h"
#include "enclave/interface.h"
#include "node/rpc/call_types.h"

namespace ccf
{
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(GetState::Out)
  DECLARE_JSON_REQUIRED_FIELDS(
    GetState::Out, node_id, state, last_signed_seqno, startup_seqno)
  DECLARE_JSON_OPTIONAL_FIELDS(
    GetState::Out, recovery_target_seqno, last_recovered_seqno)

  DECLARE_JSON_TYPE(GetVersion::Out)
  DECLARE_JSON_REQUIRED_FIELDS(
    GetVersion::Out, ccf_version, quickjs_version, unsafe)

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(JoinNetworkNodeToNode::In)
  DECLARE_JSON_REQUIRED_FIELDS(
    JoinNetworkNodeToNode::In,
    node_info_network,
    quote_info,
    public_encryption_key,
    consensus_type,
    startup_seqno)
  DECLARE_JSON_OPTIONAL_FIELDS(
    JoinNetworkNodeToNode::In, certificate_signing_request, node_data)

  DECLARE_JSON_ENUM(
    ccf::IdentityType,
    {{ccf::IdentityType::REPLICATED, "Replicated"},
     {ccf::IdentityType::SPLIT, "Split"}})
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(NetworkIdentity)
  DECLARE_JSON_REQUIRED_FIELDS(NetworkIdentity, cert, priv_key)
  DECLARE_JSON_OPTIONAL_FIELDS(NetworkIdentity, type)
  DECLARE_JSON_TYPE_WITH_BASE(ReplicatedNetworkIdentity, NetworkIdentity)
  DECLARE_JSON_TYPE_WITH_BASE(SplitNetworkIdentity, NetworkIdentity)
  DECLARE_JSON_REQUIRED_FIELDS(SplitNetworkIdentity, cert, type)

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(
    JoinNetworkNodeToNode::Out::NetworkInfo)
  DECLARE_JSON_REQUIRED_FIELDS(
    JoinNetworkNodeToNode::Out::NetworkInfo,
    public_only,
    last_recovered_signed_idx,
    consensus_type,
    ledger_secrets,
    identity)
  DECLARE_JSON_OPTIONAL_FIELDS(
    JoinNetworkNodeToNode::Out::NetworkInfo,
    service_status,
    endorsed_certificate,
    reconfiguration_type)
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(JoinNetworkNodeToNode::Out)
  DECLARE_JSON_REQUIRED_FIELDS(JoinNetworkNodeToNode::Out, node_status)
  DECLARE_JSON_OPTIONAL_FIELDS(
    JoinNetworkNodeToNode::Out, node_id, network_info)

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CreateNetworkNodeToNode::In)
  DECLARE_JSON_REQUIRED_FIELDS(
    CreateNetworkNodeToNode::In,
    node_id,
    certificate_signing_request,
    node_endorsed_certificate,
    public_key,
    service_cert,
    quote_info,
    public_encryption_key,
    code_digest,
    node_info_network,
    create_txid)
  DECLARE_JSON_OPTIONAL_FIELDS(
    CreateNetworkNodeToNode::In,
    genesis_info,
    node_data,
    service_data,
    security_policy)

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(GetCommit::Out)
  DECLARE_JSON_REQUIRED_FIELDS(GetCommit::Out, transaction_id)
  DECLARE_JSON_OPTIONAL_FIELDS(GetCommit::Out, view_history)

  DECLARE_JSON_TYPE(GetTxStatus::Out)
  DECLARE_JSON_REQUIRED_FIELDS(GetTxStatus::Out, transaction_id, status)

  DECLARE_JSON_TYPE(GetNetworkInfo::Out)
  DECLARE_JSON_REQUIRED_FIELDS(
    GetNetworkInfo::Out,
    service_status,
    service_certificate,
    current_view,
    primary_id,
    recovery_count,
    service_data,
    current_service_create_txid)

  DECLARE_JSON_TYPE(GetNode::NodeInfo)
  DECLARE_JSON_REQUIRED_FIELDS(
    GetNode::NodeInfo,
    node_id,
    status,
    primary,
    rpc_interfaces,
    node_data,
    last_written)

  DECLARE_JSON_TYPE(GetNodes::Out)
  DECLARE_JSON_REQUIRED_FIELDS(GetNodes::Out, nodes)

  DECLARE_JSON_TYPE(VerifyReceipt::In)
  DECLARE_JSON_REQUIRED_FIELDS(VerifyReceipt::In, receipt)
  DECLARE_JSON_TYPE(VerifyReceipt::Out)
  DECLARE_JSON_REQUIRED_FIELDS(VerifyReceipt::Out, valid)

  DECLARE_JSON_TYPE(GetCode::Version)
  DECLARE_JSON_REQUIRED_FIELDS(GetCode::Version, digest, status)
  DECLARE_JSON_TYPE(GetCode::Out)
  DECLARE_JSON_REQUIRED_FIELDS(GetCode::Out, versions)

  DECLARE_JSON_TYPE(GetSnpHostDataMap::HostData)
  DECLARE_JSON_REQUIRED_FIELDS(GetSnpHostDataMap::HostData, raw, metadata)
  DECLARE_JSON_TYPE(GetSnpHostDataMap::Out)
  DECLARE_JSON_REQUIRED_FIELDS(GetSnpHostDataMap::Out, host_data)

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

  DECLARE_JSON_TYPE(UpdateResharing::In)
  DECLARE_JSON_REQUIRED_FIELDS(UpdateResharing::In, rid)
}
