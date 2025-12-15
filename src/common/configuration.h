// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include "ccf/crypto/curve.h"
#include "ccf/crypto/pem.h"
#include "ccf/ds/unit_strings.h"
#include "ccf/node/startup_config.h"
#include "ccf/pal/attestation_sev_snp_endorsements.h"
#include "ccf/service/consensus_type.h"
#include "ccf/service/node_info_network.h"
#include "ccf/service/reconfiguration_type.h"
#include "ccf/service/tables/members.h"
#include "common/enclave_interface_types.h"
#include "consensus/consensus_types.h"
#include "ds/internal_logger.h"
#include "ds/oversized.h"
#include "service/tables/config.h"

#include <optional>
#include <string>
#include <vector>

DECLARE_JSON_ENUM(
  StartType,
  {{StartType::Start, "Start"},
   {StartType::Join, "Join"},
   {StartType::Recover, "Recover"}});

struct EnclaveConfig
{
  uint8_t* to_enclave_buffer_start = nullptr;
  size_t to_enclave_buffer_size = 0;
  ringbuffer::Offsets* to_enclave_buffer_offsets = nullptr;

  uint8_t* from_enclave_buffer_start = nullptr;
  size_t from_enclave_buffer_size = 0;
  ringbuffer::Offsets* from_enclave_buffer_offsets = nullptr;

  oversized::WriterConfig writer_config = {};
};

static constexpr auto node_to_node_interface_name = "node_to_node_interface";

namespace ccf
{
  DECLARE_JSON_ENUM(
    LoggerLevel,
    {{LoggerLevel::TRACE, "Trace"},
     {LoggerLevel::DEBUG, "Debug"},
     {LoggerLevel::INFO, "Info"},
     {LoggerLevel::FAIL, "Fail"},
     {LoggerLevel::FATAL, "Fatal"}});

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCFConfig::NodeCertificateInfo);
  DECLARE_JSON_REQUIRED_FIELDS(CCFConfig::NodeCertificateInfo)
  DECLARE_JSON_OPTIONAL_FIELDS(
    CCFConfig::NodeCertificateInfo,
    subject_name,
    subject_alt_names,
    curve_id,
    initial_validity_days);

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCFConfig::Ledger);
  DECLARE_JSON_REQUIRED_FIELDS(CCFConfig::Ledger);
  DECLARE_JSON_OPTIONAL_FIELDS(
    CCFConfig::Ledger, directory, read_only_directories, chunk_size);

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCFConfig::LedgerSignatures);
  DECLARE_JSON_REQUIRED_FIELDS(CCFConfig::LedgerSignatures);
  DECLARE_JSON_OPTIONAL_FIELDS(CCFConfig::LedgerSignatures, tx_count, delay);

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCFConfig::JWT);
  DECLARE_JSON_REQUIRED_FIELDS(CCFConfig::JWT);
  DECLARE_JSON_OPTIONAL_FIELDS(CCFConfig::JWT, key_refresh_interval);

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCFConfig::Attestation::Environment);
  DECLARE_JSON_REQUIRED_FIELDS(CCFConfig::Attestation::Environment);
  DECLARE_JSON_OPTIONAL_FIELDS(
    CCFConfig::Attestation::Environment,
    security_policy,
    uvm_endorsements,
    snp_endorsements);

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCFConfig::Attestation);
  DECLARE_JSON_REQUIRED_FIELDS(CCFConfig::Attestation);
  DECLARE_JSON_OPTIONAL_FIELDS(
    CCFConfig::Attestation,
    snp_endorsements_servers,
    environment,
    snp_security_policy_file,
    snp_uvm_endorsements_file,
    snp_endorsements_file);

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCFConfig::Snapshots);
  DECLARE_JSON_REQUIRED_FIELDS(CCFConfig::Snapshots);
  DECLARE_JSON_OPTIONAL_FIELDS(
    CCFConfig::Snapshots, directory, tx_count, read_only_directory);

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCFConfig);
  DECLARE_JSON_REQUIRED_FIELDS(CCFConfig, network);
  DECLARE_JSON_OPTIONAL_FIELDS(
    CCFConfig,
    worker_threads,
    node_certificate,
    consensus,
    ledger,
    ledger_signatures,
    jwt,
    attestation,
    snapshots,
    node_to_node_message_limit,
    historical_cache_soft_limit);

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(SelfHealingOpenConfig);
  DECLARE_JSON_REQUIRED_FIELDS(SelfHealingOpenConfig, addresses);
  DECLARE_JSON_OPTIONAL_FIELDS(
    SelfHealingOpenConfig, retry_timeout, failover_timeout);

  DECLARE_JSON_TYPE(StartupConfig::Start);
  DECLARE_JSON_REQUIRED_FIELDS(
    StartupConfig::Start, members, constitution, service_configuration);

  DECLARE_JSON_TYPE(StartupConfig::Join);
  DECLARE_JSON_REQUIRED_FIELDS(
    StartupConfig::Join,
    target_rpc_address,
    retry_timeout,
    service_cert,
    follow_redirect);

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(StartupConfig::Recover);
  DECLARE_JSON_REQUIRED_FIELDS(
    StartupConfig::Recover, previous_service_identity);
  DECLARE_JSON_OPTIONAL_FIELDS(
    StartupConfig::Recover,
    previous_sealed_ledger_secret_location,
    self_healing_open);

  DECLARE_JSON_TYPE_WITH_BASE(StartupConfig, CCFConfig);
  DECLARE_JSON_REQUIRED_FIELDS(
    StartupConfig,
    startup_host_time,
    snapshot_tx_interval,
    initial_service_certificate_validity_days,
    service_subject_name,
    cose_signatures,
    service_data,
    node_data,
    start,
    join,
    recover,
    sealed_ledger_secret_location);
}
