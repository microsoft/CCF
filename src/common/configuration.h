// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include "ccf/crypto/curve.h"
#include "ccf/crypto/pem.h"
#include "ccf/ds/unit_strings.h"
#include "ccf/node/configuration.h"
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
    StartType,
    {{StartType::Start, "Start"},
     {StartType::Join, "Join"},
     {StartType::Recover, "Recover"}});

  DECLARE_JSON_ENUM(
    LoggerLevel,
    {{LoggerLevel::TRACE, "Trace"},
     {LoggerLevel::DEBUG, "Debug"},
     {LoggerLevel::INFO, "Info"},
     {LoggerLevel::FAIL, "Fail"},
     {LoggerLevel::FATAL, "Fatal"}});

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCFConfig::NodeCertificateInfo);
  DECLARE_JSON_REQUIRED_FIELDS(CCFConfig::NodeCertificateInfo);
  DECLARE_JSON_OPTIONAL_FIELDS(
    CCFConfig::NodeCertificateInfo,
    subject_name,
    subject_alt_names,
    curve_id,
    initial_validity_days);

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCFConfig::Ledger);
  DECLARE_JSON_REQUIRED_FIELDS(CCFConfig::Ledger);
  DECLARE_JSON_OPTIONAL_FIELDS(
    CCFConfig::Ledger,
    directory,
    read_only_directories,
    chunk_size,
    max_transaction_size);

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCFConfig::LedgerSignatures);
  DECLARE_JSON_REQUIRED_FIELDS(CCFConfig::LedgerSignatures);
  DECLARE_JSON_OPTIONAL_FIELDS(CCFConfig::LedgerSignatures, tx_count, delay);

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCFConfig::JWT);
  DECLARE_JSON_REQUIRED_FIELDS(CCFConfig::JWT);
  DECLARE_JSON_OPTIONAL_FIELDS(
    CCFConfig::JWT, key_refresh_interval, key_refresh_max_response_size);

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

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCFConfig::Snapshots::BackupFetch);
  DECLARE_JSON_REQUIRED_FIELDS(CCFConfig::Snapshots::BackupFetch);
  DECLARE_JSON_OPTIONAL_FIELDS(
    CCFConfig::Snapshots::BackupFetch,
    enabled,
    max_attempts,
    retry_interval,
    target_rpc_interface,
    max_size);

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCFConfig::Snapshots);
  DECLARE_JSON_REQUIRED_FIELDS(CCFConfig::Snapshots);
  DECLARE_JSON_OPTIONAL_FIELDS(
    CCFConfig::Snapshots,
    directory,
    tx_count,
    min_tx_count,
    time_interval,
    read_only_directory,
    backup_fetch);

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCFConfig::FilesCleanup);
  DECLARE_JSON_REQUIRED_FIELDS(CCFConfig::FilesCleanup);
  DECLARE_JSON_OPTIONAL_FIELDS(
    CCFConfig::FilesCleanup,
    max_snapshots,
    max_committed_ledger_chunks,
    interval);

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCFConfig::IdentityHistoryFetch);
  DECLARE_JSON_REQUIRED_FIELDS(CCFConfig::IdentityHistoryFetch);
  DECLARE_JSON_OPTIONAL_FIELDS(
    CCFConfig::IdentityHistoryFetch, max_attempts, retry_interval);

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(RecoveryDecisionProtocolConfig);
  DECLARE_JSON_REQUIRED_FIELDS(
    RecoveryDecisionProtocolConfig, expected_locations);
  DECLARE_JSON_OPTIONAL_FIELDS(
    RecoveryDecisionProtocolConfig, message_retry_timeout, failover_timeout);

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(SealingRecoveryConfig);
  DECLARE_JSON_REQUIRED_FIELDS(SealingRecoveryConfig, location);
  DECLARE_JSON_OPTIONAL_FIELDS(
    SealingRecoveryConfig, recovery_decision_protocol);

  DECLARE_JSON_ENUM(
    LogFormat, {{LogFormat::TEXT, "Text"}, {LogFormat::JSON, "Json"}});

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(ParsedMemberInfo);
  DECLARE_JSON_REQUIRED_FIELDS(ParsedMemberInfo, certificate_file);
  DECLARE_JSON_OPTIONAL_FIELDS(
    ParsedMemberInfo,
    encryption_public_key_file,
    data_json_file,
    recovery_role);

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCFConfig::OutputFiles);
  DECLARE_JSON_REQUIRED_FIELDS(CCFConfig::OutputFiles);
  DECLARE_JSON_OPTIONAL_FIELDS(
    CCFConfig::OutputFiles,
    node_certificate_file,
    pid_file,
    node_to_node_address_file,
    rpc_addresses_file);

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCFConfig::Logging);
  DECLARE_JSON_REQUIRED_FIELDS(CCFConfig::Logging);
  DECLARE_JSON_OPTIONAL_FIELDS(CCFConfig::Logging, format);

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCFConfig::Memory);
  DECLARE_JSON_REQUIRED_FIELDS(CCFConfig::Memory);
  DECLARE_JSON_OPTIONAL_FIELDS(
    CCFConfig::Memory, circuit_size, max_msg_size, max_fragment_size);

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCFConfig::Command::Start);
  DECLARE_JSON_REQUIRED_FIELDS(
    CCFConfig::Command::Start, members, constitution_files);
  DECLARE_JSON_OPTIONAL_FIELDS(
    CCFConfig::Command::Start,
    service_configuration,
    initial_service_certificate_validity_days,
    service_subject_name,
    cose_signatures);

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCFConfig::Command::Join);
  DECLARE_JSON_REQUIRED_FIELDS(CCFConfig::Command::Join, target_rpc_address);
  DECLARE_JSON_OPTIONAL_FIELDS(
    CCFConfig::Command::Join,
    retry_timeout,
    follow_redirect,
    fetch_recent_snapshot,
    fetch_snapshot_max_attempts,
    fetch_snapshot_retry_interval,
    fetch_snapshot_max_size,
    host_data_transparent_statement_path);

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCFConfig::Command::Recover);
  DECLARE_JSON_REQUIRED_FIELDS(CCFConfig::Command::Recover);
  DECLARE_JSON_OPTIONAL_FIELDS(
    CCFConfig::Command::Recover,
    initial_service_certificate_validity_days,
    previous_service_identity_file);

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCFConfig::Command);
  DECLARE_JSON_REQUIRED_FIELDS(CCFConfig::Command, type);
  DECLARE_JSON_OPTIONAL_FIELDS(
    CCFConfig::Command, service_certificate_file, start, join, recover);

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCFConfig);
  DECLARE_JSON_REQUIRED_FIELDS(CCFConfig, network, command);
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
    files_cleanup,
    node_to_node_message_limit,
    historical_cache_soft_limit,
    identity_history_fetch,
    tick_interval,
    slow_io_logging_threshold,
    node_client_interface,
    client_connection_timeout,
    idle_connection_timeout,
    node_data_json_file,
    service_data_json_file,
    ignore_first_sigterm,
    sealing_recovery,
    output_files,
    logging,
    memory);
}
