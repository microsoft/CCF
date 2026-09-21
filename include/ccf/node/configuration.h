// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/curve.h"
#include "ccf/ds/json.h"
#include "ccf/ds/unit_strings.h"
#include "ccf/entity_id.h"
#include "ccf/node/cose_signatures_config.h"
#include "ccf/node/start_type.h"
#include "ccf/pal/attestation_sev_snp_endorsements.h"
#include "ccf/service/consensus_config.h"
#include "ccf/service/node_info_network.h"
#include "ccf/service/service_config.h"
#include "ccf/service/tables/host_data.h"
#include "ccf/service/tables/members.h"
#include "ccf/service/tables/self_healing_open.h"

#include <optional>
#include <string>
#include <vector>

namespace ccf
{
  enum class LogFormat : uint8_t
  {
    TEXT,
    JSON
  };

  struct ParsedMemberInfo
  {
    std::string certificate_file;
    std::optional<std::string> encryption_public_key_file = std::nullopt;
    std::optional<std::string> data_json_file = std::nullopt;
    std::optional<ccf::MemberRecoveryRole> recovery_role = std::nullopt;

    bool operator==(const ParsedMemberInfo&) const = default;
  };

  struct RecoveryDecisionProtocolConfig
  {
    std::vector<sealing_recovery::Location> expected_locations;
    ccf::ds::TimeString message_retry_timeout = {"100ms"};
    ccf::ds::TimeString failover_timeout = {"2000ms"};
    bool operator==(const RecoveryDecisionProtocolConfig&) const = default;
  };

  struct SealingRecoveryConfig
  {
    sealing_recovery::Location location;
    std::optional<RecoveryDecisionProtocolConfig> recovery_decision_protocol =
      std::nullopt;
    bool operator==(const SealingRecoveryConfig&) const = default;
  };

  struct CCFConfig
  {
    // Default, and minimum enforced number, of worker threads. A configured
    // value of 0 is accepted and coerced up to 1 (see
    // validate_and_coerce_worker_threads in src/host/run.cpp).
    size_t worker_threads = 1;

    // 2**24.5 as per RFC8446 Section 5.5
    size_t node_to_node_message_limit = 23'726'566;

    ccf::ds::SizeString historical_cache_soft_limit = {"512MB"};

    // How long an idle RPC (client TLS) connection is kept before it is closed.
    // std::nullopt disables idle closure (connections are never closed for
    // being idle).
    std::optional<ccf::ds::TimeString> idle_connection_timeout =
      ccf::ds::TimeString("60s");
    ccf::ds::TimeString pending_node_timeout = {"1h"};

    ccf::consensus::Configuration consensus = {};
    ccf::NodeInfoNetwork network;

    struct NodeCertificateInfo
    {
      std::string subject_name = "CN=CCF Node";
      std::vector<std::string> subject_alt_names;
      ccf::crypto::CurveID curve_id = ccf::crypto::CurveID::SECP384R1;
      size_t initial_validity_days = 1;

      bool operator==(const NodeCertificateInfo&) const = default;
    };
    NodeCertificateInfo node_certificate = {};

    struct Ledger
    {
      std::string directory = "ledger";
      std::vector<std::string> read_only_directories;
      ccf::ds::SizeString chunk_size = {"5MB"};
      ccf::ds::SizeString max_transaction_size = {"32MB"};

      bool operator==(const Ledger&) const = default;
    };
    Ledger ledger = {};

    struct LedgerSignatures
    {
      size_t tx_count = 5000;
      ccf::ds::TimeString delay = {"1000ms"};

      bool operator==(const LedgerSignatures&) const = default;
    };
    LedgerSignatures ledger_signatures = {};

    struct JWT
    {
      ccf::ds::TimeString key_refresh_interval = {"30min"};
      ccf::ds::SizeString key_refresh_max_response_size = {"1MB"};

      bool operator==(const JWT&) const = default;
    };
    JWT jwt = {};

    struct Attestation
    {
      ccf::pal::snp::EndorsementsServers snp_endorsements_servers;
      std::optional<std::string> snp_security_policy_file = std::nullopt;
      std::optional<std::string> snp_uvm_endorsements_file = std::nullopt;
      std::optional<std::string> snp_endorsements_file = std::nullopt;

      struct Environment
      {
        // Each of these contains the string read from the relevant file. It is
        // expected to be a base-64 string.
        std::optional<std::string> security_policy = std::nullopt;
        std::optional<std::string> uvm_endorsements = std::nullopt;
        std::optional<std::string> snp_endorsements = std::nullopt;

        bool operator==(const Environment&) const = default;
      };
      Environment environment = {};

      bool operator==(const Attestation&) const = default;
    };
    Attestation attestation = {};

    struct Snapshots
    {
      std::string directory = "snapshots";
      size_t tx_count = 10'000;
      size_t min_tx_count = 2;
      ccf::ds::TimeString time_interval = {"0s"};
      std::optional<std::string> read_only_directory = std::nullopt;

      struct BackupFetch
      {
        bool enabled = false;
        size_t max_attempts = 3;
        ccf::ds::TimeString retry_interval = {"1000ms"};
        std::string target_rpc_interface = ccf::PRIMARY_RPC_INTERFACE;
        ccf::ds::SizeString max_size = {"200MB"};

        bool operator==(const BackupFetch&) const = default;
      };
      BackupFetch backup_fetch = {};

      bool operator==(const Snapshots&) const = default;
    };
    Snapshots snapshots = {};

    struct FilesCleanup
    {
      std::optional<size_t> max_snapshots = std::nullopt;
      std::optional<size_t> max_committed_ledger_chunks = std::nullopt;
      ccf::ds::TimeString interval = {"30s"};

      bool operator==(const FilesCleanup&) const = default;
    };
    FilesCleanup files_cleanup = {};

    struct IdentityHistoryFetch
    {
      size_t max_attempts = 100;
      ccf::ds::TimeString retry_interval = {"100ms"};

      bool operator==(const IdentityHistoryFetch&) const = default;
    };
    IdentityHistoryFetch identity_history_fetch = {};
    ccf::ds::TimeString tick_interval = {"10ms"};
    ccf::ds::TimeString slow_io_logging_threshold = {"10ms"};
    std::optional<std::string> node_client_interface = std::nullopt;
    ccf::ds::TimeString client_connection_timeout = {"2000ms"};
    std::optional<std::string> node_data_json_file = std::nullopt;
    std::optional<std::string> service_data_json_file = std::nullopt;
    bool ignore_first_sigterm = false;
    std::optional<SealingRecoveryConfig> sealing_recovery = std::nullopt;

    struct OutputFiles
    {
      std::string node_certificate_file = "nodecert.pem";
      std::string pid_file = "my_node.pid";

      // Addresses files
      std::string node_to_node_address_file;
      std::string rpc_addresses_file;

      bool operator==(const OutputFiles&) const = default;
    };
    OutputFiles output_files = {};

    struct Logging
    {
      LogFormat format = LogFormat::TEXT;

      bool operator==(const Logging&) const = default;
    };
    Logging logging = {};

    struct Memory
    {
      ccf::ds::SizeString circuit_size = {"16MB"};
      ccf::ds::SizeString max_msg_size = {"64MB"};
      ccf::ds::SizeString max_fragment_size = {"256KB"};

      bool operator==(const Memory&) const = default;
    };
    Memory memory = {};

    struct Command
    {
      StartType type = StartType::Start;
      std::string service_certificate_file = "service_cert.pem";

      struct Start
      {
        std::vector<ParsedMemberInfo> members;
        std::vector<std::string> constitution_files;
        ccf::ServiceConfiguration service_configuration;
        size_t initial_service_certificate_validity_days = 1;
        std::string service_subject_name = "CN=CCF Service";
        ccf::COSESignaturesConfig cose_signatures;

        bool operator==(const Start&) const = default;
      };
      Start start = {};

      struct Join
      {
        ccf::NodeInfoNetwork::NetAddress target_rpc_address;
        ccf::ds::TimeString retry_timeout = {"1000ms"};
        bool follow_redirect = true;
        bool fetch_recent_snapshot = true;
        size_t fetch_snapshot_max_attempts = 3;
        ccf::ds::TimeString fetch_snapshot_retry_interval = {"1000ms"};
        ccf::ds::SizeString fetch_snapshot_max_size = {"10GB"};
        std::optional<std::string> host_data_transparent_statement_path =
          std::nullopt;

        bool operator==(const Join&) const = default;
      };
      Join join = {};

      struct Recover
      {
        size_t initial_service_certificate_validity_days = 1;
        std::string previous_service_identity_file;
        bool operator==(const Recover&) const = default;
      };
      Recover recover = {};
    };
    Command command = {};
  };

  DECLARE_JSON_ENUM(
    StartType,
    {{StartType::Start, "Start"},
     {StartType::Join, "Join"},
     {StartType::Recover, "Recover"}});

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
    pending_node_timeout,
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
