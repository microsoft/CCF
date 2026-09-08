// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/curve.h"
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
    size_t worker_threads = 0;

    // 2**24.5 as per RFC8446 Section 5.5
    size_t node_to_node_message_limit = 23'726'566;

    ccf::ds::SizeString historical_cache_soft_limit = {"512MB"};

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
    std::optional<ccf::ds::TimeString> idle_connection_timeout =
      ccf::ds::TimeString("60s");
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
}
