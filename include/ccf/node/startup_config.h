// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/curve.h"
#include "ccf/ds/unit_strings.h"
#include "ccf/node/cose_signatures_config.h"
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
      std::optional<std::string> read_only_directory = std::nullopt;

      bool operator==(const Snapshots&) const = default;
    };
    Snapshots snapshots = {};
  };

  struct SelfHealingOpenConfig
  {
    self_healing_open::Identity identity;
    std::vector<self_healing_open::Identity> cluster_identities;
    ccf::ds::TimeString retry_timeout = {"100ms"};
    ccf::ds::TimeString failover_timeout = {"2000ms"};
    bool operator==(const SelfHealingOpenConfig&) const = default;
  };

  struct StartupConfig : CCFConfig
  {
    StartupConfig() = default;
    StartupConfig(const CCFConfig& common_base) : CCFConfig(common_base) {}

    std::string startup_host_time;
    size_t snapshot_tx_interval = 10'000;

    // Only if starting or recovering
    size_t initial_service_certificate_validity_days = 1;
    std::string service_subject_name = "CN=CCF Service";
    ccf::COSESignaturesConfig cose_signatures;

    std::optional<std::string> sealed_ledger_secret_location;

    nlohmann::json service_data = nullptr;

    nlohmann::json node_data = nullptr;

    struct Start
    {
      std::vector<ccf::NewMember> members;
      std::string constitution;
      ccf::ServiceConfiguration service_configuration;

      bool operator==(const Start& other) const = default;
    };
    Start start = {};

    struct Join
    {
      ccf::NodeInfoNetwork::NetAddress target_rpc_address;
      ccf::ds::TimeString retry_timeout;
      std::vector<uint8_t> service_cert;
      bool follow_redirect;
      bool fetch_recent_snapshot;
      size_t fetch_snapshot_max_attempts;
      ccf::ds::TimeString fetch_snapshot_retry_interval;
      ccf::ds::SizeString fetch_snapshot_max_size;
    };
    Join join = {};

    struct Recover
    {
      std::optional<std::vector<uint8_t>> previous_service_identity =
        std::nullopt;
      std::optional<std::string> previous_sealed_ledger_secret_location =
        std::nullopt;
      std::optional<SelfHealingOpenConfig> self_healing_open = std::nullopt;
    };
    Recover recover = {};
  };
}
