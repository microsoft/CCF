// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/curve.h"
#include "ccf/ds/unit_strings.h"
#include "ccf/pal/attestation_sev_snp_endorsements.h"
#include "ccf/service/consensus_config.h"
#include "ccf/service/node_info_network.h"
#include "ccf/service/service_config.h"
#include "ccf/service/tables/host_data.h"
#include "ccf/service/tables/members.h"
#include "common/configuration.h"

#include <optional>
#include <string>
#include <vector>

struct CCFConfig
{
  size_t worker_threads = 0;
  consensus::Configuration consensus = {};
  ccf::NodeInfoNetwork network = {};

  struct NodeCertificateInfo
  {
    std::string subject_name = "CN=CCF Node";
    std::vector<std::string> subject_alt_names = {};
    crypto::CurveID curve_id = crypto::CurveID::SECP384R1;
    size_t initial_validity_days = 1;

    bool operator==(const NodeCertificateInfo&) const = default;
  };
  NodeCertificateInfo node_certificate = {};

  struct LedgerSignatures
  {
    size_t tx_count = 5000;
    ds::TimeString delay = {"1000ms"};

    bool operator==(const LedgerSignatures&) const = default;
  };
  LedgerSignatures ledger_signatures = {};

  struct JWT
  {
    ds::TimeString key_refresh_interval = {"30min"};

    bool operator==(const JWT&) const = default;
  };
  JWT jwt = {};

  struct Attestation
  {
    ccf::pal::snp::EndorsementsServers snp_endorsements_servers = {};

    struct Environment
    {
      std::optional<std::string> security_policy = std::nullopt;
      std::optional<std::string> uvm_endorsements = std::nullopt;

      bool operator==(const Environment&) const = default;
    };
    Environment environment = {};

    bool operator==(const Attestation&) const = default;
  };
  Attestation attestation = {};
};

struct StartupConfig : CCFConfig
{
  std::string startup_host_time;
  size_t snapshot_tx_interval = 10'000;

  // Only if starting or recovering
  size_t initial_service_certificate_validity_days = 1;
  nlohmann::json service_data = nullptr;

  nlohmann::json node_data = nullptr;

  std::optional<HostDataMetadata> security_policy; // TODO: Remove

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
    ds::TimeString retry_timeout = {"1000ms"};
    std::vector<uint8_t> service_cert = {};
  };
  Join join = {};

  struct Recover
  {
    std::optional<std::vector<uint8_t>> previous_service_identity =
      std::nullopt;
  };
  Recover recover = {};
};