// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include "ccf/crypto/curve.h"
#include "ccf/crypto/pem.h"
#include "ccf/ds/logger.h"
#include "ccf/ds/unit_strings.h"
#include "ccf/service/node_info_network.h"
#include "ccf/service/tables/members.h"
#include "common/enclave_interface_types.h"
#include "consensus/consensus_types.h"
#include "ds/oversized.h"
#include "enclave/consensus_type.h"
#include "enclave/reconfiguration_type.h"
#include "service/tables/config.h"

#include <optional>
#include <string>
#include <vector>

namespace logger
{
  DECLARE_JSON_ENUM(
    Level,
    {{Level::TRACE, "Trace"},
     {Level::DEBUG, "Debug"},
     {Level::INFO, "Info"},
     {Level::FAIL, "Fail"},
     {Level::FATAL, "Fatal"}});
}

DECLARE_JSON_ENUM(
  StartType,
  {{StartType::Start, "Start"},
   {StartType::Join, "Join"},
   {StartType::Recover, "Recover"}});

struct EnclaveConfig
{
  uint8_t* to_enclave_buffer_start;
  size_t to_enclave_buffer_size;
  ringbuffer::Offsets* to_enclave_buffer_offsets;

  uint8_t* from_enclave_buffer_start;
  size_t from_enclave_buffer_size;
  ringbuffer::Offsets* from_enclave_buffer_offsets;

  oversized::WriterConfig writer_config = {};
};

static constexpr auto node_to_node_interface_name = "node_to_node_interface";

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
};

DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCFConfig::NodeCertificateInfo);
DECLARE_JSON_REQUIRED_FIELDS(CCFConfig::NodeCertificateInfo)
DECLARE_JSON_OPTIONAL_FIELDS(
  CCFConfig::NodeCertificateInfo,
  subject_name,
  subject_alt_names,
  curve_id,
  initial_validity_days);

DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCFConfig::LedgerSignatures);
DECLARE_JSON_REQUIRED_FIELDS(CCFConfig::LedgerSignatures);
DECLARE_JSON_OPTIONAL_FIELDS(CCFConfig::LedgerSignatures, tx_count, delay);

DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCFConfig::JWT);
DECLARE_JSON_REQUIRED_FIELDS(CCFConfig::JWT);
DECLARE_JSON_OPTIONAL_FIELDS(CCFConfig::JWT, key_refresh_interval);

DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCFConfig);
DECLARE_JSON_REQUIRED_FIELDS(CCFConfig, network);
DECLARE_JSON_OPTIONAL_FIELDS(
  CCFConfig,
  worker_threads,
  node_certificate,
  consensus,
  ledger_signatures,
  jwt);

struct StartupConfig : CCFConfig
{
  // Only if joining or recovering
  std::vector<uint8_t> startup_snapshot = {};

  std::optional<size_t> startup_snapshot_evidence_seqno_for_1_x = std::nullopt;

  std::string startup_host_time;
  size_t snapshot_tx_interval = 10'000;

  // Only if starting or recovering
  size_t initial_service_certificate_validity_days = 1;
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

DECLARE_JSON_TYPE(StartupConfig::Start);
DECLARE_JSON_REQUIRED_FIELDS(
  StartupConfig::Start, members, constitution, service_configuration);

DECLARE_JSON_TYPE(StartupConfig::Join);
DECLARE_JSON_REQUIRED_FIELDS(
  StartupConfig::Join, target_rpc_address, retry_timeout, service_cert);

DECLARE_JSON_TYPE(StartupConfig::Recover);
DECLARE_JSON_REQUIRED_FIELDS(StartupConfig::Recover, previous_service_identity);

DECLARE_JSON_TYPE_WITH_BASE_AND_OPTIONAL_FIELDS(StartupConfig, CCFConfig);
DECLARE_JSON_REQUIRED_FIELDS(
  StartupConfig,
  startup_host_time,
  snapshot_tx_interval,
  initial_service_certificate_validity_days,
  service_data,
  node_data,
  start,
  join,
  recover);
DECLARE_JSON_OPTIONAL_FIELDS(
  StartupConfig, startup_snapshot_evidence_seqno_for_1_x);
