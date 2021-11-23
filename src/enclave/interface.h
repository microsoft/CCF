// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
/* Definition of the call-in and call-out interfaces
 */
#pragma once

#include "consensus/consensus_types.h"
#include "consensus_type.h"
#include "crypto/curve.h"
#include "crypto/san.h"
#include "ds/buffer.h"
#include "ds/json.h"
#include "ds/logger.h"
#include "ds/oversized.h"
#include "ds/ring_buffer_types.h"
#include "kv/kv_types.h"
#include "node/config.h"
#include "node/members.h"
#include "node/node_info_network.h"
#include "reconfiguration_type.h"

#include <chrono>

namespace logger
{
#ifdef VERBOSE_LOGGING
  DECLARE_JSON_ENUM(
    Level,
    {{Level::TRACE, "trace"},
     {Level::DEBUG, "debug"},
     {Level::INFO, "info"},
     {Level::FAIL, "fail"},
     {Level::FATAL, "fatal"}});
#else
  DECLARE_JSON_ENUM(
    Level,
    {{Level::INFO, "info"}, {Level::FAIL, "fail"}, {Level::FATAL, "fatal"}});
#endif
}

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

// Common configuration struct
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

  struct Intervals
  {
    size_t signature_interval_size = 5000;
    size_t signature_interval_duration_ms = 1000;

    bool operator==(const Intervals&) const = default;
  };
  Intervals intervals = {};

  struct JWT
  {
    size_t key_refresh_interval_s = 1800;

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

DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCFConfig::Intervals);
DECLARE_JSON_REQUIRED_FIELDS(CCFConfig::Intervals);
DECLARE_JSON_OPTIONAL_FIELDS(
  CCFConfig::Intervals,
  signature_interval_size,
  signature_interval_duration_ms);

DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCFConfig::JWT);
DECLARE_JSON_REQUIRED_FIELDS(CCFConfig::JWT);
DECLARE_JSON_OPTIONAL_FIELDS(CCFConfig::JWT, key_refresh_interval_s);

DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCFConfig);
DECLARE_JSON_REQUIRED_FIELDS(CCFConfig, network);
DECLARE_JSON_OPTIONAL_FIELDS(
  CCFConfig, worker_threads, node_certificate, consensus, intervals, jwt);

struct StartupConfig : CCFConfig
{
  // Only if joining or recovering
  std::vector<uint8_t> startup_snapshot = {};

  std::optional<size_t> startup_snapshot_evidence_seqno_for_1_x = std::nullopt;

  std::string startup_host_time;
  size_t snapshot_tx_interval = 10'000;

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
    ccf::NodeInfoNetwork_v2::NetAddress target_rpc_address;
    size_t timer_ms = 1000;
    std::vector<uint8_t> network_cert = {};
  };
  Join join = {};
};

DECLARE_JSON_TYPE(StartupConfig::Start);
DECLARE_JSON_REQUIRED_FIELDS(
  StartupConfig::Start, members, constitution, service_configuration);

DECLARE_JSON_TYPE(StartupConfig::Join);
DECLARE_JSON_REQUIRED_FIELDS(
  StartupConfig::Join, target_rpc_address, timer_ms, network_cert);

DECLARE_JSON_TYPE_WITH_BASE_AND_OPTIONAL_FIELDS(StartupConfig, CCFConfig);
DECLARE_JSON_REQUIRED_FIELDS(
  StartupConfig,
  startup_snapshot,
  startup_host_time,
  snapshot_tx_interval,
  start,
  join);
DECLARE_JSON_OPTIONAL_FIELDS(
  StartupConfig, startup_snapshot_evidence_seqno_for_1_x);

enum class EnclaveType
{
  RELEASE,
  DEBUG,
  VIRTUAL
};

DECLARE_JSON_ENUM(
  EnclaveType,
  {{EnclaveType::RELEASE, "release"},
   {EnclaveType::DEBUG, "debug"},
   {EnclaveType::VIRTUAL, "virtual"}});

enum class LogFormat
{
  TEXT,
  JSON
};

DECLARE_JSON_ENUM(
  LogFormat, {{LogFormat::TEXT, "text"}, {LogFormat::JSON, "json"}});

struct ParsedMemberInfo
{
  std::string certificate_file;
  std::optional<std::string> encryption_public_key_file = std::nullopt;
  std::optional<std::string> data_json_file = std::nullopt;

  bool operator==(const ParsedMemberInfo& other) const = default;
};

DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(ParsedMemberInfo);
DECLARE_JSON_REQUIRED_FIELDS(ParsedMemberInfo, certificate_file);
DECLARE_JSON_OPTIONAL_FIELDS(
  ParsedMemberInfo, encryption_public_key_file, data_json_file);

// Host configuration
struct CCHostConfig : CCFConfig
{
  struct Enclave
  {
    std::string file;
    EnclaveType type = EnclaveType::RELEASE;
  };
  Enclave enclave = {};

  std::string node_certificate_file = "nodecert.pem";
  std::string node_pid_file = "cchost.pid";

  std::string network_certificate_file = "networkcert.pem";

  // Addresses files
  std::string node_address_file = "";
  std::string rpc_addresses_file = "";

  // Other
  size_t tick_period_ms = 10;
  size_t io_logging_threshold_ns = 10'000'000;
  std::optional<std::string> node_client_interface = std::nullopt;
  size_t client_connection_timeout_ms = 2000;

  struct Ledger
  {
    std::string directory = "ledger";
    std::vector<std::string> read_only_directories = {};
    size_t chunk_size = 5'000'000;

    bool operator==(const Ledger&) const = default;
  };
  Ledger ledger = {};

  struct Snapshots
  {
    std::string directory = "snapshots";
    size_t interval_size = 10'000;

    bool operator==(const Snapshots&) const = default;
  };
  Snapshots snapshots = {};

  struct Logging
  {
    logger::Level host_level = logger::Level::INFO;
    LogFormat format = LogFormat::TEXT;

    bool operator==(const Logging&) const = default;
  };
  Logging logging = {};

  struct Memory
  {
    size_t circuit_size_shift = 22;
    size_t max_msg_size_shift = 24;
    size_t max_fragment_size_shift = 16;

    bool operator==(const Memory&) const = default;
  };
  Memory memory = {};

  struct Start
  {
    std::vector<ParsedMemberInfo> members = {};
    std::vector<std::string> constitution_files = {};
    ccf::ServiceConfiguration service_configuration;

    bool operator==(const Start&) const = default;
  };
  Start start = {};

  struct Join
  {
    ccf::NodeInfoNetwork_v2::NetAddress target_rpc_address;
    size_t timer_ms = 1000;

    bool operator==(const Join&) const = default;
  };
  Join join = {};
};

DECLARE_JSON_TYPE(CCHostConfig::Enclave);
DECLARE_JSON_REQUIRED_FIELDS(CCHostConfig::Enclave, type, file);

DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCHostConfig::Ledger);
DECLARE_JSON_REQUIRED_FIELDS(CCHostConfig::Ledger);
DECLARE_JSON_OPTIONAL_FIELDS(
  CCHostConfig::Ledger, directory, read_only_directories, chunk_size);

DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCHostConfig::Snapshots);
DECLARE_JSON_REQUIRED_FIELDS(CCHostConfig::Snapshots);
DECLARE_JSON_OPTIONAL_FIELDS(CCHostConfig::Snapshots, directory, interval_size);

DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCHostConfig::Logging);
DECLARE_JSON_REQUIRED_FIELDS(CCHostConfig::Logging);
DECLARE_JSON_OPTIONAL_FIELDS(CCHostConfig::Logging, host_level, format);

DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCHostConfig::Memory);
DECLARE_JSON_REQUIRED_FIELDS(CCHostConfig::Memory);
DECLARE_JSON_OPTIONAL_FIELDS(
  CCHostConfig::Memory,
  circuit_size_shift,
  max_msg_size_shift,
  max_fragment_size_shift);

DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCHostConfig::Start);
DECLARE_JSON_REQUIRED_FIELDS(CCHostConfig::Start, members, constitution_files);
DECLARE_JSON_OPTIONAL_FIELDS(CCHostConfig::Start, service_configuration);

DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CCHostConfig::Join);
DECLARE_JSON_REQUIRED_FIELDS(CCHostConfig::Join, target_rpc_address);
DECLARE_JSON_OPTIONAL_FIELDS(CCHostConfig::Join, timer_ms);

DECLARE_JSON_TYPE_WITH_BASE_AND_OPTIONAL_FIELDS(CCHostConfig, CCFConfig);
DECLARE_JSON_REQUIRED_FIELDS(CCHostConfig, enclave);
DECLARE_JSON_OPTIONAL_FIELDS(
  CCHostConfig,
  node_certificate_file,
  node_pid_file,
  node_address_file,
  rpc_addresses_file,
  tick_period_ms,
  io_logging_threshold_ns,
  node_client_interface,
  client_connection_timeout_ms,
  network_certificate_file,
  ledger,
  snapshots,
  logging,
  memory,
  start,
  join);

/// General administrative messages
enum AdminMessage : ringbuffer::Message
{
  /// Log message. Enclave -> Host
  DEFINE_RINGBUFFER_MSG_TYPE(log_msg),

  /// Fatal error message. Enclave -> Host
  DEFINE_RINGBUFFER_MSG_TYPE(fatal_error_msg),

  /// Stop processing messages. Host -> Enclave
  DEFINE_RINGBUFFER_MSG_TYPE(stop),

  /// Stopped processing messages. Enclave -> Host
  DEFINE_RINGBUFFER_MSG_TYPE(stopped),

  /// Periodically update based on current time. Host -> Enclave
  DEFINE_RINGBUFFER_MSG_TYPE(tick),

  /// Notify the host of work done since last message. Enclave -> Host
  DEFINE_RINGBUFFER_MSG_TYPE(work_stats)
};

DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  AdminMessage::log_msg,
  std::chrono::microseconds::rep,
  std::string,
  size_t,
  logger::Level,
  uint16_t,
  std::string);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(AdminMessage::fatal_error_msg, std::string);
DECLARE_RINGBUFFER_MESSAGE_NO_PAYLOAD(AdminMessage::stop);
DECLARE_RINGBUFFER_MESSAGE_NO_PAYLOAD(AdminMessage::stopped);
DECLARE_RINGBUFFER_MESSAGE_NO_PAYLOAD(AdminMessage::tick);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(AdminMessage::work_stats, std::string);

/// Messages sent from app endpoints
enum AppMessage : ringbuffer::Message
{
  /// Start an arbitrary process on the host. Enclave -> Host
  DEFINE_RINGBUFFER_MSG_TYPE(launch_host_process)
};

DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  AppMessage::launch_host_process, std::string);

struct LaunchHostProcessMessage
{
  std::vector<std::string> args;
};

DECLARE_JSON_TYPE(LaunchHostProcessMessage);
DECLARE_JSON_REQUIRED_FIELDS(LaunchHostProcessMessage, args);
