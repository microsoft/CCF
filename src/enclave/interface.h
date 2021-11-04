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
#include "tls/tls.h"

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

#ifdef DEBUG_CONFIG
  struct DebugConfig
  {
    size_t memory_reserve_startup;
  };
  DebugConfig debug_config = {};
#endif
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
    std::vector<crypto::SubjectAltName> subject_alt_names = {};
    crypto::CurveID curve_id = crypto::CurveID::SECP384R1;
    size_t initial_validity_days = 1;
  };
  NodeCertificateInfo node_certificate = {};

  struct Intervals
  {
    size_t sig_tx_interval = 5000;
    size_t sig_ms_interval = 1000;
    size_t jwt_key_refresh_interval_s = 1800;
  };
  Intervals intervals = {};

  struct Join
  {
    ccf::NodeInfoNetwork_v2::NetAddress target_rpc_address;
    size_t join_timer_ms = 1000;
  };
  Join join = {};
};

DECLARE_JSON_TYPE(CCFConfig::Intervals);
DECLARE_JSON_REQUIRED_FIELDS(
  CCFConfig::Intervals,
  sig_tx_interval,
  sig_ms_interval,
  jwt_key_refresh_interval_s);

DECLARE_JSON_TYPE(CCFConfig::NodeCertificateInfo);
DECLARE_JSON_REQUIRED_FIELDS(
  CCFConfig::NodeCertificateInfo,
  subject_name,
  subject_alt_names,
  curve_id,
  initial_validity_days);

DECLARE_JSON_TYPE(CCFConfig::Join);
DECLARE_JSON_REQUIRED_FIELDS(
  CCFConfig::Join, target_rpc_address, join_timer_ms);

DECLARE_JSON_TYPE(CCFConfig);
DECLARE_JSON_REQUIRED_FIELDS(CCFConfig, consensus, network, intervals, join);

// Enclave configuration
struct StartupConfig : CCFConfig
{
  // Only if joining or recovering
  std::vector<uint8_t> startup_snapshot = {}; // TODO: Should this be optional?
  std::optional<size_t> startup_snapshot_evidence_seqno_for_1_x = std::nullopt;

  std::string startup_host_time;

  struct Start
  {
    std::vector<ccf::NewMember> members;
    std::string constitution;
    ccf::ServiceConfiguration service_configuration;
  };
  Start start = {};
};

DECLARE_JSON_TYPE(StartupConfig::Start);
DECLARE_JSON_REQUIRED_FIELDS(
  StartupConfig::Start, members, constitution, service_configuration);

DECLARE_JSON_TYPE_WITH_BASE_AND_OPTIONAL_FIELDS(StartupConfig, CCFConfig);
DECLARE_JSON_REQUIRED_FIELDS(
  StartupConfig, startup_snapshot, startup_host_time, start);
DECLARE_JSON_OPTIONAL_FIELDS(
  StartupConfig, startup_snapshot_evidence_seqno_for_1_x);

enum EnclaveType
{
  RELEASE,
  DEBUG,
  VIRTUAL
};

DECLARE_JSON_ENUM(
  EnclaveType,
  {{EnclaveType::RELEASE, "release"},
   {EnclaveType::DEBUG, "debug"},
   {EnclaveType::VIRTUAL, "virtual"}})

struct ParsedMemberInfo
{
  std::string certificate_file;
  std::optional<std::string> encryption_public_key_file = std::nullopt;
  std::optional<std::string> data_json_file = std::nullopt;
};

DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(ParsedMemberInfo);
DECLARE_JSON_REQUIRED_FIELDS(ParsedMemberInfo, certificate_file);
DECLARE_JSON_OPTIONAL_FIELDS(
  ParsedMemberInfo, encryption_public_key_file, data_json_file);

// Host configuration
struct CCHostConfig : CCFConfig
{
  std::string enclave_file;
  EnclaveType enclave_type = EnclaveType::RELEASE;

  std::string node_cert_file = "nodecert.pem";
  std::string node_pid_file = "cchost.pid";

  // Address files
  std::string node_address_file = "";
  std::string rpc_address_file = "";

  // Other
  size_t tick_period_ms = 1;
  size_t io_logging_threshold_ns = 10'000'000;
  std::optional<std::string> node_client_interface = std::nullopt;
  size_t client_connection_timeout_ms = 2000;

  std::string network_cert_file = "networkcert.pem";

  struct Ledger
  {
    std::string ledger_dir = "ledger";
    std::vector<std::string> read_only_ledger_dirs = {};
    size_t ledger_chunk_bytes = 5'000'000;
  };
  Ledger ledger = {};

  struct Snapshots
  {
    std::string snapshot_dir = "snapshots";
    size_t snapshot_tx_interval = 10'000;
  };
  Snapshots snapshots = {};

  struct Logging
  {
    logger::Level host_log_level = logger::Level::INFO;
    bool log_format_json = false;
  };
  Logging logging = {};

  struct Memory
  {
    size_t circuit_size_shift = 22;
    size_t max_msg_size_shift = 24;
    size_t max_fragment_size_shift = 16;
  };
  Memory memory = {};

  struct Start
  {
    std::vector<ParsedMemberInfo> members = {};
    std::vector<std::string> constitution_files = {};
    ccf::ServiceConfiguration service_configuration;
  };
  Start start = {};
};

DECLARE_JSON_TYPE(CCHostConfig::Ledger);
DECLARE_JSON_REQUIRED_FIELDS(
  CCHostConfig::Ledger, ledger_dir, read_only_ledger_dirs, ledger_chunk_bytes);

DECLARE_JSON_TYPE(CCHostConfig::Snapshots);
DECLARE_JSON_REQUIRED_FIELDS(
  CCHostConfig::Snapshots, snapshot_dir, snapshot_tx_interval);

DECLARE_JSON_TYPE(CCHostConfig::Logging);
DECLARE_JSON_REQUIRED_FIELDS(
  CCHostConfig::Logging, host_log_level, log_format_json);

DECLARE_JSON_TYPE(CCHostConfig::Memory);
DECLARE_JSON_REQUIRED_FIELDS(
  CCHostConfig::Memory,
  circuit_size_shift,
  max_msg_size_shift,
  max_fragment_size_shift);

DECLARE_JSON_TYPE_WITH_BASE(CCHostConfig, CCFConfig);
// TODO: Should most of these fields actually be optional so we can have a
// minimal config?
DECLARE_JSON_REQUIRED_FIELDS(
  CCHostConfig,
  enclave_file,
  enclave_type,
  node_cert_file,
  node_pid_file,
  node_address_file,
  rpc_address_file,
  tick_period_ms,
  io_logging_threshold_ns,
  node_client_interface,
  client_connection_timeout_ms,
  network_cert_file,
  ledger,
  snapshots,
  logging,
  memory);

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
