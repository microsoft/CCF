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
#include "node/members.h"
#include "node/node_info_network.h"
#include "tls/tls.h"

#include <chrono>

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

struct CCFConfig
{
  // TODO: Rename most of these fields!
  consensus::Configuration consensus = {};
  ccf::NodeInfoNetwork network = {};

  size_t snapshot_tx_interval = 10'000; // TODO: Delete
  // TODO: Serialise
  struct Snapshots
  {
    size_t snapshot_tx_interval = 10'000;
    std::string snapshot_dir = "snapshots";
  };
  Snapshots snapshots = {};

  struct SignatureIntervals
  {
    size_t sig_tx_interval;
    size_t sig_ms_interval;
  };
  SignatureIntervals signature_intervals = {};

  struct Genesis
  {
    std::vector<ccf::NewMember> members_info;
    std::string constitution;
    size_t recovery_threshold;
    size_t max_allowed_node_cert_validity_days;
  };
  Genesis genesis = {};

  struct Joining
  {
    // TODO: Make one unique address
    std::string target_host;
    std::string target_port;
    std::vector<uint8_t> network_cert;
    size_t join_timer;
  };
  Joining joining = {}; // TODO: Rename

  crypto::CertificateSubjectIdentity node_certificate_subject_identity;
  size_t jwt_key_refresh_interval_s;
  crypto::CurveID curve_id;

  size_t initial_node_certificate_validity_period_days;
};

struct StartupConfig : CCFConfig
{
  // Only if joining or recovering
  std::vector<uint8_t> startup_snapshot;
  std::optional<size_t> startup_snapshot_evidence_seqno_for_1_x = std::nullopt;

  std::string startup_host_time;
};

DECLARE_JSON_TYPE(CCFConfig::SignatureIntervals);
DECLARE_JSON_REQUIRED_FIELDS(
  CCFConfig::SignatureIntervals, sig_tx_interval, sig_ms_interval);

DECLARE_JSON_TYPE(CCFConfig::Genesis);
DECLARE_JSON_REQUIRED_FIELDS(
  CCFConfig::Genesis,
  members_info,
  constitution,
  recovery_threshold,
  max_allowed_node_cert_validity_days);

DECLARE_JSON_TYPE(CCFConfig::Joining);
DECLARE_JSON_REQUIRED_FIELDS(
  CCFConfig::Joining, target_host, target_port, network_cert, join_timer);

DECLARE_JSON_TYPE(CCFConfig);
DECLARE_JSON_REQUIRED_FIELDS(
  CCFConfig,
  consensus,
  network,
  snapshot_tx_interval,
  signature_intervals,
  genesis,
  joining,
  node_certificate_subject_identity,
  jwt_key_refresh_interval_s,
  curve_id,
  initial_node_certificate_validity_period_days);

DECLARE_JSON_TYPE_WITH_BASE_AND_OPTIONAL_FIELDS(StartupConfig, CCFConfig);
DECLARE_JSON_REQUIRED_FIELDS(
  StartupConfig, startup_snapshot, startup_host_time);
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

struct CCHostConfig : CCFConfig
{
  std::string enclave_file;
  EnclaveType enclave_type = EnclaveType::RELEASE;

  size_t worker_threads = 0;

  std::string node_cert_file = "nodecert.pem";
  std::string node_pid_file = "cchost.pid";

  // Logging
  logger::Level host_log_level = logger::Level::INFO;
  bool log_format_json = false;

  // Other
  size_t tick_period_ms = 10;

  // struct Ledger
  // {
  //   std::string ledger_dir = "ledger";
  //   std::vector<std::string> read_only_ledger_dirs = {};
  //   size_t ledger_chunk_bytes = 5'000'000;
  // };
  // Ledger ledger = {};

  // // struct Snapshots
  // // {
  // //   std::string snapshot_dir = "snapshots";
  // //   size_t snapshot_tx_interval = 10'000;
  // // };
  // // Snapshots snapshots = {};

  // struct Memory
  // {
  //   size_t circuit_size = 2 << 22;
  //   size_t max_msg_size = 2 << 24;
  //   size_t max_fragment_size = 2 << 16;
  // };
  // Memory memory = {};
};

DECLARE_JSON_TYPE_WITH_BASE(CCHostConfig, CCFConfig);
// TODO: Should most of these fields actually be optional so we can have a
// minimal config?
DECLARE_JSON_REQUIRED_FIELDS(
  CCHostConfig,
  enclave_file,
  enclave_type,
  worker_threads,
  node_cert_file,
  node_pid_file,
  // host_log_level, // TODO: Tricky because of MACRO
  log_format_json,
  tick_period_ms)

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
