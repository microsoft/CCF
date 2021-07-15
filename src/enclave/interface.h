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
  consensus::Configuration consensus_config = {};
  ccf::NodeInfoNetwork node_info_network = {};
  size_t snapshot_tx_interval;
  size_t max_open_sessions_soft;
  size_t max_open_sessions_hard;

  // Only if joining or recovering
  std::vector<uint8_t> startup_snapshot;
  size_t startup_snapshot_evidence_seqno;

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
  };
  Genesis genesis = {};

  struct Joining
  {
    std::string target_host;
    std::string target_port;
    std::vector<uint8_t> network_cert;
    size_t join_timer;
  };
  Joining joining = {};

  std::string subject_name;
  std::vector<crypto::SubjectAltName> subject_alternative_names;

  size_t jwt_key_refresh_interval_s;

  crypto::CurveID curve_id;
};

DECLARE_JSON_TYPE(CCFConfig::SignatureIntervals);
DECLARE_JSON_REQUIRED_FIELDS(
  CCFConfig::SignatureIntervals, sig_tx_interval, sig_ms_interval);

DECLARE_JSON_TYPE(CCFConfig::Genesis);
DECLARE_JSON_REQUIRED_FIELDS(
  CCFConfig::Genesis, members_info, constitution, recovery_threshold);

DECLARE_JSON_TYPE(CCFConfig::Joining);
DECLARE_JSON_REQUIRED_FIELDS(
  CCFConfig::Joining, target_host, target_port, network_cert, join_timer);

DECLARE_JSON_TYPE(CCFConfig);
DECLARE_JSON_REQUIRED_FIELDS(
  CCFConfig,
  consensus_config,
  node_info_network,
  snapshot_tx_interval,
  max_open_sessions_soft,
  max_open_sessions_hard,
  startup_snapshot,
  startup_snapshot_evidence_seqno,
  signature_intervals,
  genesis,
  joining,
  subject_name,
  subject_alternative_names,
  jwt_key_refresh_interval_s,
  curve_id);

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
