// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
/* Definition of the call-in and call-out interfaces
 */
#pragma once

#include "consensus/consensus_types.h"
#include "consensus_type.h"
#include "ds/buffer.h"
#include "ds/logger.h"
#include "ds/oversized.h"
#include "ds/ring_buffer_types.h"
#include "kv/kv_types.h"
#include "node/members.h"
#include "node/node_info_network.h"
#include "start_type.h"
#include "tls/tls.h"

#include <chrono>

struct EnclaveConfig
{
  ringbuffer::Circuit* circuit = nullptr;
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
  consensus::Config consensus_config = {};
  ccf::NodeInfoNetwork node_info_network = {};
  std::string domain;

  struct SignatureIntervals
  {
    size_t sig_max_tx;
    size_t sig_max_ms;
    MSGPACK_DEFINE(sig_max_tx, sig_max_ms);
  };
  SignatureIntervals signature_intervals = {};

  struct Genesis
  {
    std::vector<ccf::MemberPubInfo> members_info;
    std::string gov_script;
    size_t recovery_threshold;
    MSGPACK_DEFINE(members_info, gov_script, recovery_threshold);
  };
  Genesis genesis = {};

  struct Joining
  {
    std::string target_host;
    std::string target_port;
    std::vector<uint8_t> network_cert;
    size_t join_timer;
    MSGPACK_DEFINE(target_host, target_port, network_cert, join_timer);
  };
  Joining joining = {};

  MSGPACK_DEFINE(
    consensus_config,
    node_info_network,
    domain,
    signature_intervals,
    genesis,
    joining);
};

/// General administrative messages
enum AdminMessage : ringbuffer::Message
{
  /// Log message. Enclave -> Host
  DEFINE_RINGBUFFER_MSG_TYPE(log_msg),

  /// Fatal error message. Enclave -> Host
  DEFINE_RINGBUFFER_MSG_TYPE(fatal_error_msg),

  /// Sealing network secrets. Enclave -> Host
  DEFINE_RINGBUFFER_MSG_TYPE(sealed_secrets),

  /// Stop processing messages. Host -> Enclave
  DEFINE_RINGBUFFER_MSG_TYPE(stop),

  /// Send notification data. Enclave -> Host
  DEFINE_RINGBUFFER_MSG_TYPE(notification),

  /// Periodically update based on current time. Host -> Enclave
  DEFINE_RINGBUFFER_MSG_TYPE(tick)
};

DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  AdminMessage::log_msg,
  std::chrono::milliseconds,
  std::string,
  size_t,
  logger::Level,
  uint16_t,
  std::string);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(AdminMessage::fatal_error_msg, std::string);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  AdminMessage::sealed_secrets, kv::Version, std::vector<uint8_t>);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(AdminMessage::stop);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  AdminMessage::notification, std::vector<uint8_t>);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(AdminMessage::tick, size_t);
