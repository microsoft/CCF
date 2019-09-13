// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
/* Definition of the call-in and call-out interfaces
 */
#pragma once

#include "consensus/raft/rafttypes.h"
#include "ds/buffer.h"
#include "ds/logger.h"
#include "ds/oversized.h"
#include "ds/ringbuffer_types.h"
#include "kv/kvtypes.h"
#include "node/nodeinfonetwork.h"
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
  raft::Config raft_config = {};
  ccf::NodeInfoNetwork node_info_network = {};

  struct SignatureIntervals
  {
    size_t sig_max_tx;
    size_t sig_max_ms;
    MSGPACK_DEFINE(sig_max_tx, sig_max_ms);
  };
  SignatureIntervals signature_intervals = {};

  struct Genesis
  {
    std::vector<std::vector<uint8_t>> member_certs;
    std::string gov_script;
    std::string app_script;
    MSGPACK_DEFINE(member_certs, gov_script, app_script);
  };
  Genesis genesis = {};

  struct Joining
  {
    std::string target_host;
    std::string target_port;
    std::vector<uint8_t> network_cert;
    MSGPACK_DEFINE(target_host, target_port, network_cert);
  };
  Joining joining = {};

  MSGPACK_DEFINE(
    raft_config, node_info_network, signature_intervals, genesis, joining);
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
  std::string);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(AdminMessage::fatal_error_msg, std::string);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  AdminMessage::sealed_secrets, kv::Version, std::vector<uint8_t>);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(AdminMessage::stop);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  AdminMessage::notification, std::vector<uint8_t>);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(AdminMessage::tick, size_t);
