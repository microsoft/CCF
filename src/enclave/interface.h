// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/oversized.h"
#include "ds/ring_buffer_types.h"

#include <chrono>
#include <vector>

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

// ACME
enum ACMEMessage : ringbuffer::Message
{
  DEFINE_RINGBUFFER_MSG_TYPE(acme_challenge_response),
  DEFINE_RINGBUFFER_MSG_TYPE(acme_challenge_response_ack),
  DEFINE_RINGBUFFER_MSG_TYPE(acme_challenge_complete)
};

DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  ACMEMessage::acme_challenge_response, std::string);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  ACMEMessage::acme_challenge_response_ack, std::string);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  ACMEMessage::acme_challenge_complete, std::string);
