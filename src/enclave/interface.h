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
  /// Fatal error message. Enclave -> Host
  DEFINE_RINGBUFFER_MSG_TYPE(fatal_error_msg),

  /// Stop processing messages. Host -> Enclave
  DEFINE_RINGBUFFER_MSG_TYPE(stop),

  /// Will soon need to stop processing messages. Host -> Enclave
  DEFINE_RINGBUFFER_MSG_TYPE(stop_notice),

  /// Stopped processing messages. Enclave -> Host
  DEFINE_RINGBUFFER_MSG_TYPE(stopped),

  /// Periodically update based on current time. Host -> Enclave
  DEFINE_RINGBUFFER_MSG_TYPE(tick),

};

DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(AdminMessage::fatal_error_msg, std::string);
DECLARE_RINGBUFFER_MESSAGE_NO_PAYLOAD(AdminMessage::stop);
DECLARE_RINGBUFFER_MESSAGE_NO_PAYLOAD(AdminMessage::stop_notice);
DECLARE_RINGBUFFER_MESSAGE_NO_PAYLOAD(AdminMessage::stopped);
DECLARE_RINGBUFFER_MESSAGE_NO_PAYLOAD(AdminMessage::tick);
