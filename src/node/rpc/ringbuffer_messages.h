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
  /// Periodically update based on current time. Host -> Enclave
  DEFINE_RINGBUFFER_MSG_TYPE(tick)
};

DECLARE_RINGBUFFER_MESSAGE_NO_PAYLOAD(AdminMessage::tick);
