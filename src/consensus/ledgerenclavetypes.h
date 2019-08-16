// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/ringbuffer_types.h"

namespace consensus
{
  using Index = uint64_t;
  /// Consensus-related ringbuffer messages
  enum : ringbuffer::Message
  {
    /// Request individual log entries. Enclave -> Host
    DEFINE_RINGBUFFER_MSG_TYPE(log_get),

    ///@{
    /// Respond to log_get. Host -> Enclave
    DEFINE_RINGBUFFER_MSG_TYPE(log_entry),
    DEFINE_RINGBUFFER_MSG_TYPE(log_no_entry),
    ///@}

    ///@{
    /// Modify the local log. Enclave -> Host
    DEFINE_RINGBUFFER_MSG_TYPE(log_append),
    DEFINE_RINGBUFFER_MSG_TYPE(log_truncate),
    ///@}
  };
}

DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(consensus::log_get, consensus::Index);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(consensus::log_entry, std::vector<uint8_t>);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(consensus::log_no_entry);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(consensus::log_append, std::vector<uint8_t>);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(consensus::log_truncate, consensus::Index);
