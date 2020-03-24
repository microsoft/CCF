// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/ring_buffer_types.h"

namespace consensus
{
  using Index = uint64_t;
  /// Consensus-related ringbuffer messages
  enum : ringbuffer::Message
  {
    /// Request individual log entries. Enclave -> Host
    DEFINE_RINGBUFFER_MSG_TYPE(ledger_get),

    ///@{
    /// Respond to log_get. Host -> Enclave
    DEFINE_RINGBUFFER_MSG_TYPE(ledger_entry),
    DEFINE_RINGBUFFER_MSG_TYPE(ledger_no_entry),
    ///@}

    ///@{
    /// Modify the local log. Enclave -> Host
    DEFINE_RINGBUFFER_MSG_TYPE(ledger_append),
    DEFINE_RINGBUFFER_MSG_TYPE(ledger_truncate),
    ///@}
  };
}

DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(consensus::ledger_get, consensus::Index);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  consensus::ledger_entry, std::vector<uint8_t>);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(consensus::ledger_no_entry);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  consensus::ledger_append, std::vector<uint8_t>);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  consensus::ledger_truncate, consensus::Index);
