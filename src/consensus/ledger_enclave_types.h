// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/ring_buffer_types.h"

namespace consensus
{
  using Index = uint64_t;

  enum LedgerRequestPurpose : uint8_t
  {
    Recovery,
    HistoricalQuery,
  };

  /// Consensus-related ringbuffer messages
  enum : ringbuffer::Message
  {
    /// Request individual ledger entries. Enclave -> Host
    DEFINE_RINGBUFFER_MSG_TYPE(ledger_get),

    /// Respond to ledger_get. Host -> Enclave
    DEFINE_RINGBUFFER_MSG_TYPE(ledger_entry),
    DEFINE_RINGBUFFER_MSG_TYPE(ledger_no_entry),

    /// Modify the local ledger. Enclave -> Host
    DEFINE_RINGBUFFER_MSG_TYPE(ledger_append),
    DEFINE_RINGBUFFER_MSG_TYPE(ledger_truncate),
    DEFINE_RINGBUFFER_MSG_TYPE(ledger_commit),
    DEFINE_RINGBUFFER_MSG_TYPE(ledger_init),

    /// Create a new snapshot. Enclave -> Host
    DEFINE_RINGBUFFER_MSG_TYPE(ledger_snapshot),
  };
}

DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  consensus::ledger_get, consensus::Index, consensus::LedgerRequestPurpose);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  consensus::ledger_entry,
  consensus::Index,
  consensus::LedgerRequestPurpose,
  std::vector<uint8_t>);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  consensus::ledger_no_entry,
  consensus::Index,
  consensus::LedgerRequestPurpose);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(consensus::ledger_init, consensus::Index);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  consensus::ledger_append,
  bool /* committable */,
  bool /* force chunk */,
  std::vector<uint8_t>);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  consensus::ledger_truncate, consensus::Index);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(consensus::ledger_commit, consensus::Index);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  consensus::ledger_snapshot, consensus::Index, std::vector<uint8_t>);
