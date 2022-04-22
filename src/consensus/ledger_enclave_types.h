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
    /// Request range of ledger entries. Enclave -> Host
    DEFINE_RINGBUFFER_MSG_TYPE(ledger_get_range),

    /// Respond to ledger_get_range. Host -> Enclave
    DEFINE_RINGBUFFER_MSG_TYPE(ledger_entry_range),
    DEFINE_RINGBUFFER_MSG_TYPE(ledger_no_entry_range),

    /// Modify the local ledger. Enclave -> Host
    DEFINE_RINGBUFFER_MSG_TYPE(ledger_append),
    DEFINE_RINGBUFFER_MSG_TYPE(ledger_truncate),
    DEFINE_RINGBUFFER_MSG_TYPE(ledger_commit),
    DEFINE_RINGBUFFER_MSG_TYPE(ledger_init),
    DEFINE_RINGBUFFER_MSG_TYPE(ledger_open),

    /// Create and commit a snapshot. Enclave -> Host
    DEFINE_RINGBUFFER_MSG_TYPE(snapshot),
    DEFINE_RINGBUFFER_MSG_TYPE(snapshot_commit),
  };
}

DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  consensus::ledger_get_range,
  consensus::Index,
  consensus::Index,
  consensus::LedgerRequestPurpose);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  consensus::ledger_entry_range,
  consensus::Index,
  consensus::Index,
  consensus::LedgerRequestPurpose,
  std::vector<uint8_t>);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  consensus::ledger_no_entry_range,
  consensus::Index,
  consensus::Index,
  consensus::LedgerRequestPurpose);

DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  consensus::ledger_init,
  consensus::Index /* start idx */,
  consensus::Index /* recovery start idx */);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  consensus::ledger_append, bool /* committable */, std::vector<uint8_t>);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  consensus::ledger_truncate, consensus::Index, bool /* recovery mode */);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(consensus::ledger_commit, consensus::Index);
DECLARE_RINGBUFFER_MESSAGE_NO_PAYLOAD(consensus::ledger_open);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  consensus::snapshot,
  consensus::Index /* snapshot idx */,
  consensus::Index /* evidence idx */,
  std::vector<uint8_t>);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  consensus::snapshot_commit,
  consensus::Index /* snapshot idx */,
  std::vector<uint8_t> /* serialised receipt */);
