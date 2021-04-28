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

    /// Create and commit a snapshot. Enclave -> Host
    DEFINE_RINGBUFFER_MSG_TYPE(snapshot),
    DEFINE_RINGBUFFER_MSG_TYPE(snapshot_commit),
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
  consensus::snapshot,
  consensus::Index /* snapshot idx */,
  consensus::Index /* evidence idx */,
  std::vector<uint8_t>);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  consensus::snapshot_commit,
  consensus::Index /* snapshot idx */,
  consensus::Index /* evidence commit idx */);
