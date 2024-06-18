// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/ring_buffer_types.h"

#include <span>

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

    /// Ask for host memory allocation and commit a snapshot. Enclave -> Host
    DEFINE_RINGBUFFER_MSG_TYPE(snapshot_allocate),
    DEFINE_RINGBUFFER_MSG_TYPE(snapshot_commit),

    /// Host -> Enclave
    DEFINE_RINGBUFFER_MSG_TYPE(snapshot_allocated),
  };
}

DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  ::consensus::ledger_get_range,
  ::consensus::Index,
  ::consensus::Index,
  ::consensus::LedgerRequestPurpose);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  ::consensus::ledger_entry_range,
  ::consensus::Index,
  ::consensus::Index,
  ::consensus::LedgerRequestPurpose,
  std::vector<uint8_t>);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  ::consensus::ledger_no_entry_range,
  ::consensus::Index,
  ::consensus::Index,
  ::consensus::LedgerRequestPurpose);

DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  ::consensus::ledger_init,
  ::consensus::Index /* start idx */,
  ::consensus::Index /* recovery start idx */);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  ::consensus::ledger_append, bool /* committable */, std::vector<uint8_t>);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  ::consensus::ledger_truncate, ::consensus::Index, bool /* recovery mode */);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  ::consensus::ledger_commit, ::consensus::Index);
DECLARE_RINGBUFFER_MESSAGE_NO_PAYLOAD(::consensus::ledger_open);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  ::consensus::snapshot_allocate,
  ::consensus::Index /* snapshot idx */,
  ::consensus::Index /* evidence idx */,
  size_t /* size to allocate */,
  uint32_t /* unique request id */);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  ::consensus::snapshot_allocated,
  std::span<uint8_t>, /* span to host-allocated memory for snapshot */
  uint32_t /* unique request id */);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  ::consensus::snapshot_commit,
  ::consensus::Index /* snapshot idx */,
  std::vector<uint8_t> /* serialised receipt */);
