// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <cstdint>
#include <functional>
#include <vector>

namespace consensus
{
  // Retained so the ledger range read budget stays equal to the previous
  // ringbuffer-derived value (memory.max_msg_size minus this allowance) until
  // the memory configuration is removed.
  static constexpr size_t ledger_range_response_metadata_size = 2048;

  using Index = uint64_t;

  enum class LedgerRangeStatus : uint8_t
  {
    Found,
    NotFound,
    TooLarge,
  };

  struct LedgerRangeResult
  {
    Index from = 0;
    Index to = 0;
    LedgerRangeStatus status = LedgerRangeStatus::NotFound;
    std::vector<uint8_t> entries;
  };

  using LedgerRangeCallback = std::function<void(LedgerRangeResult&&)>;

  class AbstractLedgerWriter
  {
  public:
    virtual ~AbstractLedgerWriter() = default;

    virtual bool init(Index idx, Index recovery_start_idx) = 0;
    virtual bool append(std::vector<uint8_t>&& entry, bool committable) = 0;
    virtual bool truncate(Index idx, bool recovery_mode) = 0;
    virtual bool commit(Index idx) = 0;
    virtual bool open() = 0;
  };

  class AbstractLedgerReader
  {
  public:
    virtual ~AbstractLedgerReader() = default;

    virtual bool get_range(
      Index from, Index to, LedgerRangeCallback&& callback) = 0;
  };
}
