// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/ledger_enclave_types.h"

#include <mutex>

namespace consensus::test
{
  class StubLedgerWriter : public AbstractLedgerWriter
  {
  public:
    struct Append
    {
      std::vector<uint8_t> entry;
      bool committable = false;
    };

    std::vector<Append> appends;
    std::vector<std::pair<Index, Index>> initialisations;
    std::vector<std::pair<Index, bool>> truncations;
    std::vector<Index> commits;
    size_t opens = 0;
    bool accepting = true;

    bool init(Index idx, Index recovery_start_idx) override
    {
      initialisations.emplace_back(idx, recovery_start_idx);
      return accepting;
    }

    bool append(std::vector<uint8_t>&& entry, bool committable) override
    {
      appends.push_back({std::move(entry), committable});
      return accepting;
    }

    bool truncate(Index idx, bool recovery_mode) override
    {
      truncations.emplace_back(idx, recovery_mode);
      return accepting;
    }

    bool commit(Index idx) override
    {
      commits.push_back(idx);
      return accepting;
    }

    bool open() override
    {
      ++opens;
      return accepting;
    }
  };

  class StubLedgerReader : public AbstractLedgerReader
  {
  public:
    struct Request
    {
      Index from = 0;
      Index to = 0;
      LedgerRangeCallback callback;
    };

  private:
    std::mutex lock;
    bool accepting = true;

  public:
    std::vector<Request> writes;

    bool get_range(
      Index from, Index to, LedgerRangeCallback&& callback) override
    {
      std::lock_guard guard(lock);
      if (!accepting)
      {
        return false;
      }
      writes.push_back({from, to, std::move(callback)});
      return true;
    }

    void stop()
    {
      std::lock_guard guard(lock);
      accepting = false;
      writes.clear();
    }

    [[nodiscard]] size_t size()
    {
      std::lock_guard guard(lock);
      return writes.size();
    }

    Request pop_request()
    {
      std::lock_guard guard(lock);
      if (writes.empty())
      {
        throw std::logic_error("No ledger request is pending");
      }

      auto request = std::move(writes.front());
      writes.erase(writes.begin());
      return request;
    }

    void respond(
      Request&& request, Index to, std::vector<uint8_t>&& entries = {})
    {
      const auto status = entries.empty() ? LedgerRangeStatus::NotFound :
                                            LedgerRangeStatus::Found;
      request.callback({request.from, to, status, std::move(entries)});
    }
  };
}
