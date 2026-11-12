// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/node_subsystem_interface.h"

#include <atomic>
#include <limits>
#include <memory>
#include <string>
#include <vector>

/// Defines a simple Large-File System (LFS) interface for offloading large
/// blobs of data to the host, and later requesting them asynchronously. These
/// blobs will be encrypted, so may contain secret data. Only files written by
/// this node can be read by this node.
namespace ccf::indexing
{
  using LFSKey = std::string;
  using LFSEncryptedContents = std::vector<uint8_t>;
  using LFSContents = std::vector<uint8_t>;

  struct FetchResult
  {
    enum class FetchResultType : uint8_t
    {
      Fetching,
      Loaded,
      NotFound,
      Corrupt,
    };
    std::atomic<FetchResultType> fetch_result;

    LFSKey key;

    LFSContents contents;
  };

  using FetchResultPtr = std::shared_ptr<FetchResult>;

  enum class LFSBatchStatus : uint8_t
  {
    Pending,
    Complete,
    Failed,
  };
  using LFSBatchResult = std::shared_ptr<std::atomic<LFSBatchStatus>>;
  using LFSWrites = std::vector<std::pair<LFSKey, LFSContents>>;

  class AbstractLFSAccess : public ccf::AbstractNodeSubSystem
  {
  public:
    ~AbstractLFSAccess() override = default;

    static char const* get_subsystem_name()
    {
      return "LFSAccess";
    }

    virtual void store(const LFSKey& key, LFSContents&& contents) = 0;
    // Bound plaintext size before allocating a host-supplied file. Requests
    // for the same key and bound may be coalesced.
    virtual FetchResultPtr fetch(
      const LFSKey& key,
      size_t max_bytes = std::numeric_limits<size_t>::max()) = 0;

    // Ordered with store/fetch. Completion includes all writes and removals,
    // not fsync durability. Callers must stop using removed keys before submit.
    // Failure may leave a partially applied batch; callers must fail closed.
    virtual LFSBatchResult apply_batch(
      LFSWrites&& writes, std::vector<LFSKey>&& removals) = 0;
  };
}
