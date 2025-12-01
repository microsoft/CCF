// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/node_subsystem_interface.h"

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
    enum class FetchResultType: uint8_t
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

  class AbstractLFSAccess : public ccf::AbstractNodeSubSystem
  {
  public:
    ~AbstractLFSAccess() override = default;

    static char const* get_subsystem_name()
    {
      return "LFSAccess";
    }

    virtual void store(const LFSKey& key, LFSContents&& contents) = 0;
    virtual FetchResultPtr fetch(const LFSKey& key) = 0;
  };
}
