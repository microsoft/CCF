// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/node_subsystem_interface.h"

#include <atomic>
#include <memory>
#include <string>
#include <vector>

namespace ccf::indexing
{
  using LFSKey = std::string;
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
    std::atomic<FetchResultType> fetch_result = FetchResultType::Fetching;
    LFSKey key;
    LFSContents contents;
  };

  using FetchResultPtr = std::shared_ptr<FetchResult>;

  // Node-local authenticated plaintext for public-state indexes only.
  // Operations execute in submission order, including writes before reads
  // and replacement writes before obsolete-file deletion.
  class AbstractLFSAccess : public ccf::AbstractNodeSubSystem
  {
  public:
    static char const* get_subsystem_name()
    {
      return "LFSAccess";
    }

    virtual void store(const LFSKey& key, LFSContents&& contents) = 0;
    virtual FetchResultPtr fetch(const LFSKey& key) = 0;
    virtual void remove(const LFSKey& key) = 0;
  };
}
