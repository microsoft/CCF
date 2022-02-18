// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <functional>
#include <memory>

namespace kv
{
  using Version = uint64_t;

  class ConfigurableConsensus;

  class ConsensusHook
  {
  public:
    virtual void call(ConfigurableConsensus*) = 0;
    virtual ~ConsensusHook(){};
  };

  using ConsensusHookPtr = std::unique_ptr<ConsensusHook>;
  using ConsensusHookPtrs = std::vector<ConsensusHookPtr>;

  /// Signature for transaction commit handlers
  template <typename TWrites>
  using CommitHook = std::function<void(Version, const TWrites&)>;

  template <typename TWrites>
  using MapHook =
    std::function<std::unique_ptr<ConsensusHook>(Version, const TWrites&)>;
}