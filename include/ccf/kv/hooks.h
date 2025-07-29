// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/kv/version.h"

#include <functional>
#include <memory>

namespace ccf::kv
{
  class ConfigurableConsensus;

  class ConsensusHook
  {
  public:
    virtual void call(ConfigurableConsensus*) = 0;
    virtual ~ConsensusHook() = default;
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