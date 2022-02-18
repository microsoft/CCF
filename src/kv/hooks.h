// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <functional>
#include <memory>

namespace kv
{
  /// Signature for transaction commit handlers
  template <typename TWrites>
  using CommitHook = std::function<void(Version, const TWrites&)>;

  template <typename TWrites>
  using MapHook =
    std::function<std::unique_ptr<ConsensusHook>(Version, const TWrites&)>;
}