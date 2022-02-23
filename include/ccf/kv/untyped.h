// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/kv/hooks.h"
#include "ccf/kv/serialisers/serialised_entry.h"

#include <map>
#include <optional>

namespace kv::untyped
{
  // nullopt values represent deletions
  using Write = std::map<
    kv::serialisers::SerialisedEntry,
    std::optional<kv::serialisers::SerialisedEntry>>;

  using CommitHook = kv::CommitHook<Write>;
  using MapHook = kv::MapHook<Write>;
}