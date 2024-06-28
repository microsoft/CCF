// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/kv/hooks.h"
#include "ccf/kv/serialisers/serialised_entry.h"

#include <map>
#include <optional>

namespace ccf::kv::untyped
{
  // nullopt values represent deletions
  using Write = std::map<
    ccf::kv::serialisers::SerialisedEntry,
    std::optional<ccf::kv::serialisers::SerialisedEntry>>;

  using CommitHook = ccf::kv::CommitHook<Write>;
  using MapHook = ccf::kv::MapHook<Write>;
}