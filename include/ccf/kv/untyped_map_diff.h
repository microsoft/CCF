// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/kv/abstract_handle.h"
#include "ccf/kv/serialisers/serialised_entry.h"
#include "ccf/kv/version.h"

#include <functional>
#include <optional>
#include <string>

namespace kv::untyped
{
  struct ChangeSet;

  class MapDiff : public kv::AbstractHandle
  {
  public:
    using KeyType = kv::serialisers::SerialisedEntry;
    using ValueType = kv::serialisers::SerialisedEntry;

    using ElementVisitor =
      std::function<void(const KeyType& k, const std::optional<ValueType>& V)>;

    using ElementVisitorWithEarlyOut =
      std::function<bool(const KeyType& k, const std::optional<ValueType>& V)>;

  protected:
    kv::untyped::ChangeSet& tx_changes;
    std::string map_name;

    /** Get pointer to current value if this key exists, else nullptr if it does
     * not exist or has been deleted. If non-null, points to something owned by
     * tx_changes - expect this is used/dereferenced immediately, and there is
     * no concurrent access which could invalidate it. Modifies read set if
     * appropriate to record read dependency on this key, at the version of the
     * returned data.
     */
    const ValueType* read_key(const KeyType& key);

    void foreach_state_and_writes(
      const ElementVisitorWithEarlyOut& fn, bool always_consider_writes);

  public:
    MapDiff(kv::untyped::ChangeSet& cs, const std::string& map_name);

    std::optional<std::optional<ValueType>> get(const KeyType& key);

    bool has(const KeyType& key);

    bool is_deleted(const KeyType& key);

    size_t size();

    void foreach(const ElementVisitorWithEarlyOut& fn);

    // Sub-range variant of foreach. Visits the range of keys in [from, to).
    void range(
      const ElementVisitor& fn,
      const std::optional<KeyType>& from,
      const std::optional<KeyType>& to);
  };
}