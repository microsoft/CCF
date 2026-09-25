// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/kv/abstract_handle.h"
#include "ccf/kv/serialisers/serialised_entry.h"
#include "ccf/kv/untyped.h"
#include "ccf/kv/version.h"

#include <functional>
#include <optional>
#include <string>

namespace ccf::kv::untyped
{
  struct ChangeSet;

  /** Read-only view of the changes made to a single map by the transaction
   * which committed at a given version.
   *
   * The diff is reconstructed from a change set created for it (see
   * ccf::kv::TxDiff): puts are the entries of the state which were written at
   * the change set's start version, and deletes are the keys listed in the
   * change set's writes. Nothing else is copied out of the underlying map.
   */
  class MapDiff : public ccf::kv::AbstractHandle
  {
  public:
    using KeyType = ccf::kv::serialisers::SerialisedEntry;
    using ValueType = ccf::kv::serialisers::SerialisedEntry;

    using ElementVisitor =
      std::function<void(const KeyType& k, const std::optional<ValueType>& V)>;

    using ElementVisitorWithEarlyOut =
      std::function<bool(const KeyType& k, const std::optional<ValueType>& V)>;

  protected:
    ccf::kv::untyped::ChangeSet& change_set;
    std::string map_name;

    void foreach_(const ElementVisitorWithEarlyOut& fn);

  public:
    MapDiff(ccf::kv::untyped::ChangeSet& cs, std::string map_name);

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