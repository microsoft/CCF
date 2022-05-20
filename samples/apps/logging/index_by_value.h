// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/indexing/strategies/visit_each_entry_in_map.h"

namespace loggingapp
{
  // Sample indexing policy which can construct an index by value. Takes a
  // functor which considers each write to a given table, and returns an
  // optional Category. Stores a map from each Category to each KvEntry where it
  // was present. Exposes a `get_entries_for_category` method for retrieval.
  // For instance, an app many/ parse the value as a JSON object, find a
  // specific field in it, and use that as the category.
  // Alternatively, it could create a category like "contains_foo" for every
  // value which contains the byte string "foo".
  // Note that this builds an in-memory index, so should be bucketed/chunked to
  // disk in the same way as SeqnosByKey_Bucketed.
  class IndexByValue : public ccf::indexing::strategies::VisitEachEntryInMap
  {
  public:
    using Category = std::string;
    using Categoriser = std::function<std::optional<Category>(
      const ccf::TxID& tx_id,
      const ccf::ByteVector& k,
      const ccf::ByteVector& v)>;

    struct KVEntry
    {
      const ccf::TxID tx_id;
      const ccf::ByteVector key;
      const ccf::ByteVector value;
    };

    IndexByValue(const std::string& map_name, const Categoriser& cat) :
      ccf::indexing::strategies::VisitEachEntryInMap(map_name, "IndexByValue"),
      categoriser(cat)
    {}

    void visit_entry(
      const ccf::TxID& tx_id,
      const ccf::ByteVector& k,
      const ccf::ByteVector& v) override
    {
      const auto category = categoriser(tx_id, k, v);
      if (category.has_value())
      {
        LOG_TRACE_FMT("Storing category {}", category.value());
        auto& cd = current[category.value()];
        cd.entries.emplace_back(KVEntry{tx_id, k, v});
      }
    }

    std::vector<KVEntry> get_entries_for_category(const Category& cat)
    {
      const auto it = current.find(cat);
      if (it != current.end())
      {
        LOG_TRACE_FMT(
          "Returning {} entries for category {}",
          it->second.entries.size(),
          cat);
        return it->second.entries;
      }
      LOG_TRACE_FMT(
        "Returning no entries for category {}", cat);
      return {};
    }

  protected:
    Categoriser categoriser;

    struct CategoryData
    {
      std::vector<KVEntry> entries = {};
    };
    std::unordered_map<Category, CategoryData> current;
  };
}