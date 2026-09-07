// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include <cstddef>
#include <cstdint>
#include <tav/cbor.hpp>
#include <utility>
#include <vector>

namespace ccf::cbor
{
  /// Copy an array, substituting one element.
  ///
  /// Values are immutable, so an edit rebuilds the container around the
  /// elements it keeps.
  inline tav::cbor::Value with_element(
    const tav::cbor::Value& array, size_t index, tav::cbor::Value replacement)
  {
    std::vector<tav::cbor::Value> items;
    items.reserve(array.size());
    for (size_t i = 0; i < array.size(); ++i)
    {
      items.push_back(i == index ? std::move(replacement) : array.array_at(i));
    }
    return tav::cbor::make_array(std::move(items));
  }

  /// Copy a map, substituting the value stored under an integer key.
  inline tav::cbor::Value with_entry(
    const tav::cbor::Value& map, int64_t key, tav::cbor::Value replacement)
  {
    std::vector<tav::cbor::MapItem> entries;
    entries.reserve(map.size());
    for (size_t i = 0; i < map.size(); ++i)
    {
      tav::cbor::Value existing = map.map_key_at(i);
      const bool matches = existing.kind() == tav::cbor::Kind::SIGNED &&
        existing.as_signed() == key;
      entries.emplace_back(
        std::move(existing),
        matches ? std::move(replacement) : map.map_value_at(i));
    }
    return tav::cbor::make_map(std::move(entries));
  }
}
