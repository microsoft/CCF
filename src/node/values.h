// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "service_map.h"

#include <exception>

namespace ccf
{
  using ValueId = uint8_t;
  using Value = uint64_t;

  // This table is only used to keep track of node IDs for the BFT variant of
  // the consensus
  using Values = ServiceMap<ValueId, Value>;

  enum ValueIds : ValueId
  {
    NEXT_NODE_ID = 0,
    // not to be used
    END_ID
  };

  /* returns the given value and increments it in the table.
  This is for example useful for getting a new member ID.
  */
  inline auto get_next_id(Values::Handle* handle, ValueId id)
  {
    auto search = handle->get(id);
    if (!search.has_value())
      throw std::logic_error("Failed to get next ID.");

    auto& v = search.value();
    auto nextId = v + 1;

    // overflow? (unlikely, but not impossible.)
    if (nextId < v)
      throw std::overflow_error("Overflow in ID");

    handle->put(id, nextId);
    return v;
  }
}