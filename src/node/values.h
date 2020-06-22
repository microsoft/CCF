// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv/map.h"

#include <exception>

namespace ccf
{
  using ValueId = uint8_t;
  using Value = uint64_t;
  using Values = kv::Map<ValueId, Value>;

  enum ValueIds : ValueId
  {
    NEXT_MEMBER_ID = 0,
    NEXT_USER_ID = 1,
    NEXT_NODE_ID = 2,
    NEXT_PROPOSAL_ID = 3,
    NEXT_CODE_ID = 4,
    // not to be used
    END_ID
  };

  /* returns the given value and increments it in the table.
  This is for example useful for getting a new member ID.
  */
  inline auto get_next_id(Values::TxView* view, ValueId id)
  {
    auto search = view->get(id);
    if (!search.has_value())
      throw std::logic_error("Failed to get next ID.");

    auto& v = search.value();
    auto nextId = v + 1;

    // overflow? (unlikely, but not impossible.)
    if (nextId < v)
      throw std::overflow_error("Overflow in ID");

    view->put(id, nextId);
    return v;
  }
}