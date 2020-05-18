// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "entities.h"

#include <map>

namespace ccf
{
  // The key for this table will always be 0 as there can only be one recovery
  // happening at any given time
  // TODO: Use the member ID for key instead? Probably more efficient?

  using SubmittedShares =
    Store::Map<size_t, std::map<MemberId, std::vector<uint8_t>>>;
}