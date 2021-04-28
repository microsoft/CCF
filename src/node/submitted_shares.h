// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "entities.h"
#include "service_map.h"

#include <vector>

namespace ccf
{
  // This table keeps track of the submitted encrypted recovery share so that
  // the public-only service is resilient to elections while members submit
  // their recovery shares.
  // Because shares are submitted to the public-only network on recovery, this
  // table is public but the shares are encrypted with the latest ledger secret.

  using SubmittedShares = ServiceMap<MemberId, std::vector<uint8_t>>;
}