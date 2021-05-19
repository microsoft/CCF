// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include "ds/json.h"

#include <map>

namespace ccf
{
  struct SessionMetrics
  {
    struct Caps
    {
      size_t soft_cap;
      size_t hard_cap;
    };

    size_t active;
    size_t peak;
    std::map<std::string, Caps> interfaces;
  };

  DECLARE_JSON_TYPE(SessionMetrics::Caps)
  DECLARE_JSON_REQUIRED_FIELDS(
    SessionMetrics::Caps, soft_cap, hard_cap)
  DECLARE_JSON_TYPE(SessionMetrics)
  DECLARE_JSON_REQUIRED_FIELDS(
    SessionMetrics, active, peak, interfaces)
}