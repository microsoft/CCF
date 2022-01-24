// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include "ds/json.h"

#include <map>

namespace ccf
{
  struct JWTMetrics
  {
    size_t attempts;
    size_t successes;
  };

  DECLARE_JSON_TYPE(JWTMetrics)
  DECLARE_JSON_REQUIRED_FIELDS(JWTMetrics, attempts, successes)
}