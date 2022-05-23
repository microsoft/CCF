// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include "ccf/ds/json.h"

#include <map>

namespace ccf
{
  struct SessionMetrics
  {
    struct Errors
    {
      size_t parsing;
    };

    struct PerInterface
    {
      size_t active;
      size_t peak;
      size_t soft_cap;
      size_t hard_cap;
      Errors errors;
    };

    size_t active;
    size_t peak;
    std::map<std::string, PerInterface> interfaces;
  };

  DECLARE_JSON_TYPE(SessionMetrics::Errors)
  DECLARE_JSON_REQUIRED_FIELDS(SessionMetrics::Errors, parsing)

  DECLARE_JSON_TYPE(SessionMetrics::PerInterface)
  DECLARE_JSON_REQUIRED_FIELDS(
    SessionMetrics::PerInterface, active, peak, soft_cap, hard_cap, errors)
  DECLARE_JSON_TYPE(SessionMetrics)
  DECLARE_JSON_REQUIRED_FIELDS(SessionMetrics, active, peak, interfaces)
}