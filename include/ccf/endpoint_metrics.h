// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once
#include "ccf/ds/json.h"

#include <vector>

namespace ccf
{
  struct EndpointMetricsEntry
  {
    /// Endpoint path
    std::string path;
    /// Endpoint method
    std::string method;
    /// Number of calls since node start
    size_t calls = 0;
    /// Number of errors (4xx) since node start
    size_t errors = 0;
    /// Number of failures (5xx) since node start
    size_t failures = 0;
    /// Number of transaction retries caused by
    /// conflicts since node start
    size_t retries = 0;
  };

  struct EndpointMetrics
  {
    /// Metrics for all endpoints in the frontend
    std::vector<EndpointMetricsEntry> metrics;
  };

  DECLARE_JSON_TYPE(EndpointMetricsEntry);
  DECLARE_JSON_REQUIRED_FIELDS(
    EndpointMetricsEntry, path, method, calls, errors, failures, retries);
  DECLARE_JSON_TYPE(EndpointMetrics);
  DECLARE_JSON_REQUIRED_FIELDS(EndpointMetrics, metrics);
}