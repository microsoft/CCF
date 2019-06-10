// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "ds/json_schema.h"

#include <nlohmann/json.hpp>

namespace ccf
{
  struct GetCommit
  {
    struct In
    {
      std::optional<int64_t> commit = std::nullopt;
    };

    struct Out
    {
      uint64_t term;
      int64_t commit;
    };
  };

  struct GetMetrics
  {
    struct HistogramResults
    {
      int low = {};
      int high = {};
      size_t overflow = {};
      size_t underflow = {};
      nlohmann::json buckets = {};
    };

    struct Out
    {
      HistogramResults histogram;
      nlohmann::json tx_rates;
    };
  };

  struct GetLeaderInfo
  {
    struct Out
    {
      NodeId leader_id;
      std::string leader_host;
      std::string leader_port;
    };
  };

  struct ListMethods
  {
    struct Out
    {
      std::vector<std::string> methods;
    };
  };

  struct GetSchema
  {
    struct In
    {
      std::string method = {};
    };

    struct Out
    {
      JsonSchema params_schema = {};
      JsonSchema result_schema = {};
    };
  };
}