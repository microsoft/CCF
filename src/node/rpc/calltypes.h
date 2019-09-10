// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "ds/json_schema.h"
#include "node/networksecrets.h"

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

  struct GetPrimaryInfo
  {
    struct Out
    {
      NodeId primary_id;
      std::string primary_host;
      std::string primary_port;
    };
  };

  struct GetNetworkInfo
  {
    struct NodeInfo
    {
      NodeId node_id;
      std::string host;
      std::string port;
    };

    struct Out
    {
      std::vector<NodeInfo> nodes = {};
      std::optional<NodeId> primary_id = {};
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
      ds::json::JsonSchema params_schema = {};
      ds::json::JsonSchema result_schema = {};
    };
  };

  struct GetSignedIndex
  {
    using In = void;

    enum class State
    {
      ReadingPublicLedger,
      ReadingPrivateLedger,
      PartOfNetwork,
      PartOfPublicNetwork,
    };

    struct Out
    {
      State state;
      kv::Version signed_index;
    };
  };

  struct GetQuotes
  {
    using In = void;

    struct Quote
    {
      NodeId node_id = {};
      std::string raw = {};

      std::string error = {};
      std::string mrenclave = {};
    };

    struct Out
    {
      std::vector<Quote> quotes;
    };
  };

  struct JoinNetworkNodeToNode
  {
    struct In
    {
      std::vector<uint8_t> raw_fresh_key;
      NodeInfoNetwork node_info_network;
      std::vector<uint8_t> quote;
    };

    struct Out
    {
      NodeId id;
      NetworkSecrets::Secret network_secrets;
      int64_t version; // Current version of the network secrets
    };
  };
}