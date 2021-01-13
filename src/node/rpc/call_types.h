// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "ds/json_schema.h"
#include "kv/kv_types.h"
#include "metrics.h"
#include "node/code_id.h"
#include "node/identity.h"
#include "node/ledger_secrets.h"
#include "node/nodes.h"
#include "node_call_types.h"
#include "tx_status.h"

#include <nlohmann/json.hpp>

namespace ccf
{
  struct GetCommit
  {
    struct Out
    {
      kv::Consensus::View view;
      kv::Consensus::SeqNo seqno;
    };
  };

  struct GetTxStatus
  {
    struct In
    {
      kv::Consensus::View view;
      kv::Consensus::SeqNo seqno;
    };

    struct Out
    {
      TxStatus status;
    };
  };

  struct GetPrimaryInfo
  {
    struct Out
    {
      NodeId primary_id;
      std::string primary_host;
      std::string primary_port;
      kv::Consensus::View current_view;
    };
  };

  struct GetCode
  {
    struct Version
    {
      std::string digest;
      ccf::CodeStatus status;
    };

    struct Out
    {
      std::vector<GetCode::Version> versions = {};
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
      std::optional<NodeId> primary_id = std::nullopt;
    };
  };

  struct GetNodesByRPCAddress
  {
    struct NodeInfo
    {
      NodeId node_id;
      NodeStatus status;
    };

    struct In
    {
      std::string host;
      std::string port;
      bool retired = false;
    };

    struct Out
    {
      std::vector<NodeInfo> nodes = {};
    };
  };

  struct CallerInfo
  {
    CallerId caller_id;
  };

  struct GetUserId
  {
    struct In
    {
      std::string cert;
    };

    using Out = CallerInfo;
  };

  struct GetAPI
  {
    using Out = nlohmann::json;
  };

  struct EndpointMetrics
  {
    struct Metric
    {
      size_t calls = 0;
      size_t errors = 0;
      size_t failures = 0;
    };

    struct Out
    {
      std::map<std::string, std::map<std::string, Metric>> metrics;
    };
  };

  struct GetReceipt
  {
    struct In
    {
      int64_t commit = 0;
    };

    struct Out
    {
      std::vector<std::uint8_t> receipt = {};
    };
  };

  struct VerifyReceipt
  {
    struct In
    {
      std::vector<std::uint8_t> receipt = {};
    };

    struct Out
    {
      bool valid = false;
    };
  };
}