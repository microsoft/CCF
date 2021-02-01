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
#include "node/service.h"
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
    struct Out
    {
      ServiceStatus service_status;
      std::optional<kv::Consensus::View> current_view;
      std::optional<NodeId> primary_id;
      std::optional<bool> view_change_in_progress;
    };
  };

  struct GetNode
  {
    struct NodeInfo
    {
      NodeId node_id;
      NodeStatus status;
      std::string host;
      std::string port;
      std::string local_host;
      std::string local_port;
      bool primary;
    };

    using Out = NodeInfo;
  };

  struct GetNodes
  {
    struct In
    {
      std::optional<std::string> host;
      std::optional<std::string> port;
      std::optional<NodeStatus> status;
    };

    struct Out
    {
      std::vector<GetNode::NodeInfo> nodes = {};
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
    struct Entry
    {
      std::string path;
      std::string method;
      size_t calls = 0;
      size_t errors = 0;
      size_t failures = 0;
    };

    struct Out
    {
      std::vector<Entry> metrics;
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

  struct GetRecoveryShare
  {
    using In = void;

    struct Out
    {
      std::string encrypted_share;
    };
  };

  struct SubmitRecoveryShare
  {
    struct In
    {
      std::string share;
    };

    struct Out
    {
      std::string message;
    };
  };
}