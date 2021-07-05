// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/receipt.h"
#include "ccf/tx_id.h"
#include "ds/json_schema.h"
#include "kv/kv_types.h"
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
    using In = void;

    struct Out
    {
      ccf::TxID transaction_id;
    };
  };

  struct GetTxStatus
  {
    struct Out
    {
      ccf::TxID transaction_id;
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
      crypto::Pem service_certificate;
      std::optional<ccf::View> current_view;
      std::optional<NodeId> primary_id;
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
    struct Out
    {
      std::vector<GetNode::NodeInfo> nodes = {};
    };
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
      size_t retries = 0;
    };

    struct Out
    {
      std::vector<Entry> metrics;
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

  struct UpdateIdentity
  {
    struct In
    {
      kv::ReconfigurationId rid;
    };
  };
}