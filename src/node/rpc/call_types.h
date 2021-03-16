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
    struct Out
    {
      kv::Consensus::View view;
      kv::Consensus::SeqNo seqno;
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

  struct CallerInfo
  {
    EntityId caller_id;
  };

  struct GetCallerId
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
      size_t retries = 0;
    };

    struct Out
    {
      std::vector<Entry> metrics;
    };
  };

  struct GetReceipt
  {
    struct Element
    {
      std::optional<std::string> left = std::nullopt;
      std::optional<std::string> right = std::nullopt;
    };

    struct Out
    {
      std::string signature;
      std::string root;
      std::vector<Element> proof = {};
      std::string leaf;
      ccf::NodeId node_id;

      void from_receipt(const historical::TxReceiptPtr& r)
      {
        signature = tls::b64_from_raw(r->signature);
        root = r->root.to_string();
        for (const auto& node : *r->path)
        {
          Element n;
          if (node.direction == ccf::HistoryTree::Path::Direction::PATH_LEFT)
          {
            n.left = node.hash.to_string();
          }
          else
          {
            n.right = node.hash.to_string();
          }
          proof.emplace_back(std::move(n));
        }
        leaf = r->path->leaf().to_string();
        node_id = r->node_id;
      }
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