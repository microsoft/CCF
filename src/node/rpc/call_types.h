// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json_schema.h"
#include "ccf/receipt.h"
#include "ccf/service/tables/code_id.h"
#include "ccf/service/tables/nodes.h"
#include "ccf/tx_id.h"
#include "ccf/tx_status.h"
#include "kv/kv_types.h"
#include "node/identity.h"
#include "node/ledger_secrets.h"
#include "node_call_types.h"

#include <nlohmann/json.hpp>

namespace ccf
{
  struct GetCommit
  {
    using In = void;

    struct Out
    {
      ccf::TxID transaction_id;
      std::vector<std::pair<ccf::View, ccf::SeqNo>> view_history;
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
      std::vector<Version> versions = {};
    };
  };

  struct GetSnpHostDataMap
  {
    struct HostData
    {
      std::string raw;
      std::string metadata;
    };

    struct Out
    {
      std::vector<GetSnpHostDataMap::HostData> host_data = {};
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
      size_t recovery_count;
      nlohmann::json service_data;
      std::optional<ccf::TxID> current_service_create_txid;
    };
  };

  struct GetNode
  {
    struct NodeInfo
    {
      NodeId node_id;
      NodeStatus status;
      bool primary;
      ccf::NodeInfoNetwork::RpcInterfaces rpc_interfaces;
      nlohmann::json node_data;
      ccf::SeqNo last_written;
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

  struct UpdateResharing
  {
    struct In
    {
      kv::ReconfigurationId rid;
    };
  };
}
