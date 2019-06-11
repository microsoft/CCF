// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "../entities.h"
#include "../nodestate.h"
#include "frontend.h"

namespace ccf
{
  class ManagementRpcFrontend : public RpcFrontend
  {
  public:
    ManagementRpcFrontend(Store& tables, NodeState& node) : RpcFrontend(tables)
    {
      auto start = [&node](RequestArgs& args) {
        const auto in = args.params.get<StartNetwork::In>();
        auto result = node.start_network(args.tx, in);
        if (result.second)
          return jsonrpc::success(result.first);

        return jsonrpc::error(
          jsonrpc::ErrorCodes::INTERNAL_ERROR,
          "Could not start network. Does tx0 have the right format?");
      };

      auto join = [&node](RequestArgs& args) {
        const auto in = args.params.get<JoinNetwork::In>();
        node.join_network(args.rpc_ctx, in);

        return jsonrpc::success();
      };

      auto get_signed_index = [&node](RequestArgs& args) {
        GetSignedIndex::Out result;
        if (node.is_reading_public_ledger())
        {
          result.state = GetSignedIndex::State::ReadingPublicLedger;
        }
        else if (node.is_awaiting_recovery())
        {
          result.state = GetSignedIndex::State::AwaitingRecovery;
        }
        else if (node.is_reading_private_ledger())
        {
          result.state = GetSignedIndex::State::ReadingPrivateLedger;
        }
        else if (node.is_part_of_network())
        {
          result.state = GetSignedIndex::State::PartOfNetwork;
        }
        else if (node.is_part_of_public_network())
        {
          result.state = GetSignedIndex::State::PartOfPublicNetwork;
        }
        else
        {
          return jsonrpc::error(
            jsonrpc::ErrorCodes::INVALID_REQUEST,
            "Network is not in recovery mode");
        }

        result.signed_index = node.last_signed_index(args.tx);
        return jsonrpc::success(result);
      };

      auto set_recovery_nodes = [&node](RequestArgs& args) {
        if (node.is_awaiting_recovery())
        {
          auto in = args.params.get<SetRecoveryNodes::In>();
          auto network_cert = node.replace_nodes(args.tx, in.nodes);
          return jsonrpc::success(network_cert);
        }
        else
        {
          return jsonrpc::error(
            jsonrpc::ErrorCodes::INVALID_REQUEST,
            "Network is not ready to recover");
        }
      };

      auto get_quotes = [&node](RequestArgs& args) {
        GetQuotes::Out result;
        node.node_quotes(args.tx, result);

        return jsonrpc::success(result);
      };

      install_with_auto_schema<StartNetwork>(
        ManagementProcs::START_NETWORK, start, Write);
      install_with_auto_schema<JoinNetwork>(
        ManagementProcs::JOIN_NETWORK, join, Read);
      install_with_auto_schema<GetSignedIndex>(
        ManagementProcs::GET_SIGNED_INDEX, get_signed_index, Read);
      install_with_auto_schema<SetRecoveryNodes>(
        ManagementProcs::SET_RECOVERY_NODES, set_recovery_nodes, Write);
      install_with_auto_schema<GetQuotes>(
        ManagementProcs::GET_QUOTES, get_quotes, Read);
    }
  };
}
