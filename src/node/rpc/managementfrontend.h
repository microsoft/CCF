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
        auto result = node.start_network(args.tx, args.params);
        if (result.second)
          return jsonrpc::success(result.first);

        return jsonrpc::error(
          jsonrpc::ErrorCodes::INTERNAL_ERROR,
          "Could not start network. Does tx0 have the right format?");
      };

      auto join = [&node](RequestArgs& args) {
        node.join_network(args.params);
        return jsonrpc::success();
      };

      auto get_signed_index = [&node](RequestArgs& args) {
        nlohmann::json result;
        if (node.is_reading_public_ledger())
        {
          result["state"] = "readingPublicLedger";
        }
        else if (node.is_awaiting_recovery())
        {
          result["state"] = "awaitingRecovery";
        }
        else if (node.is_reading_private_ledger())
        {
          result["state"] = "readingPrivateLedger";
        }
        else if (node.is_part_of_network())
        {
          result["state"] = "partOfNetwork";
        }
        else if (node.is_part_of_public_network())
        {
          result["state"] = "partOfPublicNetwork";
        }
        else
        {
          return jsonrpc::error(
            jsonrpc::ErrorCodes::INVALID_REQUEST,
            "Network is not in recovery mode");
        }

        result["signed_index"] = node.last_signed_index(args.tx);
        return jsonrpc::success(result);
      };

      auto set_recovery_nodes = [&node](RequestArgs& args) {
        if (node.is_awaiting_recovery())
        {
          std::vector<NodeInfo> nodes;
          for (const auto node :
               args.params.value("nodes", std::vector<nlohmann::json>()))
          {
            NodeInfo ni;
            try
            {
              from_json(node, ni);
            }
            catch (const std::exception& e)
            {
              std::stringstream ss;
              ss << "Failed to deserialise node definition: " << node << " : "
                 << e.what();
              return jsonrpc::error(
                jsonrpc::ErrorCodes::INVALID_REQUEST, ss.str());
            }
            nodes.push_back(ni);
          }
          auto network_cert = node.replace_nodes(args.tx, nodes);
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
        nlohmann::json response;
        node.node_quotes(args.tx, response);

        return jsonrpc::success(response);
      };

      install(ManagementProcs::START_NETWORK, start, Write);
      install(ManagementProcs::JOIN_NETWORK, join, Read);
      install(ManagementProcs::GET_SIGNED_INDEX, get_signed_index, Read);
      install(ManagementProcs::SET_RECOVERY_NODES, set_recovery_nodes, Write);
      install(ManagementProcs::GET_QUOTES, get_quotes, Read);
    }
  };
}
