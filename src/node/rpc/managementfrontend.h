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
      auto get_signed_index = [&node, &tables](RequestArgs& args) {
        GetSignedIndex::Out result;
        if (node.is_reading_public_ledger())
        {
          result.state = GetSignedIndex::State::ReadingPublicLedger;
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
            jsonrpc::StandardErrorCodes::INVALID_REQUEST,
            "Network is not in recovery mode");
        }

        // TODO: Fix this
        // auto sig_view =
        //   args.tx.get_view(tables.get<Signatures>(Tables::SIGNATURES));

        // auto sig = sig_view->get(0);
        // if (!sig.has_value())
        result.signed_index = 0;
        // result.signed_index = sig.value().index;
        return jsonrpc::success(result);
      };

      auto get_quotes = [&node](RequestArgs& args) {
        GetQuotes::Out result;
        node.node_quotes(args.tx, result);

        return jsonrpc::success(result);
      };

      install_with_auto_schema<GetSignedIndex>(
        ManagementProcs::GET_SIGNED_INDEX, get_signed_index, Read);
      install_with_auto_schema<GetQuotes>(
        ManagementProcs::GET_QUOTES, get_quotes, Read);
    }
  };
}
