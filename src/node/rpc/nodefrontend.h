// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "../../crypto/hash.h"
#include "../../enclave/oe_shim.h"
#include "../entities.h"
#include "../quoteverification.h"
#include "frontend.h"

namespace ccf
{
  class NodesCallRpcFrontend : public RpcFrontend
  {
  public:
    NodesCallRpcFrontend(
      Store& tables, AbstractNodeState& node, NetworkState& network) :
      RpcFrontend(tables, nullptr, tables.get<Certs>(Tables::NODE_CERTS))
    {
      auto accept = [&node, &network](RequestArgs& args) {
        const auto in = args.params.get<JoinNetworkNodeToNode::In>();

        std::vector<uint8_t> caller_cert(args.rpc_ctx.caller_cert);

#ifdef GET_QUOTE
        QuoteVerificationResult verify_result =
          QuoteVerifier::verify_quote(args.tx, network, in.quote, caller_cert);

        if (verify_result != QuoteVerificationResult::VERIFIED)
          return QuoteVerifier::quote_verification_error_to_json(verify_result);
#else
        LOG_INFO_FMT("Skipped joining node quote verification");
#endif

        NodeId joining_node_id =
          get_next_id(args.tx.get_view(network.values), NEXT_NODE_ID);

        LOG_INFO_FMT(
          "Adding node, host:{}, port:{}",
          in.node_info_network.host,
          in.node_info_network.rpcport);

        auto nodes_view = args.tx.get_view(network.nodes);
        nodes_view->put(
          joining_node_id,
          {in.node_info_network.host,
           in.node_info_network.pubhost,
           in.node_info_network.nodeport,
           in.node_info_network.rpcport,
           caller_cert,
           in.quote,
           NodeStatus::PENDING});

        // Set joiner's fresh key for encrypting past network secrets
        node.set_joiner_key(joining_node_id, args.params["raw_fresh_key"]);

        // Send network secrets and NodeID
        return jsonrpc::success(nlohmann::json(
          JoinNetworkNodeToNode::Out{joining_node_id,
                                     network.secrets->get_current(),
                                     network.secrets->get_current_version()}));
      };

      install(NodeProcs::JOIN, accept, Write);
    }
  };
}
