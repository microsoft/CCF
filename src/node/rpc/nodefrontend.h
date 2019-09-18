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
      RpcFrontend(tables, nullptr, tables.get<Certs>(Tables::NODE_CERTS), false)
    {
      auto accept = [&node, &network](RequestArgs& args) {
        const auto in = args.params.get<JoinNetworkNodeToNode::In>();

        // Convert caller cert from DER to PEM as PEM certificates are quoted
        auto caller_pem = tls::make_verifier({args.rpc_ctx.caller_cert.p,
                                              args.rpc_ctx.caller_cert.p +
                                                args.rpc_ctx.caller_cert.n})
                            ->cert_pem();
        std::vector<uint8_t> caller_pem_raw = {caller_pem.str().begin(),
                                               caller_pem.str().end()};

        auto nodes_view = args.tx.get_view(network.nodes);

        // Check that an active node with the same network info does not already
        // exist
        NodeId duplicate_node_id = NoNode;
        nodes_view->foreach(
          [&in, &duplicate_node_id](const NodeId& nid, const NodeInfo& ni) {
            if (
              in.node_info_network.nodeport == ni.nodeport &&
              in.node_info_network.host == ni.host &&
              ni.status != NodeStatus::RETIRED)
            {
              duplicate_node_id = nid;
              return false;
            }
            return true;
          });

        if (duplicate_node_id != NoNode)
        {
          return jsonrpc::error(
            jsonrpc::StandardErrorCodes::INVALID_PARAMS,
            fmt::format(
              "A node with the same node host {} and port {} already exists "
              "(node id: {})",
              in.node_info_network.host,
              in.node_info_network.nodeport,
              duplicate_node_id));
        }

#ifdef GET_QUOTE
        QuoteVerificationResult verify_result = QuoteVerifier::verify_quote(
          args.tx, network, in.quote, caller_pem_raw);

        if (verify_result != QuoteVerificationResult::VERIFIED)
          return QuoteVerifier::quote_verification_error_to_json(verify_result);
#else
        LOG_INFO_FMT("Skipped joining node quote verification");
#endif

        NodeId joining_node_id =
          get_next_id(args.tx.get_view(network.values), NEXT_NODE_ID);

        nodes_view->put(
          joining_node_id,
          {in.node_info_network,
           caller_pem_raw,
           in.quote,
           NodeStatus::TRUSTED});

        // Set joiner's fresh key for encrypting past network secrets
        node.set_joiner_key(joining_node_id, args.params["raw_fresh_key"]);

        LOG_INFO_FMT(
          "Adding node {}:{} as node {}",
          in.node_info_network.host,
          in.node_info_network.rpcport,
          joining_node_id);

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
