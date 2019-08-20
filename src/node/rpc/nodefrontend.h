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
        // TODO: For now, disable quote verificatin.
        // Indeed, as we no longer look up the certificate of the node from the
        // KV (PEM format) but instead rely on the caller_cert from the TLS
        // connection (DER format), we need to transform the caller_cert to PEM
        // to check that the hashes match.

        // QuoteVerificationResult verify_result =
        //   QuoteVerifier::verify_quote(args.tx, network, in.quote,
        //   caller_cert);
        QuoteVerificationResult verify_result =
          QuoteVerificationResult::VERIFIED;

        if (verify_result != QuoteVerificationResult::VERIFIED)
          return QuoteVerifier::quote_verification_error_to_json(verify_result);
#else
        LOG_INFO_FMT("Skipped joining node quote verification");
#endif

        NodeId joining_node_id =
          get_next_id(args.tx.get_view(network.values), NEXT_NODE_ID);

        LOG_INFO_FMT(
          "Adding node, host:{}, port:{}",
          in.node_info.host,
          in.node_info.rpcport);

        auto nodes_view = args.tx.get_view(network.nodes);
        nodes_view->put(
          joining_node_id,
          {in.node_info.host,
           in.node_info.pubhost,
           in.node_info.nodeport,
           in.node_info.rpcport,
           caller_cert,
           in.quote,
           NodeStatus::PENDING});

        // Set joiner's fresh key for encrypting past network secrets
        node.set_joiner_key(joining_node_id, args.params["raw_fresh_key"]);

        //         // Retrieve joining node's cert and quote
        //         auto nodes_view = args.tx.get_view(network.nodes);
        //         auto joining_nodeinfo =
        //         nodes_view->get(args.caller_id).value();

        // #ifdef GET_QUOTE
        //         QuoteVerificationResult verify_result =
        //         QuoteVerifier::verify_quote(
        //           args.tx, network, joining_nodeinfo.quote,
        //           joining_nodeinfo.cert);

        //         if (verify_result != QuoteVerificationResult::VERIFIED)
        //           return
        //           QuoteVerifier::quote_verification_error_to_json(verify_result);
        // #else
        //         LOG_INFO_FMT("Skipped joining node quote verification");
        // #endif

        // TODO(#important,#TR): In addition to verifying the quote, we should
        // go through a round of governance before marking the node as TRUSTED
        // (section IV-D).
        // joining_nodeinfo.status = NodeStatus::TRUSTED;
        // nodes_view->put(args.caller_id, joining_nodeinfo);

        // LOG_INFO_FMT(
        //   "Accepting a new node to the network as node {}", args.caller_id);

        // // Set joiner's fresh key for encrypting past network secrets
        // node.set_joiner_key(args.caller_id, args.params["raw_fresh_key"]);

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
