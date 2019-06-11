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
        // Retrieve joining node's cert and quote
        auto nodes_view = args.tx.get_view(network.nodes);
        auto joining_nodeinfo = nodes_view->get(args.caller_id).value();

#ifdef GET_QUOTE
        QuoteVerificationResult verify_result = QuoteVerifier::verify_quote(
          args.tx, network, joining_nodeinfo.quote, joining_nodeinfo.cert);

        if (verify_result != QuoteVerificationResult::VERIFIED)
          return QuoteVerifier::quote_verification_error_to_json(verify_result);
#else
        LOG_INFO << "Skipped joining node quote verification." << std::endl;
#endif

        // TODO(#important,#TR): In addition to verifying the quote, we should
        // go through a round of governance before marking the node as TRUSTED
        // (section IV-D).
        joining_nodeinfo.status = NodeStatus::TRUSTED;
        nodes_view->put(args.caller_id, joining_nodeinfo);

        LOG_INFO << "Accepting a new node to the network as node "
                 << args.caller_id << std::endl;

        // Set joiner's fresh key for encrypting past network secrets
        node.set_joiner_key(args.caller_id, args.params["raw_fresh_key"]);

        // Send network secrets and NodeID
        return jsonrpc::success(nlohmann::json(
          JoinNetworkNodeToNode::Out{args.caller_id,
                                     network.secrets->get_current(),
                                     network.secrets->get_current_version()}));
      };

      install(NodeProcs::JOIN, accept, Write);
    }
  };
}
