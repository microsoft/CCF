// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "crypto/hash.h"
#include "frontend.h"
#include "node/entities.h"
#include "node/networkstate.h"
#include "node/quoteverification.h"

namespace ccf
{
  class NodeCallRpcFrontend : public RpcFrontend
  {
  private:
    NetworkState& network;
    AbstractNodeState& node;

    std::optional<NodeId> check_already_trusted(
      Store::Tx& tx, std::vector<uint8_t>& node_pem)
    {
      auto nodes_view = tx.get_view(network.nodes);

      std::optional<NodeId> existing_node_id;
      nodes_view->foreach(
        [&existing_node_id, &node_pem](const NodeId& nid, const NodeInfo& ni) {
          if (ni.cert == node_pem && ni.status == NodeStatus::TRUSTED)
          {
            existing_node_id = nid;
            return false;
          }
          return true;
        });

      return existing_node_id;
    }

    std::optional<NodeId> check_conflicting_node_network(
      Store::Tx& tx, const NodeInfoNetwork& node_info_network)
    {
      auto nodes_view = tx.get_view(network.nodes);

      std::optional<NodeId> duplicate_node_id;
      nodes_view->foreach([&node_info_network, &duplicate_node_id](
                            const NodeId& nid, const NodeInfo& ni) {
        if (
          node_info_network.nodeport == ni.nodeport &&
          node_info_network.host == ni.host && ni.status != NodeStatus::RETIRED)
        {
          duplicate_node_id = nid;
          return false;
        }
        return true;
      });

      return duplicate_node_id;
    }

  public:
    NodeCallRpcFrontend(NetworkState& network, AbstractNodeState& node) :
      RpcFrontend(*network.tables, nullptr, &network.node_certs, false),
      network(network),
      node(node)
    {
      auto accept = [this](RequestArgs& args) {
        const auto in = args.params.get<JoinNetworkNodeToNode::In>();

        auto [nodes_view, service_view] =
          args.tx.get_view(this->network.nodes, this->network.service);

        auto active_service = service_view->get(0);
        if (!active_service.has_value())
          return jsonrpc::error(
            jsonrpc::StandardErrorCodes::INTERNAL_ERROR,
            "No service is available to add new node");

        // Convert caller cert from DER to PEM as PEM certificates
        // are quoted
        auto caller_pem = tls::make_verifier({args.rpc_ctx.caller_cert.p,
                                              args.rpc_ctx.caller_cert.p +
                                                args.rpc_ctx.caller_cert.n})
                            ->cert_pem();
        std::vector<uint8_t> caller_pem_raw = {caller_pem.str().begin(),
                                               caller_pem.str().end()};

        // TODO: Only verify the quote if the node is not known?
#ifdef GET_QUOTE
        QuoteVerificationResult verify_result = QuoteVerifier::verify_quote(
          args.tx, network, in.quote, caller_pem_raw);

        if (verify_result != QuoteVerificationResult::VERIFIED)
          return QuoteVerifier::quote_verification_error_to_json(verify_result);
#else
        LOG_INFO_FMT("Skipped joining node quote verification");
#endif

        // TODO:
        // 1. If service is opening, trust straight away
        // 2. If service is open
        //    i.   If node is not known in KV, add as PENDING
        //    ii.  If node is known in state PENDING, return still PENDING
        //    iii. If node is known in state TRUSTED, return NS and node id

        if (active_service->status == ServiceStatus::OPENING)
        {
          auto existing_node_id =
            check_already_trusted(args.tx, caller_pem_raw);
          if (existing_node_id.has_value())
            return jsonrpc::success<JoinNetworkNodeToNode::Out>(
              {NodeStatus::TRUSTED,
               existing_node_id.value(),
               {this->network.secrets->get_current(),
                this->network.secrets->get_current_version()}});

          // Check that an active node with the same network info does not
          // already exist
          auto conflicting_node_id =
            check_conflicting_node_network(args.tx, in.node_info_network);
          if (conflicting_node_id.has_value())
          {
            return jsonrpc::error(
              jsonrpc::StandardErrorCodes::INVALID_PARAMS,
              fmt::format(
                "A node with the same node host {} and port {} already "
                "exists "
                "(node id: {})",
                in.node_info_network.host,
                in.node_info_network.nodeport,
                conflicting_node_id.value()));
          }

          // Assign joining node a new NodeId
          NodeId joining_node_id =
            get_next_id(args.tx.get_view(this->network.values), NEXT_NODE_ID);

          // Add as TRUSTED
          nodes_view->put(
            joining_node_id,
            {in.node_info_network,
             caller_pem_raw,
             in.quote,
             NodeStatus::TRUSTED});

          // Set joiner's fresh key for encrypting past network
          // secrets
          this->node.set_joiner_key(
            joining_node_id, args.params["raw_fresh_key"]);

          return jsonrpc::success<JoinNetworkNodeToNode::Out>(
            {NodeStatus::TRUSTED,
             joining_node_id,
             {this->network.secrets->get_current(),
              this->network.secrets->get_current_version()}});
        }
        else if (active_service->status == ServiceStatus::OPEN)
        {
          // Check that an active node with the same network info does not
          // already exist
          auto conflicting_node_id =
            check_conflicting_node_network(args.tx, in.node_info_network);
          if (conflicting_node_id.has_value())
          {
            return jsonrpc::error(
              jsonrpc::StandardErrorCodes::INVALID_PARAMS,
              fmt::format(
                "A node with the same node host {} and port {} already "
                "exists "
                "(node id: {})",
                in.node_info_network.host,
                in.node_info_network.nodeport,
                conflicting_node_id.value()));
          }

          // Assign joining node a new NodeId
          NodeId joining_node_id =
            get_next_id(args.tx.get_view(this->network.values), NEXT_NODE_ID);

          // Add as PENDING
          nodes_view->put(
            joining_node_id,
            {in.node_info_network,
             caller_pem_raw,
             in.quote,
             NodeStatus::PENDING});

          // Set joiner's fresh key for encrypting past network
          // secrets
          this->node.set_joiner_key(
            joining_node_id, args.params["raw_fresh_key"]);

          return jsonrpc::success<JoinNetworkNodeToNode::Out>(
            {NodeStatus::PENDING, joining_node_id});

          // Lookup node in KV from caller cert
          // std::optional<NodeId> existing_node_id;
          // nodes_view->foreach([&existing_node_id, &caller_pem_raw,
          // &this->node](
          //                       const NodeId& nid, const NodeInfo& ni) {
          //   if (ni.cert == caller_pem_raw)
          //   {
          //     existing_node_id = nid;
          //     return false;
          //   }
          //   return true;
          // });

          // // If the joining node already exists in status PENDING
          // if (existing_node_id.has_value())
          // {
          // }
          // else
          // {
          //   // If the joining node does not already exist, add node
          //   // as PENDING

          //   // Assign joining node a new NodeId
          //   NodeId joining_node_id =
          //     get_next_id(args.tx.get_view(network.values), NEXT_NODE_ID);

          //   // Add as PENDING
          //   nodes_view->put(
          //     joining_node_id,
          //     {in.node_info_network,
          //      caller_pem_raw,
          //      in.quote,
          //      NodeStatus::PENDING});

          //   // Set joiner's fresh key for encrypting past network
          //   // secrets
          //   node.set_joiner_key(joining_node_id,
          //   args.params["raw_fresh_key"]);

          //   // return jsonrpc::success();
        }

        // if (caller_id.has_value())
        // {
        //   if (TRUSTED)
        //   {
        //   }
        //   else if (PENDING)
        //   {}
        // }
        // else
        // {}

        // // Lookup node in KV from caller_id
        // if (caller_id.has_value() && TRUSTED)
        // {
        //   // return secrets
        // }
        // else
        // {
        //   // if not already PENDING, add as pending
        //   // return nothing
        // }
        // // If we know this node
        // }

        // NodeId joining_node_id =
        //   get_next_id(args.tx.get_view(network.values), NEXT_NODE_ID);

        // // Set joiner's fresh key for encrypting past network secrets
        // node.set_joiner_key(joining_node_id,
        // args.params["raw_fresh_key"]);

        // // If the network is OPENING, new nodes can directly be TRUSTED
        // and
        // // given network identity and ledger secrets. Otherwise, new
        // nodes are
        // // added as PENDING and must be first trusted via member
        // governance NodeStatus joining_node_status = NodeStatus::PENDING;
        // if (active_service->status == ServiceStatus::OPENING)
        //   joining_node_status = NodeStatus::TRUSTED;

        // nodes_view->put(
        //   joining_node_id,
        //   {in.node_info_network,
        //    caller_pem_raw,
        //    in.quote,
        //    joining_node_status});

        // // TODO: Also add to node certs table??
        // // I don't think so, remove node certs table

        // LOG_INFO_FMT(
        //   "Adding node {}:{} as node {} with status {}",
        //   in.node_info_network.host,
        //   in.node_info_network.rpcport,
        //   joining_node_id,
        //   joining_node_status);

        // if (active_service->status == ServiceStatus::OPENING)
        // {
        //   // Send network secrets and NodeID
        //   return jsonrpc::success<JoinNetworkNodeToNode::Out>(
        //     {joining_node_id,
        //      network.secrets->get_current(),
        //      network.secrets->get_current_version()});
        // }
        // else
        // {
        //   // Only send NodeID
        //   return jsonrpc::success(
        //     nlohmann::json(JoinNetworkNodeToNode::Out{joining_node_id}));
        // }
      };

      install(NodeProcs::JOIN, accept, Write);
    }
  };
}
