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

    std::optional<NodeId> check_node_exists(
      Store::Tx& tx,
      std::vector<uint8_t>& node_pem,
      std::optional<NodeStatus> node_status = std::nullopt)
    {
      auto nodes_view = tx.get_view(network.nodes);

      std::optional<NodeId> existing_node_id;
      nodes_view->foreach([&existing_node_id, &node_pem, &node_status](
                            const NodeId& nid, const NodeInfo& ni) {
        if (
          ni.cert == node_pem &&
          (!node_status.has_value() || ni.status == node_status.value()))
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
          args.tx, this->network, in.quote, caller_pem_raw);

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
          // If the node is already trusted, return network secrets straight
          // away.
          auto existing_node_id =
            check_node_exists(args.tx, caller_pem_raw, NodeStatus::TRUSTED);
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
        else // TODO: Fix this
        // else if (active_service->status == ServiceStatus::OPEN)
        {
          // Check if the node already exists
          auto existing_node_id = check_node_exists(args.tx, caller_pem_raw);
          if (existing_node_id.has_value())
          {
            auto node_status =
              nodes_view->get(existing_node_id.value())->status;

            if (node_status == NodeStatus::PENDING)
            {
              return jsonrpc::success<JoinNetworkNodeToNode::Out>(
                {NodeStatus::PENDING, existing_node_id.value()});
            }
            else if (node_status == NodeStatus::TRUSTED)
            {
              LOG_FAIL_FMT("Service open, node is already trusted");
              return jsonrpc::success<JoinNetworkNodeToNode::Out>(
                {NodeStatus::TRUSTED,
                 existing_node_id.value(),
                 {this->network.secrets->get_current(),
                  this->network.secrets->get_current_version()}});
            }
          }
          else
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
          }

          // TODO: Remove when this is refactored, only here to remove clang
          // warning
          return jsonrpc::success<JoinNetworkNodeToNode::Out>(
            {NodeStatus::PENDING, 0});
        }
      };

      install(NodeProcs::JOIN, accept, Write);
    }
  };
}
