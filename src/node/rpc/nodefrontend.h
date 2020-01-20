// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/hash.h"
#include "frontend.h"
#include "node/entities.h"
#include "node/networkstate.h"
#include "node/quoteverification.h"

namespace ccf
{
  class NodeRpcFrontend : public RpcFrontend<>
  {
  private:
    NetworkState& network;
    AbstractNodeState& node;
    Signatures* signatures;

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
          node_info_network.nodehost == ni.nodehost &&
          ni.status != NodeStatus::RETIRED)
        {
          duplicate_node_id = nid;
          return false;
        }
        return true;
      });

      return duplicate_node_id;
    }

    auto add_node(
      Store::Tx& tx,
      std::vector<uint8_t>& caller_pem_raw,
      const JoinNetworkNodeToNode::In& in,
      NodeStatus node_status)
    {
      auto nodes_view = tx.get_view(network.nodes);

      auto conflicting_node_id =
        check_conflicting_node_network(tx, in.node_info_network);
      if (conflicting_node_id.has_value())
      {
        return jsonrpc::error(
          jsonrpc::StandardErrorCodes::INVALID_PARAMS,
          fmt::format(
            "A node with the same node host {} and port {} already exists "
            "(node id: {})",
            in.node_info_network.nodehost,
            in.node_info_network.nodeport,
            conflicting_node_id.value()));
      }

#ifdef GET_QUOTE
      // TODO: https://github.com/microsoft/CCF/issues/480
      // Verifying the joining node's quote takes a significant amount of time
      // as of OE v0.7.0 (about 2 secs).
      QuoteVerificationResult verify_result = QuoteVerifier::verify_quote(
        tx, this->network, in.quote, caller_pem_raw);

      if (verify_result != QuoteVerificationResult::VERIFIED)
        return QuoteVerifier::quote_verification_error_to_json(verify_result);
#else
      LOG_INFO_FMT("Skipped joining node quote verification");
#endif

      NodeId joining_node_id =
        get_next_id(tx.get_view(this->network.values), NEXT_NODE_ID);

      nodes_view->put(
        joining_node_id,
        {in.node_info_network,
         caller_pem_raw,
         in.quote,
         in.public_encryption_key,
         node_status});

      LOG_INFO_FMT("Node {} added as {}", joining_node_id, node_status);

      if (node_status == NodeStatus::TRUSTED)
      {
        return jsonrpc::success<JoinNetworkNodeToNode::Out>(
          {node_status,
           joining_node_id,
           {this->network.ledger_secrets->get_current(),
            this->network.ledger_secrets->get_current_version(),
            *this->network.identity.get()}});
      }
      else
      {
        return jsonrpc::success<JoinNetworkNodeToNode::Out>(
          {node_status, joining_node_id});
      }
    }

  public:
    NodeRpcFrontend(NetworkState& network, AbstractNodeState& node) :
      RpcFrontend<>(*network.tables),
      network(network),
      node(node),
      signatures(tables.get<Signatures>(Tables::SIGNATURES))
    {
      auto accept = [this](RequestArgs& args) {
        const auto in = args.params.get<JoinNetworkNodeToNode::In>();

        if (
          !this->node.is_part_of_network() &&
          !this->node.is_part_of_public_network())
        {
          return jsonrpc::error(
            jsonrpc::StandardErrorCodes::INTERNAL_ERROR,
            "Target node should be part of network to accept new nodes");
        }

        auto [nodes_view, service_view] =
          args.tx.get_view(this->network.nodes, this->network.service);

        auto active_service = service_view->get(0);
        if (!active_service.has_value())
        {
          return jsonrpc::error(
            jsonrpc::StandardErrorCodes::INTERNAL_ERROR,
            "No service is available to accept new node");
        }

        // Convert caller cert from DER to PEM as PEM certificates
        // are quoted
        auto caller_pem =
          tls::make_verifier(
            std::vector<uint8_t>(args.rpc_ctx.session.caller_cert))
            ->cert_pem();
        std::vector<uint8_t> caller_pem_raw = {caller_pem.str().begin(),
                                               caller_pem.str().end()};

        if (active_service->status == ServiceStatus::OPENING)
        {
          // If the service is opening, new nodes are trusted straight away
          NodeStatus joining_node_status = NodeStatus::TRUSTED;

          // If the node is already trusted, return network secrets
          auto existing_node_id =
            check_node_exists(args.tx, caller_pem_raw, joining_node_status);
          if (existing_node_id.has_value())
          {
            return jsonrpc::success<JoinNetworkNodeToNode::Out>(
              {joining_node_status,
               existing_node_id.value(),
               {this->network.ledger_secrets->get_current(),
                this->network.ledger_secrets->get_current_version(),
                *this->network.identity.get()}});
          }

          return add_node(args.tx, caller_pem_raw, in, joining_node_status);
        }

        // If the service is open, new nodes are first added as pending and
        // then only trusted via member governance. It is expected that a new
        // node polls the network to retrieve the network secrets until it is
        // trusted

        auto existing_node_id = check_node_exists(args.tx, caller_pem_raw);
        if (existing_node_id.has_value())
        {
          // If the node already exists, return network secrets if is already
          // trusted. Otherwise, only return its node id
          auto node_status = nodes_view->get(existing_node_id.value())->status;
          if (node_status == NodeStatus::TRUSTED)
          {
            return jsonrpc::success<JoinNetworkNodeToNode::Out>(
              {node_status,
               existing_node_id.value(),
               {this->network.ledger_secrets->get_current(),
                this->network.ledger_secrets->get_current_version(),
                *this->network.identity.get()}});
          }
          else if (node_status == NodeStatus::PENDING)
          {
            return jsonrpc::success<JoinNetworkNodeToNode::Out>(
              {node_status, existing_node_id.value()});
          }
          else
          {
            return jsonrpc::error(
              jsonrpc::StandardErrorCodes::INVALID_REQUEST,
              "Joining node is not in expected state");
          }
        }
        else
        {
          // If the node does not exist, add it to the KV in state pending

          // TODO: We should also automatically stage a vote for members to
          // accept the new node as trusted
          return add_node(args.tx, caller_pem_raw, in, NodeStatus::PENDING);
        }
      };

      auto get_signed_index = [this](RequestArgs& args) {
        GetSignedIndex::Out result;
        if (this->node.is_reading_public_ledger())
        {
          result.state = GetSignedIndex::State::ReadingPublicLedger;
        }
        else if (this->node.is_reading_private_ledger())
        {
          result.state = GetSignedIndex::State::ReadingPrivateLedger;
        }
        else if (this->node.is_part_of_network())
        {
          result.state = GetSignedIndex::State::PartOfNetwork;
        }
        else if (this->node.is_part_of_public_network())
        {
          result.state = GetSignedIndex::State::PartOfPublicNetwork;
        }
        else
        {
          return jsonrpc::error(
            jsonrpc::StandardErrorCodes::INVALID_REQUEST,
            "Network is not in recovery mode");
        }

        auto sig_view = args.tx.get_view(*signatures);
        auto sig = sig_view->get(0);
        if (!sig.has_value())
          result.signed_index = 0;
        else
          result.signed_index = sig.value().index;

        return jsonrpc::success(result);
      };

      // TODO: Should this be a GeneralProc?
      auto get_quotes = [this](RequestArgs& args) {
        GetQuotes::Out result;
        this->node.node_quotes(args.tx, result);

        return jsonrpc::success(result);
      };

      install(NodeProcs::JOIN, accept, Write);
      install_with_auto_schema<GetSignedIndex>(
        NodeProcs::GET_SIGNED_INDEX, get_signed_index, Read);
      install_with_auto_schema<GetQuotes>(
        NodeProcs::GET_QUOTES, get_quotes, Read);
    }
  };
}
