// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/hash.h"
#include "frontend.h"
#include "node/entities.h"
#include "node/network_state.h"
#include "node/quote.h"
#include "node_interface.h"

namespace ccf
{
  class NodeHandlers : public CommonHandlerRegistry
  {
  private:
    NetworkState& network;
    AbstractNodeState& node;

    Signatures* signatures = nullptr;

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
        return make_error(
          HTTP_STATUS_BAD_REQUEST,
          fmt::format(
            "A node with the same node host {} and port {} already exists "
            "(node id: {})",
            in.node_info_network.nodehost,
            in.node_info_network.nodeport,
            conflicting_node_id.value()));
      }

#ifdef GET_QUOTE
      if (network.consensus_type != ConsensusType::PBFT)
      {
        QuoteVerificationResult verify_result =
          QuoteVerifier::verify_quote_against_store(
            tx, this->network.node_code_ids, in.quote, caller_pem_raw);

        if (verify_result != QuoteVerificationResult::VERIFIED)
        {
          const auto [code, message] =
            QuoteVerifier::quote_verification_error(verify_result);
          return make_error(code, message);
        }
      }
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
        return make_success(
          JoinNetworkNodeToNode::Out({node_status,
                                      joining_node_id,
                                      node.is_part_of_public_network(),
                                      this->network.consensus_type,
                                      {*this->network.ledger_secrets.get(),
                                       *this->network.identity.get(),
                                       *this->network.encryption_key.get()}}));
      }
      else
      {
        return make_success(
          JoinNetworkNodeToNode::Out({node_status, joining_node_id}));
      }
    }

  public:
    NodeHandlers(NetworkState& network, AbstractNodeState& node) :
      CommonHandlerRegistry(*network.tables),
      network(network),
      node(node)
    {}

    void init_handlers(Store& tables_) override
    {
      CommonHandlerRegistry::init_handlers(tables_);

      signatures = tables->get<Signatures>(Tables::SIGNATURES);

      auto accept = [this](RequestArgs& args, const nlohmann::json& params) {
        const auto in = params.get<JoinNetworkNodeToNode::In>();

        if (
          !this->node.is_part_of_network() &&
          !this->node.is_part_of_public_network())
        {
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            "Target node should be part of network to accept new nodes");
        }

        if (this->network.consensus_type != in.consensus_type)
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST,
            fmt::format(
              "Node requested to join with consensus type {} but "
              "current consensus type is {}",
              in.consensus_type,
              this->network.consensus_type));
        }

        auto [nodes_view, service_view] =
          args.tx.get_view(this->network.nodes, this->network.service);

        auto active_service = service_view->get(0);
        if (!active_service.has_value())
        {
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            "No service is available to accept new node");
        }

        // Convert caller cert from DER to PEM as PEM certificates
        // are quoted
        auto caller_pem_raw =
          tls::cert_der_to_pem(args.rpc_ctx->session->caller_cert);

        if (active_service->status == ServiceStatus::OPENING)
        {
          // If the service is opening, new nodes are trusted straight away
          NodeStatus joining_node_status = NodeStatus::TRUSTED;

          // If the node is already trusted, return network secrets
          auto existing_node_id =
            check_node_exists(args.tx, caller_pem_raw, joining_node_status);
          if (existing_node_id.has_value())
          {
            return make_success(JoinNetworkNodeToNode::Out(
              {joining_node_status,
               existing_node_id.value(),
               node.is_part_of_public_network(),
               this->network.consensus_type,
               {*this->network.ledger_secrets.get(),
                *this->network.identity.get(),
                *this->network.encryption_key.get()}}));
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
            return make_success(JoinNetworkNodeToNode::Out(
              {node_status,
               existing_node_id.value(),
               node.is_part_of_public_network(),
               this->network.consensus_type,
               {*this->network.ledger_secrets.get(),
                *this->network.identity.get(),
                *this->network.encryption_key.get()}}));
          }
          else if (node_status == NodeStatus::PENDING)
          {
            return make_success(JoinNetworkNodeToNode::Out(
              {node_status, existing_node_id.value()}));
          }
          else
          {
            return make_error(
              HTTP_STATUS_BAD_REQUEST, "Joining node is not in expected state");
          }
        }
        else
        {
          // If the node does not exist, add it to the KV in state pending
          return add_node(args.tx, caller_pem_raw, in, NodeStatus::PENDING);
        }
      };

      auto get_signed_index = [this](Store::Tx& tx) {
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
          return make_error(
            HTTP_STATUS_BAD_REQUEST, "Network is not in recovery mode");
        }

        auto sig_view = tx.get_view(*signatures);
        auto sig = sig_view->get(0);
        if (!sig.has_value())
          result.signed_index = 0;
        else
          result.signed_index = sig.value().index;

        return make_success(result);
      };

      auto get_quote = [this](Store::Tx& tx) {
        GetQuotes::Out result;
        std::set<NodeId> filter;
        filter.insert(this->node.get_node_id());
        this->node.node_quotes(tx, result, filter);

        return make_success(result);
      };

      auto get_quotes = [this](Store::Tx& tx) {
        GetQuotes::Out result;
        this->node.node_quotes(tx, result);

        return make_success(result);
      };

      install(NodeProcs::JOIN, json_adapter(accept), Write);
      install(NodeProcs::GET_SIGNED_INDEX, json_adapter(get_signed_index), Read)
        .set_auto_schema<GetSignedIndex>()
        .set_http_get_only();
      install(NodeProcs::GET_NODE_QUOTE, json_adapter(get_quote), Read)
        .set_auto_schema<GetQuotes>()
        .set_http_get_only();
      install(NodeProcs::GET_QUOTES, json_adapter(get_quotes), Read)
        .set_auto_schema<GetQuotes>()
        .set_http_get_only();
    }
  };

  class NodeRpcFrontend : public RpcFrontend
  {
  protected:
    NodeHandlers node_handlers;

  public:
    NodeRpcFrontend(NetworkState& network, AbstractNodeState& node) :
      RpcFrontend(*network.tables, node_handlers),
      node_handlers(network, node)
    {}
  };
}
