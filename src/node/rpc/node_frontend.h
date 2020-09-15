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
  class NodeEndpoints : public CommonEndpointRegistry
  {
  private:
    NetworkState& network;
    AbstractNodeState& node;

    Signatures* signatures = nullptr;

    std::optional<NodeId> check_node_exists(
      kv::Tx& tx,
      const tls::Pem& node_pem,
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
      kv::Tx& tx, const NodeInfoNetwork& node_info_network)
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
      kv::Tx& tx,
      const tls::Pem& caller_pem,
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
      if (network.consensus_type != ConsensusType::BFT)
      {
        QuoteVerificationResult verify_result =
          QuoteVerifier::verify_quote_against_store(
            tx, this->network.node_code_ids, in.quote, caller_pem);

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
         caller_pem,
         in.quote,
         in.public_encryption_key,
         node_status});

      LOG_INFO_FMT("Node {} added as {}", joining_node_id, node_status);

      JoinNetworkNodeToNode::Out rep;
      rep.node_status = node_status;
      rep.node_id = joining_node_id;

      if (node_status == NodeStatus::TRUSTED)
      {
        rep.network_info = JoinNetworkNodeToNode::Out::NetworkInfo{
          node.is_part_of_public_network(),
          node.get_last_recovered_commit_idx(),
          this->network.consensus_type,
          *this->network.ledger_secrets.get(),
          *this->network.identity.get(),
          *this->network.encryption_key.get()};
      }
      return make_success(rep);
    }

  public:
    NodeEndpoints(NetworkState& network, AbstractNodeState& node) :
      CommonEndpointRegistry(*network.tables),
      network(network),
      node(node)
    {}

    void init_handlers(kv::Store& tables_) override
    {
      CommonEndpointRegistry::init_handlers(tables_);

      signatures = tables->get<Signatures>(Tables::SIGNATURES);

      auto accept = [this](
                      EndpointContext& args, const nlohmann::json& params) {
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
        auto caller_pem =
          tls::cert_der_to_pem(args.rpc_ctx->session->caller_cert);

        if (active_service->status == ServiceStatus::OPENING)
        {
          // If the service is opening, new nodes are trusted straight away
          NodeStatus joining_node_status = NodeStatus::TRUSTED;

          // If the node is already trusted, return network secrets
          auto existing_node_id =
            check_node_exists(args.tx, caller_pem, joining_node_status);
          if (existing_node_id.has_value())
          {
            JoinNetworkNodeToNode::Out rep;
            rep.node_status = joining_node_status;
            rep.node_id = existing_node_id.value();
            rep.network_info = {node.is_part_of_public_network(),
                                node.get_last_recovered_commit_idx(),
                                this->network.consensus_type,
                                *this->network.ledger_secrets.get(),
                                *this->network.identity.get(),
                                *this->network.encryption_key.get()};
            return make_success(rep);
          }

          return add_node(args.tx, caller_pem, in, joining_node_status);
        }

        // If the service is open, new nodes are first added as pending and
        // then only trusted via member governance. It is expected that a new
        // node polls the network to retrieve the network secrets until it is
        // trusted

        auto existing_node_id = check_node_exists(args.tx, caller_pem);
        if (existing_node_id.has_value())
        {
          JoinNetworkNodeToNode::Out rep;
          rep.node_id = existing_node_id.value();

          // If the node already exists, return network secrets if is already
          // trusted. Otherwise, only return its node id
          auto node_status = nodes_view->get(existing_node_id.value())->status;
          rep.node_status = node_status;
          if (node_status == NodeStatus::TRUSTED)
          {
            rep.network_info = {node.is_part_of_public_network(),
                                node.get_last_recovered_commit_idx(),
                                this->network.consensus_type,
                                *this->network.ledger_secrets.get(),
                                *this->network.identity.get(),
                                *this->network.encryption_key.get()};
            return make_success(rep);
          }
          else if (node_status == NodeStatus::PENDING)
          {
            // Only return node status and ID
            return make_success(rep);
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
          return add_node(args.tx, caller_pem, in, NodeStatus::PENDING);
        }
      };
      make_endpoint("join", HTTP_POST, json_adapter(accept)).install();

      auto get_state = [this](auto& args, nlohmann::json&&) {
        GetState::Out result;
        auto [s, rts, lrs] = this->node.state();
        result.id = this->node.get_node_id();
        result.state = s;
        result.recovery_target_seqno = rts;
        result.last_recovered_seqno = lrs;

        auto sig_view = args.tx.get_read_only_view(*signatures);
        auto sig = sig_view->get(0);
        if (!sig.has_value())
        {
          result.last_signed_seqno = 0;
        }
        else
        {
          result.last_signed_seqno = sig.value().seqno;
        }

        return result;
      };
      make_read_only_endpoint(
        "state", HTTP_GET, json_read_only_adapter(get_state))
        .set_auto_schema<GetState>()
        .set_forwarding_required(ForwardingRequired::Never)
        .install();

      auto get_quote = [this](auto& args, nlohmann::json&&) {
        GetQuotes::Out result;
        std::set<NodeId> filter;
        filter.insert(this->node.get_node_id());
        this->node.node_quotes(args.tx, result, filter);

        if (result.quotes.size() > 0)
        {
          return make_success(result);
        }
        else
        {
          return make_error(HTTP_STATUS_NOT_FOUND, "Could not find node quote");
        }
      };
      make_read_only_endpoint(
        "quote", HTTP_GET, json_read_only_adapter(get_quote))
        .set_auto_schema<GetQuotes>()
        .set_forwarding_required(ForwardingRequired::Never)
        .install();

      auto get_quotes = [this](auto& args, nlohmann::json&&) {
        GetQuotes::Out result;
        this->node.node_quotes(args.tx, result);

        return make_success(result);
      };
      make_read_only_endpoint(
        "quotes", HTTP_GET, json_read_only_adapter(get_quotes))
        .set_auto_schema<GetQuotes>()
        .install();

      auto network_status = [this](auto& args, nlohmann::json&&) {
        auto service_view = args.tx.get_read_only_view(network.service);
        auto service_state = service_view->get(0);
        if (service_state.has_value())
        {
          return make_success(service_state.value().status);
        }
        return make_error(HTTP_STATUS_NOT_FOUND, "Network status is unknown");
      };
      make_read_only_endpoint(
        "network", HTTP_GET, json_read_only_adapter(network_status))
        .install();

      auto is_primary = [this](ReadOnlyEndpointContext& args) {
        if (this->node.is_primary())
        {
          args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        }
        else
        {
          args.rpc_ctx->set_response_status(HTTP_STATUS_PERMANENT_REDIRECT);
          if (consensus != nullptr)
          {
            NodeId primary_id = consensus->primary();
            auto nodes_view = args.tx.get_read_only_view(this->network.nodes);
            auto info = nodes_view->get(primary_id);
            if (info)
            {
              args.rpc_ctx->set_response_header(
                "Location",
                fmt::format(
                  "https://{}:{}/node/primary", info->pubhost, info->rpcport));
            }
          }
        }
      };
      make_read_only_endpoint("primary", HTTP_HEAD, is_primary)
        .set_forwarding_required(ForwardingRequired::Never)
        .install();
    }
  };

  class NodeRpcFrontend : public RpcFrontend
  {
  protected:
    NodeEndpoints node_endpoints;

  public:
    NodeRpcFrontend(NetworkState& network, AbstractNodeState& node) :
      RpcFrontend(*network.tables, node_endpoints),
      node_endpoints(network, node)
    {}
  };
}
