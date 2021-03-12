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
  struct Quote
  {
    NodeId node_id = {};
    std::string raw = {}; // < Hex-encoded
    std::string endorsements = {}; // < Hex-encoded
    QuoteFormat format;

    std::string mrenclave = {}; // < Hex-encoded
  };

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Quote)
  DECLARE_JSON_REQUIRED_FIELDS(Quote, node_id, raw, endorsements, format)
  DECLARE_JSON_OPTIONAL_FIELDS(Quote, mrenclave)

  struct GetQuotes
  {
    using In = void;

    struct Out
    {
      std::vector<Quote> quotes;
    };
  };

  DECLARE_JSON_TYPE(GetQuotes::Out)
  DECLARE_JSON_REQUIRED_FIELDS(GetQuotes::Out, quotes)

  class NodeEndpoints : public CommonEndpointRegistry
  {
  private:
    NetworkState& network;

    using ExistingNodeInfo = std::pair<NodeId, std::optional<kv::Version>>;

    std::optional<ExistingNodeInfo> check_node_exists(
      kv::Tx& tx,
      const std::vector<uint8_t>& node_der,
      std::optional<NodeStatus> node_status = std::nullopt)
    {
      auto nodes = tx.rw(network.nodes);

      auto node_pem = crypto::cert_der_to_pem(node_der);

      std::optional<ExistingNodeInfo> existing_node_info = std::nullopt;
      nodes->foreach([&existing_node_info, &node_pem, &node_status](
                       const NodeId& nid, const NodeInfo& ni) {
        if (
          ni.cert == node_pem &&
          (!node_status.has_value() || ni.status == node_status.value()))
        {
          existing_node_info = std::make_pair(nid, ni.ledger_secret_seqno);
          return false;
        }
        return true;
      });

      return existing_node_info;
    }

    std::optional<NodeId> check_conflicting_node_network(
      kv::Tx& tx, const NodeInfoNetwork& node_info_network)
    {
      auto nodes = tx.rw(network.nodes);

      std::optional<NodeId> duplicate_node_id;
      nodes->foreach([&node_info_network, &duplicate_node_id](
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
      const std::vector<uint8_t>& node_der,
      const JoinNetworkNodeToNode::In& in,
      NodeStatus node_status)
    {
      auto nodes = tx.rw(network.nodes);

      auto conflicting_node_id =
        check_conflicting_node_network(tx, in.node_info_network);
      if (conflicting_node_id.has_value())
      {
        return make_error(
          HTTP_STATUS_BAD_REQUEST,
          ccf::errors::NodeAlreadyExists,
          fmt::format(
            "A node with the same node host {} and port {} already exists "
            "(node id: {}).",
            in.node_info_network.nodehost,
            in.node_info_network.nodeport,
            conflicting_node_id.value()));
      }

      auto pk_der = crypto::public_key_der_from_cert(node_der);

      NodeId joining_node_id;
      if (network.consensus_type == ConsensusType::CFT)
      {
        joining_node_id = crypto::Sha256Hash(pk_der).hex_str();
      }
      else
      {
        // Pad node id string to avoid memory alignment issues on
        // node-to-node messages
        joining_node_id = fmt::format(
          "{:#08}", get_next_id(tx.rw(this->network.values), NEXT_NODE_ID));
      }

#ifdef GET_QUOTE
      QuoteVerificationResult verify_result =
        this->context.get_node_state().verify_quote(tx, in.quote_info, pk_der);
      if (verify_result != QuoteVerificationResult::Verified)
      {
        const auto [code, message] = quote_verification_error(verify_result);
        return make_error(code, ccf::errors::InvalidQuote, message);
      }
#else
      LOG_INFO_FMT("Skipped joining node quote verification");
#endif

      std::optional<kv::Version> ledger_secret_seqno = std::nullopt;
      if (node_status == NodeStatus::TRUSTED)
      {
        ledger_secret_seqno =
          this->network.ledger_secrets->get_latest(tx).first;
      }

      nodes->put(
        joining_node_id,
        {in.node_info_network,
         crypto::cert_der_to_pem(node_der),
         in.quote_info,
         in.public_encryption_key,
         node_status,
         ledger_secret_seqno});

      LOG_INFO_FMT("Node {} added as {}", joining_node_id, node_status);

      JoinNetworkNodeToNode::Out rep;
      rep.node_status = node_status;
      rep.node_id = joining_node_id;

      if (node_status == NodeStatus::TRUSTED)
      {
        rep.network_info = JoinNetworkNodeToNode::Out::NetworkInfo{
          context.get_node_state().is_part_of_public_network(),
          context.get_node_state().get_last_recovered_signed_idx(),
          this->network.consensus_type,
          this->network.ledger_secrets->get(tx),
          *this->network.identity.get()};
      }
      return make_success(rep);
    }

  public:
    NodeEndpoints(NetworkState& network, ccfapp::AbstractNodeContext& context) :
      CommonEndpointRegistry(get_actor_prefix(ActorsType::nodes), context),
      network(network)
    {
      openapi_info.title = "CCF Public Node API";
      openapi_info.description =
        "This API provides public, uncredentialed access to service and node "
        "state.";
    }

    void init_handlers() override
    {
      CommonEndpointRegistry::init_handlers();

      auto accept =
        [this](EndpointContext& args, const nlohmann::json& params) {
          const auto in = params.get<JoinNetworkNodeToNode::In>();

          if (
            !this->context.get_node_state().is_part_of_network() &&
            !this->context.get_node_state().is_part_of_public_network() &&
            !this->context.get_node_state().is_reading_private_ledger())
          {
            return make_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              "Target node should be part of network to accept new nodes.");
          }

          if (this->network.consensus_type != in.consensus_type)
          {
            return make_error(
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::ConsensusTypeMismatch,
              fmt::format(
                "Node requested to join with consensus type {} but "
                "current consensus type is {}.",
                in.consensus_type,
                this->network.consensus_type));
          }

          auto nodes = args.tx.rw(this->network.nodes);
          auto service = args.tx.rw(this->network.service);

          auto active_service = service->get(0);
          if (!active_service.has_value())
          {
            return make_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              "No service is available to accept new node.");
          }

          if (active_service->status == ServiceStatus::OPENING)
          {
            // If the service is opening, new nodes are trusted straight away
            NodeStatus joining_node_status = NodeStatus::TRUSTED;

            // If the node is already trusted, return network secrets
            auto existing_node_info = check_node_exists(
              args.tx, args.rpc_ctx->session->caller_cert, joining_node_status);
            if (existing_node_info.has_value())
            {
              JoinNetworkNodeToNode::Out rep;
              rep.node_status = joining_node_status;
              rep.node_id = existing_node_info->first;
              rep.network_info = {
                context.get_node_state().is_part_of_public_network(),
                context.get_node_state().get_last_recovered_signed_idx(),
                this->network.consensus_type,
                this->network.ledger_secrets->get(
                  args.tx, existing_node_info->second),
                *this->network.identity.get()};
              return make_success(rep);
            }

            return add_node(
              args.tx,
              args.rpc_ctx->session->caller_cert,
              in,
              joining_node_status);
          }

          // If the service is open, new nodes are first added as pending and
          // then only trusted via member governance. It is expected that a new
          // node polls the network to retrieve the network secrets until it is
          // trusted

          auto existing_node_info =
            check_node_exists(args.tx, args.rpc_ctx->session->caller_cert);
          if (existing_node_info.has_value())
          {
            JoinNetworkNodeToNode::Out rep;
            rep.node_id = existing_node_info->first;

            // If the node already exists, return network secrets if is already
            // trusted. Otherwise, only return its status
            auto node_status = nodes->get(existing_node_info->first)->status;
            rep.node_status = node_status;
            if (node_status == NodeStatus::TRUSTED)
            {
              rep.network_info = {
                context.get_node_state().is_part_of_public_network(),
                context.get_node_state().get_last_recovered_signed_idx(),
                this->network.consensus_type,
                this->network.ledger_secrets->get(
                  args.tx, existing_node_info->second),
                *this->network.identity.get()};
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
                HTTP_STATUS_BAD_REQUEST,
                ccf::errors::InvalidNodeState,
                "Joining node is not in expected state.");
            }
          }
          else
          {
            // If the node does not exist, add it to the KV in state pending
            return add_node(
              args.tx,
              args.rpc_ctx->session->caller_cert,
              in,
              NodeStatus::PENDING);
          }
        };
      make_endpoint("join", HTTP_POST, json_adapter(accept), no_auth_required)
        .set_openapi_hidden(true)
        .install();

      auto get_state = [this](auto& args, nlohmann::json&&) {
        GetState::Out result;
        auto [s, rts, lrs] = this->context.get_node_state().state();
        result.node_id = this->context.get_node_state().get_node_id();
        result.state = s;
        result.recovery_target_seqno = rts;
        result.last_recovered_seqno = lrs;

        auto signatures = args.tx.template ro<Signatures>(Tables::SIGNATURES);
        auto sig = signatures->get(0);
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
        "state", HTTP_GET, json_read_only_adapter(get_state), no_auth_required)
        .set_auto_schema<GetState>()
        .set_forwarding_required(ForwardingRequired::Never)
        .install();

      auto get_quote = [this](auto& args, nlohmann::json&&) {
        QuoteInfo node_quote_info;
        const auto result =
          get_quote_for_this_node_v1(args.tx, node_quote_info);
        if (result == ApiResult::OK)
        {
          Quote q;
          q.node_id = context.get_node_state().get_node_id();
          q.raw = ds::to_hex(node_quote_info.quote);
          q.endorsements = ds::to_hex(node_quote_info.endorsements);
          q.format = node_quote_info.format;

#ifdef GET_QUOTE
          auto code_id =
            EnclaveAttestationProvider::get_code_id(node_quote_info);
          q.mrenclave = ds::to_hex(code_id);
#endif

          return make_success(q);
        }
        else if (result == ApiResult::NotFound)
        {
          return make_error(
            HTTP_STATUS_NOT_FOUND,
            ccf::errors::ResourceNotFound,
            "Could not find node quote.");
        }
        else
        {
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            fmt::format("Error code: {}", ccf::api_result_to_str(result)));
        }
      };
      make_read_only_endpoint(
        "quotes/self",
        HTTP_GET,
        json_read_only_adapter(get_quote),
        no_auth_required)
        .set_auto_schema<void, Quote>()
        .set_forwarding_required(ForwardingRequired::Never)
        .install();

      auto get_quotes = [this](auto& args, nlohmann::json&&) {
        GetQuotes::Out result;

        auto nodes = args.tx.ro(network.nodes);
        nodes->foreach([& quotes = result.quotes](
                         const auto& node_id, const auto& node_info) {
          if (node_info.status == ccf::NodeStatus::TRUSTED)
          {
            Quote q;
            q.node_id = node_id;
            q.raw = ds::to_hex(node_info.quote_info.quote);
            q.endorsements = fmt::format(
              "{:02x}", fmt::join(node_info.quote_info.endorsements, ""));
            q.format = QuoteFormat::oe_sgx_v1;

#ifdef GET_QUOTE
            auto code_id =
              EnclaveAttestationProvider::get_code_id(node_info.quote_info);
            q.mrenclave = ds::to_hex(code_id);
#endif
            quotes.emplace_back(q);
          }
          return true;
        });

        return make_success(result);
      };
      make_read_only_endpoint(
        "quotes",
        HTTP_GET,
        json_read_only_adapter(get_quotes),
        no_auth_required)
        .set_auto_schema<GetQuotes>()
        .install();

      auto network_status = [this](auto& args, nlohmann::json&&) {
        GetNetworkInfo::Out out;
        auto service = args.tx.ro(network.service);
        auto service_state = service->get(0);
        if (service_state.has_value())
        {
          out.service_status = service_state.value().status;
          if (consensus != nullptr)
          {
            out.current_view = consensus->get_view();
            auto primary_id = consensus->primary();
            if (primary_id.has_value() && !consensus->view_change_in_progress())
            {
              out.primary_id = primary_id.value();
            }
          }
          return make_success(out);
        }
        return make_error(
          HTTP_STATUS_NOT_FOUND,
          ccf::errors::ResourceNotFound,
          "Service state not available.");
      };
      make_read_only_endpoint(
        "network",
        HTTP_GET,
        json_read_only_adapter(network_status),
        no_auth_required)
        .set_execute_outside_consensus(
          ccf::endpoints::ExecuteOutsideConsensus::Locally)
        .set_auto_schema<void, GetNetworkInfo::Out>()
        .install();

      auto get_nodes = [this](auto& args, nlohmann::json&& params) {
        const auto in = params.get<GetNodes::In>();
        GetNodes::Out out;

        auto nodes = args.tx.ro(this->network.nodes);
        nodes->foreach(
          [this, &in, &out](const NodeId& nid, const NodeInfo& ni) {
            if (in.host.has_value() && in.host.value() != ni.pubhost)
              return true;
            if (in.port.has_value() && in.port.value() != ni.pubport)
              return true;
            if (in.status.has_value() && in.status.value() != ni.status)
              return true;
            bool is_primary = false;
            if (consensus != nullptr)
            {
              is_primary = consensus->primary() == nid;
            }
            out.nodes.push_back({nid,
                                 ni.status,
                                 ni.pubhost,
                                 ni.pubport,
                                 ni.rpchost,
                                 ni.rpcport,
                                 is_primary});
            return true;
          });

        return make_success(out);
      };
      make_read_only_endpoint(
        "network/nodes",
        HTTP_GET,
        json_read_only_adapter(get_nodes),
        no_auth_required)
        .set_execute_outside_consensus(
          ccf::endpoints::ExecuteOutsideConsensus::Primary)
        .set_auto_schema<GetNodes>()
        .install();

      auto get_node_info = [this](auto& args, nlohmann::json&&) {
        std::string node_id;
        std::string error;
        if (!get_path_param(
              args.rpc_ctx->get_request_path_params(),
              "node_id",
              node_id,
              error))
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST, ccf::errors::InvalidResourceName, error);
        }

        auto nodes = args.tx.ro(this->network.nodes);
        auto info = nodes->get(node_id);

        if (!info)
        {
          return make_error(
            HTTP_STATUS_NOT_FOUND,
            ccf::errors::ResourceNotFound,
            "Node not found");
        }

        bool is_primary = false;
        if (consensus != nullptr)
        {
          auto primary = consensus->primary();
          if (primary.has_value() && primary.value() == node_id)
          {
            is_primary = true;
          }
        }
        auto ni = info.value();
        return make_success(GetNode::Out{node_id,
                                         ni.status,
                                         ni.pubhost,
                                         ni.pubport,
                                         ni.rpchost,
                                         ni.rpcport,
                                         is_primary});
      };
      make_read_only_endpoint(
        "network/nodes/{node_id}",
        HTTP_GET,
        json_read_only_adapter(get_node_info),
        no_auth_required)
        .set_auto_schema<void, GetNode::Out>()
        .set_execute_outside_consensus(
          ccf::endpoints::ExecuteOutsideConsensus::Locally)
        .install();

      auto get_self_node = [this](ReadOnlyEndpointContext& args) {
        auto node_id = this->context.get_node_state().get_node_id();
        auto nodes = args.tx.ro(this->network.nodes);
        auto info = nodes->get(node_id);
        if (info)
        {
          args.rpc_ctx->set_response_status(HTTP_STATUS_PERMANENT_REDIRECT);
          args.rpc_ctx->set_response_header(
            "Location",
            fmt::format(
              "https://{}:{}/node/network/nodes/{}",
              info->pubhost,
              info->pubport,
              node_id.value()));
          return;
        }

        args.rpc_ctx->set_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          "Node info not available");
      };
      make_read_only_endpoint(
        "network/nodes/self", HTTP_GET, get_self_node, no_auth_required)
        .set_forwarding_required(ForwardingRequired::Never)
        .set_execute_outside_consensus(
          ccf::endpoints::ExecuteOutsideConsensus::Locally)
        .install();

      auto get_primary_node = [this](ReadOnlyEndpointContext& args) {
        if (consensus != nullptr)
        {
          auto node_id = this->context.get_node_state().get_node_id();
          auto primary_id = consensus->primary();
          if (!primary_id.has_value())
          {
            args.rpc_ctx->set_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              "Primary unknown");
          }

          auto nodes = args.tx.ro(this->network.nodes);
          auto info = nodes->get(node_id);
          auto info_primary = nodes->get(primary_id.value());
          if (info && info_primary)
          {
            args.rpc_ctx->set_response_status(HTTP_STATUS_PERMANENT_REDIRECT);
            args.rpc_ctx->set_response_header(
              "Location",
              fmt::format(
                "https://{}:{}/node/network/nodes/{}",
                info->pubhost,
                info->pubport,
                primary_id->value()));
            return;
          }
        }

        args.rpc_ctx->set_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          "Primary unknown");
      };
      make_read_only_endpoint(
        "network/nodes/primary", HTTP_GET, get_primary_node, no_auth_required)
        .set_forwarding_required(ForwardingRequired::Never)
        .set_execute_outside_consensus(
          ccf::endpoints::ExecuteOutsideConsensus::Locally)
        .install();

      auto is_primary = [this](ReadOnlyEndpointContext& args) {
        if (this->context.get_node_state().is_primary())
        {
          args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        }
        else
        {
          args.rpc_ctx->set_response_status(HTTP_STATUS_PERMANENT_REDIRECT);
          if (consensus != nullptr)
          {
            auto primary_id = consensus->primary();
            if (!primary_id.has_value())
            {
              args.rpc_ctx->set_error(
                HTTP_STATUS_INTERNAL_SERVER_ERROR,
                ccf::errors::InternalError,
                "Primary unknown");
            }

            auto nodes = args.tx.ro(this->network.nodes);
            auto info = nodes->get(primary_id.value());
            if (info)
            {
              args.rpc_ctx->set_response_header(
                "Location",
                fmt::format(
                  "https://{}:{}/node/primary", info->pubhost, info->pubport));
            }
          }
        }
      };
      make_read_only_endpoint(
        "primary", HTTP_HEAD, is_primary, no_auth_required)
        .set_forwarding_required(ForwardingRequired::Never)
        .set_execute_outside_consensus(
          ccf::endpoints::ExecuteOutsideConsensus::Locally)
        .install();

      auto consensus_config = [this](CommandEndpointContext& args) {
        // Query node for configurations, separate current from pending
        if (consensus != nullptr)
        {
          auto cfg = consensus->get_latest_configuration();
          nlohmann::json c;
          for (auto& [nid, ninfo] : cfg)
          {
            nlohmann::json n;
            n["address"] = fmt::format("{}:{}", ninfo.hostname, ninfo.port);
            c[nid.value()] = n;
          }
          args.rpc_ctx->set_response_body(c.dump());
        }
        else
        {
          args.rpc_ctx->set_response_status(HTTP_STATUS_NOT_FOUND);
          args.rpc_ctx->set_response_body("No configured consensus");
        }
      };

      make_command_endpoint(
        "config", HTTP_GET, consensus_config, no_auth_required)
        .set_forwarding_required(ForwardingRequired::Never)
        .set_execute_outside_consensus(
          ccf::endpoints::ExecuteOutsideConsensus::Locally)
        .install();

      auto memory_usage = [](CommandEndpointContext& args) {

// Do not attempt to call oe_allocator_mallinfo when used from
// unit tests such as the frontend_test
#ifdef INSIDE_ENCLAVE
        oe_mallinfo_t info;
        auto rc = oe_allocator_mallinfo(&info);
        if (rc == OE_OK)
        {
          MemoryUsage::Out mu(info);
          args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          args.rpc_ctx->set_response_header(
            http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);
          args.rpc_ctx->set_response_body(nlohmann::json(mu).dump());
          return;
        }
#endif

        args.rpc_ctx->set_response_status(HTTP_STATUS_INTERNAL_SERVER_ERROR);
        args.rpc_ctx->set_response_body("Failed to read memory usage");
      };

      make_command_endpoint("memory", HTTP_GET, memory_usage, no_auth_required)
        .set_forwarding_required(ForwardingRequired::Never)
        .set_execute_outside_consensus(
          ccf::endpoints::ExecuteOutsideConsensus::Locally)
        .set_auto_schema<MemoryUsage>()
        .install();
    }
  };

  class NodeRpcFrontend : public RpcFrontend
  {
  protected:
    NodeEndpoints node_endpoints;

  public:
    NodeRpcFrontend(
      NetworkState& network, ccfapp::AbstractNodeContext& context) :
      RpcFrontend(*network.tables, node_endpoints),
      node_endpoints(network, context)
    {}
  };
}
