// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/common_auth_policies.h"
#include "ccf/common_endpoint_registry.h"
#include "ccf/http_query.h"
#include "ccf/json_handler.h"
#include "ccf/version.h"
#include "crypto/csr.h"
#include "crypto/hash.h"
#include "frontend.h"
#include "node/entities.h"
#include "node/network_state.h"
#include "node/quote.h"
#include "node/reconfig_id.h"
#include "node/rpc/error.h"
#include "node/session_metrics.h"
#include "node_interface.h"

namespace ccf
{
  struct Quote
  {
    NodeId node_id = {};
    std::vector<uint8_t> raw;
    std::vector<uint8_t> endorsements;
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

  struct NodeMetrics
  {
    ccf::SessionMetrics sessions;
  };

  DECLARE_JSON_TYPE(NodeMetrics)
  DECLARE_JSON_REQUIRED_FIELDS(NodeMetrics, sessions)

  struct JavaScriptMetrics
  {
    uint64_t bytecode_size;
    bool bytecode_used;
  };

  DECLARE_JSON_TYPE(JavaScriptMetrics)
  DECLARE_JSON_REQUIRED_FIELDS(JavaScriptMetrics, bytecode_size, bytecode_used)

  struct SetJwtPublicSigningKeys
  {
    std::string issuer;
    JsonWebKeySet jwks;
  };

  DECLARE_JSON_TYPE(SetJwtPublicSigningKeys)
  DECLARE_JSON_REQUIRED_FIELDS(SetJwtPublicSigningKeys, issuer, jwks)

  class NodeEndpoints : public CommonEndpointRegistry
  {
  private:
    NetworkState& network;

    struct ExistingNodeInfo
    {
      NodeId node_id;
      std::optional<kv::Version> ledger_secret_seqno = std::nullopt;
      std::optional<crypto::Pem> endorsed_certificate = std::nullopt;
    };

    std::optional<ExistingNodeInfo> check_node_exists(
      kv::Tx& tx,
      const std::vector<uint8_t>& self_signed_node_der,
      std::optional<NodeStatus> node_status = std::nullopt)
    {
      // Check that a node exists by looking up its public key in the nodes
      // table.
      auto nodes = tx.ro(network.nodes);
      auto endorsed_node_certificates =
        tx.ro(network.node_endorsed_certificates);

      auto pk_pem = crypto::public_key_pem_from_cert(self_signed_node_der);

      std::optional<ExistingNodeInfo> existing_node_info = std::nullopt;
      nodes->foreach([&existing_node_info,
                      &pk_pem,
                      &node_status,
                      &endorsed_node_certificates](
                       const NodeId& nid, const NodeInfo& ni) {
        if (
          ni.public_key == pk_pem &&
          (!node_status.has_value() || ni.status == node_status.value()))
        {
          existing_node_info = {
            nid, ni.ledger_secret_seqno, endorsed_node_certificates->get(nid)};
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
          node_info_network.node_address == ni.node_address &&
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
      NodeStatus node_status,
      ServiceStatus service_status)
    {
      auto nodes = tx.rw(network.nodes);
      auto node_endorsed_certificates =
        tx.rw(network.node_endorsed_certificates);

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
            in.node_info_network.node_address.hostname,
            in.node_info_network.node_address.port,
            conflicting_node_id.value()));
      }

      auto pubk_der = crypto::public_key_der_from_cert(node_der);
      NodeId joining_node_id = compute_node_id_from_pubk_der(pubk_der);

      CodeDigest code_digest;

#ifdef GET_QUOTE
      QuoteVerificationResult verify_result =
        this->context.get_node_state().verify_quote(
          tx, in.quote_info, pubk_der, code_digest);
      if (verify_result != QuoteVerificationResult::Verified)
      {
        const auto [code, message] = quote_verification_error(verify_result);
        return make_error(code, ccf::errors::InvalidQuote, message);
      }
#else
      LOG_INFO_FMT("Skipped joining node quote verification");
#endif

      std::optional<kv::Version> ledger_secret_seqno = std::nullopt;
      if (
        node_status == NodeStatus::TRUSTED ||
        node_status == NodeStatus::LEARNER)
      {
        ledger_secret_seqno =
          this->network.ledger_secrets->get_latest(tx).first;
      }

      // Note: All new nodes should specify a CSR from 2.x
      auto client_public_key_pem = crypto::public_key_pem_from_cert(node_der);
      if (in.certificate_signing_request.has_value())
      {
        // Verify that client's public key matches the one specified in the CSR)
        auto csr_public_key_pem = crypto::public_key_pem_from_csr(
          in.certificate_signing_request.value());
        if (client_public_key_pem != csr_public_key_pem)
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::CSRPublicKeyInvalid,
            "Public key in CSR does not match TLS client identity.");
        }
      }

      NodeInfo node_info = {
        in.node_info_network,
        in.quote_info,
        in.public_encryption_key,
        node_status,
        ledger_secret_seqno,
        ds::to_hex(code_digest.data),
        in.certificate_signing_request,
        client_public_key_pem};

      // Because the certificate signature scheme is non-deterministic, only
      // self-signed node certificate is recorded in the node info table
      if (this->network.consensus_type == ConsensusType::BFT)
      {
        node_info.cert = crypto::cert_der_to_pem(node_der);
      }

      nodes->put(joining_node_id, node_info);

      kv::NetworkConfiguration nc =
        get_latest_network_configuration(network, tx);
      nc.nodes.insert(joining_node_id);

      if (
        node_status == NodeStatus::TRUSTED ||
        node_status == NodeStatus::LEARNER)
      {
        add_new_network_reconfiguration(network, tx, nc);
      }

      LOG_INFO_FMT("Node {} added as {}", joining_node_id, node_status);

      JoinNetworkNodeToNode::Out rep;
      rep.node_status = node_status;
      rep.node_id = joining_node_id;

      if (
        node_status == NodeStatus::TRUSTED ||
        node_status == NodeStatus::LEARNER)
      {
        // Joining node only submit a CSR from 2.x
        std::optional<crypto::Pem> endorsed_certificate = std::nullopt;
        if (
          in.certificate_signing_request.has_value() &&
          this->network.consensus_type == ConsensusType::CFT)
        {
          endorsed_certificate =
            context.get_node_state().generate_endorsed_certificate(
              in.certificate_signing_request.value(),
              this->network.identity->priv_key,
              this->network.identity->cert);
          node_endorsed_certificates->put(
            joining_node_id, {endorsed_certificate.value()});
        }

        rep.network_info = JoinNetworkNodeToNode::Out::NetworkInfo{
          context.get_node_state().is_part_of_public_network(),
          context.get_node_state().get_last_recovered_signed_idx(),
          this->network.consensus_type,
          this->network.ledger_secrets->get(tx),
          *this->network.identity.get(),
          service_status,
          endorsed_certificate};
      }
      return make_success(rep);
    }

  public:
    NodeEndpoints(
      NetworkState& network, ccfapp::AbstractNodeContext& context_) :
      CommonEndpointRegistry(get_actor_prefix(ActorsType::nodes), context_),
      network(network)
    {
      openapi_info.title = "CCF Public Node API";
      openapi_info.description =
        "This API provides public, uncredentialed access to service and node "
        "state.";
      openapi_info.document_version = "2.2.0";
    }

    void init_handlers() override
    {
      CommonEndpointRegistry::init_handlers();

      auto accept = [this](auto& args, const nlohmann::json& params) {
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

        // If the joiner and this node both started from a snapshot, make sure
        // that the joiner's snapshot is more recent than this node's snapshot
        auto this_startup_seqno =
          this->context.get_node_state().get_startup_snapshot_seqno();
        if (
          this_startup_seqno.has_value() && in.startup_seqno.has_value() &&
          this_startup_seqno.value() > in.startup_seqno.value())
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::StartupSnapshotIsOld,
            fmt::format(
              "Node requested to join from snapshot at seqno {} which is "
              "older "
              "than this node startup seqno {}",
              in.startup_seqno.value(),
              this_startup_seqno.value()));
        }

        auto nodes = args.tx.rw(this->network.nodes);
        auto service = args.tx.rw(this->network.service);

        auto active_service = service->get();
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
            rep.network_info = JoinNetworkNodeToNode::Out::NetworkInfo(
              context.get_node_state().is_part_of_public_network(),
              context.get_node_state().get_last_recovered_signed_idx(),
              this->network.consensus_type,
              this->network.ledger_secrets->get(
                args.tx, existing_node_info->ledger_secret_seqno),
              *this->network.identity.get(),
              active_service->status,
              existing_node_info->endorsed_certificate);

            return make_success(rep);
          }

          if (
            consensus != nullptr && consensus->type() == ConsensusType::CFT &&
            !this->context.get_node_state().can_replicate())
          {
            auto primary_id = consensus->primary();
            if (primary_id.has_value())
            {
              auto nodes = args.tx.ro(this->network.nodes);
              auto info = nodes->get(primary_id.value());
              if (info)
              {
                const auto& pub_address =
                  info->rpc_interfaces[0].public_rpc_address;
                args.rpc_ctx->set_response_header(
                  http::headers::LOCATION,
                  fmt::format(
                    "https://{}:{}/node/join",
                    pub_address.hostname,
                    pub_address.port));

                return make_error(
                  HTTP_STATUS_PERMANENT_REDIRECT,
                  ccf::errors::NodeCannotHandleRequest,
                  "Node is not primary; cannot handle write");
              }
            }

            return make_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              "Primary unknown");
          }

          return add_node(
            args.tx,
            args.rpc_ctx->session->caller_cert,
            in,
            joining_node_status,
            active_service->status);
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

          // If the node already exists, return network secrets if is already
          // trusted. Otherwise, only return its status
          auto node_status = nodes->get(existing_node_info->node_id)->status;
          rep.node_status = node_status;
          if (
            node_status == NodeStatus::TRUSTED ||
            node_status == NodeStatus::LEARNER)
          {
            rep.network_info = JoinNetworkNodeToNode::Out::NetworkInfo(
              context.get_node_state().is_part_of_public_network(),
              context.get_node_state().get_last_recovered_signed_idx(),
              this->network.consensus_type,
              this->network.ledger_secrets->get(
                args.tx, existing_node_info->ledger_secret_seqno),
              *this->network.identity.get(),
              active_service->status,
              existing_node_info->endorsed_certificate);

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
          if (
            consensus != nullptr && consensus->type() == ConsensusType::CFT &&
            !this->context.get_node_state().can_replicate())
          {
            auto primary_id = consensus->primary();
            if (primary_id.has_value())
            {
              auto nodes = args.tx.ro(this->network.nodes);
              auto info = nodes->get(primary_id.value());
              if (info)
              {
                const auto& pub_address =
                  info->rpc_interfaces[0].public_rpc_address;
                args.rpc_ctx->set_response_header(
                  http::headers::LOCATION,
                  fmt::format(
                    "https://{}:{}/node/join",
                    pub_address.hostname,
                    pub_address.port));

                return make_error(
                  HTTP_STATUS_PERMANENT_REDIRECT,
                  ccf::errors::NodeCannotHandleRequest,
                  "Node is not primary; cannot handle write");
              }
            }

            return make_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              "Primary unknown");
          }

          // If the node does not exist, add it to the KV in state pending
          return add_node(
            args.tx,
            args.rpc_ctx->session->caller_cert,
            in,
            NodeStatus::PENDING,
            active_service->status);
        }
      };
      make_endpoint("/join", HTTP_POST, json_adapter(accept), no_auth_required)
        .set_forwarding_required(endpoints::ForwardingRequired::Never)
        .set_openapi_hidden(true)
        .install();

      auto get_state = [this](auto& args, nlohmann::json&&) {
        GetState::Out result;
        auto [s, rts, lrs] = this->context.get_node_state().state();
        result.node_id = this->context.get_node_state().get_node_id();
        result.state = s;
        result.recovery_target_seqno = rts;
        result.last_recovered_seqno = lrs;
        result.startup_seqno =
          this->context.get_node_state().get_startup_snapshot_seqno().value_or(
            0);

        auto signatures = args.tx.template ro<Signatures>(Tables::SIGNATURES);
        auto sig = signatures->get();
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
        "/state", HTTP_GET, json_read_only_adapter(get_state), no_auth_required)
        .set_auto_schema<GetState>()
        .set_forwarding_required(endpoints::ForwardingRequired::Never)
        .install();

      auto get_quote = [this](auto& args, nlohmann::json&&) {
        QuoteInfo node_quote_info;
        const auto result =
          get_quote_for_this_node_v1(args.tx, node_quote_info);
        if (result == ApiResult::OK)
        {
          Quote q;
          q.node_id = context.get_node_state().get_node_id();
          q.raw = node_quote_info.quote;
          q.endorsements = node_quote_info.endorsements;
          q.format = node_quote_info.format;

#ifdef GET_QUOTE
          // get_code_id attempts to re-validate the quote to extract mrenclave
          // and the Open Enclave is insufficiently flexible to allow quotes
          // with expired collateral to be parsed at all. Recent nodes therefore
          // cache their code digest on startup, and this code attempts to fetch
          // that value when possible and only call the unreliable get_code_id
          // otherwise.
          auto nodes = args.tx.ro(network.nodes);
          auto node_info = nodes->get(context.get_node_state().get_node_id());
          if (node_info.has_value() && node_info->code_digest.has_value())
          {
            q.mrenclave = node_info->code_digest.value();
          }
          else
          {
            auto code_id =
              EnclaveAttestationProvider::get_code_id(node_quote_info);
            if (code_id.has_value())
            {
              q.mrenclave = ds::to_hex(code_id.value().data);
            }
            else
            {
              return make_error(
                HTTP_STATUS_INTERNAL_SERVER_ERROR,
                ccf::errors::InvalidQuote,
                "Failed to extract code id from node quote.");
            }
          }
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
        "/quotes/self",
        HTTP_GET,
        json_read_only_adapter(get_quote),
        no_auth_required)
        .set_auto_schema<void, Quote>()
        .set_forwarding_required(endpoints::ForwardingRequired::Never)
        .install();

      auto get_quotes = [this](auto& args, nlohmann::json&&) {
        GetQuotes::Out result;

        auto nodes = args.tx.ro(network.nodes);
        nodes->foreach([&quotes = result.quotes](
                         const auto& node_id, const auto& node_info) {
          if (
            node_info.status == ccf::NodeStatus::TRUSTED ||
            node_info.status == ccf::NodeStatus::LEARNER)
          {
            Quote q;
            q.node_id = node_id;
            q.raw = node_info.quote_info.quote;
            q.endorsements = node_info.quote_info.endorsements;
            q.format = node_info.quote_info.format;

#ifdef GET_QUOTE
            // get_code_id attempts to re-validate the quote to extract
            // mrenclave and the Open Enclave is insufficiently flexible to
            // allow quotes with expired collateral to be parsed at all. Recent
            // nodes therefore cache their code digest on startup, and this code
            // attempts to fetch that value when possible and only call the
            // unreliable get_code_id otherwise.
            if (node_info.code_digest.has_value())
            {
              q.mrenclave = node_info.code_digest.value();
            }
            else
            {
              auto code_id =
                EnclaveAttestationProvider::get_code_id(node_info.quote_info);
              if (code_id.has_value())
              {
                q.mrenclave = ds::to_hex(code_id.value().data);
              }
            }
#endif
            quotes.emplace_back(q);
          }
          return true;
        });

        return make_success(result);
      };
      make_read_only_endpoint(
        "/quotes",
        HTTP_GET,
        json_read_only_adapter(get_quotes),
        no_auth_required)
        .set_auto_schema<GetQuotes>()
        .install();

      auto network_status = [this](auto& args, nlohmann::json&&) {
        GetNetworkInfo::Out out;
        auto service = args.tx.ro(network.service);
        auto service_state = service->get();
        if (service_state.has_value())
        {
          const auto& service_value = service_state.value();
          out.service_status = service_value.status;
          out.service_certificate = service_value.cert;
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
        "/network",
        HTTP_GET,
        json_read_only_adapter(network_status),
        no_auth_required)
        .set_execute_outside_consensus(
          ccf::endpoints::ExecuteOutsideConsensus::Locally)
        .set_auto_schema<void, GetNetworkInfo::Out>()
        .install();

      auto get_nodes = [this](auto& args, nlohmann::json&&) {
        const auto parsed_query =
          http::parse_query(args.rpc_ctx->get_request_query());

        std::string error_string; // Ignored - all params are optional
        const auto host = http::get_query_value_opt<std::string>(
          parsed_query, "host", error_string);
        const auto port = http::get_query_value_opt<std::string>(
          parsed_query, "port", error_string);
        const auto status_str = http::get_query_value_opt<std::string>(
          parsed_query, "status", error_string);

        std::optional<NodeStatus> status;
        if (status_str.has_value())
        {
          // Convert the query argument to a JSON string, try to parse it as a
          // NodeStatus, return an error if this doesn't work
          try
          {
            status = nlohmann::json(status_str.value()).get<NodeStatus>();
          }
          catch (const JsonParseError& e)
          {
            return ccf::make_error(
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::InvalidQueryParameterValue,
              fmt::format(
                "Query parameter '{}' is not a valid node status",
                status_str.value()));
          }
        }

        GetNodes::Out out;

        auto nodes = args.tx.ro(this->network.nodes);
        nodes->foreach([this, host, port, status, &out](
                         const NodeId& nid, const NodeInfo& ni) {
          const auto& primary_interface = ni.rpc_interfaces[0];
          const auto& pub_address = primary_interface.public_rpc_address;
          if (host.has_value() && host.value() != pub_address.hostname)
            return true;
          if (port.has_value() && port.value() != pub_address.port)
            return true;
          if (status.has_value() && status.value() != ni.status)
            return true;

          bool is_primary = false;
          if (consensus != nullptr)
          {
            is_primary = consensus->primary() == nid;
          }
          out.nodes.push_back(
            {nid,
             ni.status,
             pub_address.hostname,
             pub_address.port,
             primary_interface.rpc_address.hostname,
             primary_interface.rpc_address.port,
             is_primary});
          return true;
        });

        return make_success(out);
      };
      make_read_only_endpoint(
        "/network/nodes",
        HTTP_GET,
        json_read_only_adapter(get_nodes),
        no_auth_required)
        .set_execute_outside_consensus(
          ccf::endpoints::ExecuteOutsideConsensus::Primary)
        .set_auto_schema<void, GetNodes::Out>()
        .add_query_parameter<std::string>(
          "host", ccf::endpoints::OptionalParameter)
        .add_query_parameter<std::string>(
          "port", ccf::endpoints::OptionalParameter)
        .add_query_parameter<std::string>(
          "status", ccf::endpoints::OptionalParameter)
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
        const auto& primary_interface = ni.rpc_interfaces[0];
        return make_success(GetNode::Out{
          node_id,
          ni.status,
          primary_interface.public_rpc_address.hostname,
          primary_interface.public_rpc_address.port,
          primary_interface.rpc_address.hostname,
          primary_interface.rpc_address.port,
          is_primary});
      };
      make_read_only_endpoint(
        "/network/nodes/{node_id}",
        HTTP_GET,
        json_read_only_adapter(get_node_info),
        no_auth_required)
        .set_auto_schema<void, GetNode::Out>()
        .set_execute_outside_consensus(
          ccf::endpoints::ExecuteOutsideConsensus::Locally)
        .install();

      auto get_self_node = [this](auto& args) {
        auto node_id = this->context.get_node_state().get_node_id();
        auto nodes = args.tx.ro(this->network.nodes);
        auto info = nodes->get(node_id);
        if (info)
        {
          const auto& address = info->rpc_interfaces[0].public_rpc_address;
          args.rpc_ctx->set_response_status(HTTP_STATUS_PERMANENT_REDIRECT);
          args.rpc_ctx->set_response_header(
            http::headers::LOCATION,
            fmt::format(
              "https://{}:{}/node/network/nodes/{}",
              address.hostname,
              address.port,
              node_id.value()));
          return;
        }

        args.rpc_ctx->set_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          "Node info not available");
        return;
      };
      make_read_only_endpoint(
        "/network/nodes/self", HTTP_GET, get_self_node, no_auth_required)
        .set_forwarding_required(endpoints::ForwardingRequired::Never)
        .set_execute_outside_consensus(
          ccf::endpoints::ExecuteOutsideConsensus::Locally)
        .install();

      auto get_primary_node = [this](auto& args) {
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
            return;
          }

          auto nodes = args.tx.ro(this->network.nodes);
          auto info = nodes->get(node_id);
          auto info_primary = nodes->get(primary_id.value());
          if (info && info_primary)
          {
            const auto& address = info->rpc_interfaces[0].public_rpc_address;
            args.rpc_ctx->set_response_status(HTTP_STATUS_PERMANENT_REDIRECT);
            args.rpc_ctx->set_response_header(
              http::headers::LOCATION,
              fmt::format(
                "https://{}:{}/node/network/nodes/{}",
                address.hostname,
                address.port,
                primary_id->value()));
            return;
          }
        }

        args.rpc_ctx->set_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          "Primary unknown");
        return;
      };
      make_read_only_endpoint(
        "/network/nodes/primary", HTTP_GET, get_primary_node, no_auth_required)
        .set_forwarding_required(endpoints::ForwardingRequired::Never)
        .set_execute_outside_consensus(
          ccf::endpoints::ExecuteOutsideConsensus::Locally)
        .install();

      auto is_primary = [this](auto& args) {
        if (this->context.get_node_state().can_replicate())
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
              return;
            }

            auto nodes = args.tx.ro(this->network.nodes);
            auto info = nodes->get(primary_id.value());
            if (info)
            {
              const auto& address = info->rpc_interfaces[0].public_rpc_address;
              args.rpc_ctx->set_response_header(
                http::headers::LOCATION,
                fmt::format(
                  "https://{}:{}/node/primary",
                  address.hostname,
                  address.port));
            }
          }
        }
      };
      make_read_only_endpoint(
        "/primary", HTTP_HEAD, is_primary, no_auth_required)
        .set_forwarding_required(endpoints::ForwardingRequired::Never)
        .set_execute_outside_consensus(
          ccf::endpoints::ExecuteOutsideConsensus::Locally)
        .install();

      auto consensus_config = [this](auto& args) {
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
        "/config", HTTP_GET, consensus_config, no_auth_required)
        .set_forwarding_required(endpoints::ForwardingRequired::Never)
        .set_execute_outside_consensus(
          ccf::endpoints::ExecuteOutsideConsensus::Locally)
        .install();

      auto consensus_state = [this](auto& args) {
        if (consensus != nullptr)
        {
          auto d = consensus->get_details();
          nlohmann::json c;
          c["details"] = d;
          args.rpc_ctx->set_response_body(c.dump());
        }
        else
        {
          args.rpc_ctx->set_response_status(HTTP_STATUS_NOT_FOUND);
          args.rpc_ctx->set_response_body("No configured consensus");
        }
      };

      make_command_endpoint(
        "/consensus", HTTP_GET, consensus_state, no_auth_required)
        .set_forwarding_required(endpoints::ForwardingRequired::Never)
        .set_execute_outside_consensus(
          ccf::endpoints::ExecuteOutsideConsensus::Locally)
        .install();

      auto memory_usage = [](auto& args) {

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

      make_command_endpoint("/memory", HTTP_GET, memory_usage, no_auth_required)
        .set_forwarding_required(endpoints::ForwardingRequired::Never)
        .set_execute_outside_consensus(
          ccf::endpoints::ExecuteOutsideConsensus::Locally)
        .set_auto_schema<MemoryUsage>()
        .install();

      auto node_metrics = [this](auto& args) {
        NodeMetrics nm;
        nm.sessions = context.get_node_state().get_session_metrics();

        args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        args.rpc_ctx->set_response_header(
          http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);
        args.rpc_ctx->set_response_body(nlohmann::json(nm).dump());
      };

      make_command_endpoint(
        "/metrics", HTTP_GET, node_metrics, no_auth_required)
        .set_forwarding_required(endpoints::ForwardingRequired::Never)
        .set_execute_outside_consensus(
          ccf::endpoints::ExecuteOutsideConsensus::Locally)
        .set_auto_schema<void, NodeMetrics>()
        .install();

      auto js_metrics = [this](auto& args, nlohmann::json&&) {
        auto bytecode_map = args.tx.ro(this->network.modules_quickjs_bytecode);
        auto version_val = args.tx.ro(this->network.modules_quickjs_version);
        uint64_t bytecode_size = 0;
        bytecode_map->foreach(
          [&bytecode_size](const auto&, const auto& bytecode) {
            bytecode_size += bytecode.size();
            return true;
          });
        JavaScriptMetrics m;
        m.bytecode_size = bytecode_size;
        m.bytecode_used =
          version_val->get() == std::string(ccf::quickjs_version);
        return m;
      };

      make_read_only_endpoint(
        "/js_metrics",
        HTTP_GET,
        json_read_only_adapter(js_metrics),
        no_auth_required)
        .set_auto_schema<void, JavaScriptMetrics>()
        .set_execute_outside_consensus(
          ccf::endpoints::ExecuteOutsideConsensus::Locally)
        .install();

      auto version = [this](auto&, nlohmann::json&&) {
        GetVersion::Out result;
        result.ccf_version = ccf::ccf_version;
        result.quickjs_version = ccf::quickjs_version;
        return make_success(result);
      };

      make_command_endpoint(
        "/version", HTTP_GET, json_command_adapter(version), no_auth_required)
        .set_forwarding_required(endpoints::ForwardingRequired::Never)
        .set_auto_schema<GetVersion>()
        .set_execute_outside_consensus(
          ccf::endpoints::ExecuteOutsideConsensus::Locally)
        .install();

      auto create = [this](auto& ctx, nlohmann::json&& params) {
        LOG_DEBUG_FMT("Processing create RPC");

        // This endpoint can only be called once, directly from the starting
        // node for the genesis or end of public recovery transaction to
        // initialise the service
        if (
          network.consensus_type == ConsensusType::CFT &&
          !context.get_node_state().is_in_initialised_state() &&
          !context.get_node_state().is_reading_public_ledger())
        {
          return make_error(
            HTTP_STATUS_FORBIDDEN,
            ccf::errors::InternalError,
            "Node is not in initial state.");
        }

        const auto in = params.get<CreateNetworkNodeToNode::In>();
        GenesisGenerator g(this->network, ctx.tx);
        if (g.is_service_created(in.network_cert))
        {
          return make_error(
            HTTP_STATUS_FORBIDDEN,
            ccf::errors::InternalError,
            "Service is already created.");
        }

        g.create_service(in.network_cert);

        // Retire all nodes, in case there are any (i.e. post recovery)
        g.retire_active_nodes();

        NodeInfo node_info = {
          in.node_info_network,
          {in.quote_info},
          in.public_encryption_key,
          NodeStatus::TRUSTED,
          std::nullopt,
          ds::to_hex(in.code_digest.data),
          in.certificate_signing_request,
          in.public_key};

        // Genesis transaction (i.e. not after recovery)
        if (in.genesis_info.has_value())
        {
          // Note that it is acceptable to start a network without any member
          // having a recovery share. The service will check that at least one
          // recovery member is added before the service is opened.
          for (const auto& info : in.genesis_info->members_info)
          {
            g.add_member(info);
          }

          if (
            in.genesis_info->configuration.consensus == ConsensusType::BFT &&
            (!in.genesis_info->configuration.reconfiguration_type.has_value() ||
             in.genesis_info->configuration.reconfiguration_type.value() !=
               ReconfigurationType::TWO_TRANSACTION))
          {
            return make_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              "BFT consensus requires two-transaction reconfiguration.");
          }

          g.init_configuration(in.genesis_info->configuration);
          g.set_constitution(in.genesis_info->constitution);
        }

        if (!in.node_cert.has_value())
        {
          auto endorsed_certificates =
            ctx.tx.rw(network.node_endorsed_certificates);
          endorsed_certificates->put(
            in.node_id,
            context.get_node_state().generate_endorsed_certificate(
              in.certificate_signing_request,
              this->network.identity->priv_key,
              this->network.identity->cert));
        }
        else
        {
          node_info.cert = in.node_cert.value();
        }

        g.add_node(in.node_id, node_info);

#ifdef GET_QUOTE
        g.trust_node_code_id(in.code_digest);
#endif

        LOG_INFO_FMT("Created service");
        return make_success(true);
      };
      make_endpoint(
        "/create", HTTP_POST, json_adapter(create), no_auth_required)
        .set_openapi_hidden(true)
        .install();

      // Only called from node. See node_state.h.
      auto refresh_jwt_keys = [this](auto& ctx, nlohmann::json&& body) {
        // All errors are server errors since the client is the server.

        if (!consensus)
        {
          LOG_FAIL_FMT("JWT key auto-refresh: no consensus available");
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            "No consensus available.");
        }

        auto primary_id = consensus->primary();
        if (!primary_id.has_value())
        {
          LOG_FAIL_FMT("JWT key auto-refresh: primary unknown");
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            "Primary is unknown");
        }

        const auto& sig_auth_ident =
          ctx.template get_caller<ccf::NodeCertAuthnIdentity>();
        if (primary_id.value() != sig_auth_ident.node_id)
        {
          LOG_FAIL_FMT(
            "JWT key auto-refresh: request does not originate from primary");
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            "Request does not originate from primary.");
        }

        SetJwtPublicSigningKeys parsed;
        try
        {
          parsed = body.get<SetJwtPublicSigningKeys>();
        }
        catch (const JsonParseError& e)
        {
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            "Unable to parse body.");
        }

        auto issuers = ctx.tx.rw(this->network.jwt_issuers);
        auto issuer_metadata_ = issuers->get(parsed.issuer);
        if (!issuer_metadata_.has_value())
        {
          LOG_FAIL_FMT(
            "JWT key auto-refresh: {} is not a valid issuer", parsed.issuer);
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            fmt::format("{} is not a valid issuer.", parsed.issuer));
        }
        auto& issuer_metadata = issuer_metadata_.value();

        if (!issuer_metadata.auto_refresh)
        {
          LOG_FAIL_FMT(
            "JWT key auto-refresh: {} does not have auto_refresh enabled",
            parsed.issuer);
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            fmt::format(
              "{} does not have auto_refresh enabled.", parsed.issuer));
        }

        if (!set_jwt_public_signing_keys(
              ctx.tx,
              "<auto-refresh>",
              parsed.issuer,
              issuer_metadata,
              parsed.jwks))
        {
          LOG_FAIL_FMT(
            "JWT key auto-refresh: error while storing signing keys for issuer "
            "{}",
            parsed.issuer);
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            fmt::format(
              "Error while storing signing keys for issuer {}.",
              parsed.issuer));
        }

        return make_success(true);
      };
      make_endpoint(
        "/jwt_keys/refresh",
        HTTP_POST,
        json_adapter(refresh_jwt_keys),
        {std::make_shared<NodeCertAuthnPolicy>()})
        .set_openapi_hidden(true)
        .install();

      auto update_resharing = [this](auto& args, const nlohmann::json& params) {
        const auto in = params.get<UpdateResharing::In>();
        auto resharings = args.tx.rw(network.resharings);

        bool exists = false;
        resharings->foreach(
          [rid = in.rid, &exists](
            const kv::ReconfigurationId& trid, const ResharingResult& result) {
            if (trid == rid)
            {
              exists = true;
              return false;
            }
            return true;
          });

        if (exists)
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::ResharingAlreadyCompleted,
            fmt::format(
              "resharing for configuration {} already completed", in.rid));
        }

        // For now, just pretend that we're done.
        ResharingResult rr;
        rr.reconfiguration_id = in.rid;
        rr.seqno = 0;
        resharings->put(in.rid, rr);
        return make_success(true);
      };

      make_endpoint(
        "/update-resharing",
        HTTP_POST,
        json_adapter(update_resharing),
        {std::make_shared<NodeCertAuthnPolicy>()})
        .set_forwarding_required(endpoints::ForwardingRequired::Always)
        .set_openapi_hidden(true)
        .install();

      auto orc_handler = [this](auto& args, const nlohmann::json& params) {
        const auto in = params.get<ObservedReconfigurationCommit::In>();
        LOG_DEBUG_FMT(
          "ORC for configuration #{} from {}", in.reconfiguration_id, in.from);

        if (consensus == nullptr)
        {
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::ConsensusTypeMismatch,
            fmt::format("No consensus"));
        }

        if (consensus->type() != ConsensusType::BFT)
        {
          auto primary_id = consensus->primary();
          if (!primary_id.has_value())
          {
            return make_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              "Primary unknown");
          }

          if (primary_id.value() != context.get_node_state().get_node_id())
          {
            return make_error(
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::NodeCannotHandleRequest,
              "Only the primary accepts ORCs");
          }
        }

        if (consensus->orc(in.reconfiguration_id, in.from))
        {
          LOG_DEBUG_FMT(
            "Configurations: sufficient number of ORCs, updating nodes in "
            "configuration #{}",
            in.reconfiguration_id);
          auto ncfgs = args.tx.ro(network.network_configurations);
          auto nodes = args.tx.rw(network.nodes);
          auto nc = ncfgs->get(in.reconfiguration_id);
          for (auto nid : nc->nodes)
          {
            auto node_info = nodes->get(nid);
            if (!node_info.has_value())
            {
              return make_error(
                HTTP_STATUS_INTERNAL_SERVER_ERROR,
                ccf::errors::InternalError,
                fmt::format("Missing node information for {}", nid));
            }

            if (node_info->status == NodeStatus::LEARNER)
            {
              node_info->status = NodeStatus::TRUSTED;
              nodes->put(nid, *node_info);
            }
            else if (node_info->status == NodeStatus::RETIRING)
            {
              node_info->status = NodeStatus::RETIRED;
              nodes->put(nid, *node_info);
            }
          }
        }

        return make_success();
      };

      make_endpoint(
        "/orc",
        HTTP_POST,
        json_adapter(orc_handler),
        {std::make_shared<NodeCertAuthnPolicy>()})
        .set_forwarding_required(endpoints::ForwardingRequired::Always)
        .set_openapi_hidden(true)
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
