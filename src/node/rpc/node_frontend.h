// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/common_auth_policies.h"
#include "ccf/common_endpoint_registry.h"
#include "ccf/endpoint_context.h"
#include "ccf/http_query.h"
#include "ccf/js/core/context.h"
#include "ccf/json_handler.h"
#include "ccf/node/quote.h"
#include "ccf/odata_error.h"
#include "ccf/pal/attestation.h"
#include "ccf/pal/mem.h"
#include "ccf/service/reconfiguration_type.h"
#include "ccf/version.h"
#include "crypto/certs.h"
#include "crypto/csr.h"
#include "ds/files.h"
#include "ds/std_formatters.h"
#include "frontend.h"
#include "node/network_state.h"
#include "node/rpc/file_serving_handlers.h"
#include "node/rpc/jwt_management.h"
#include "node/rpc/no_create_tx_claims_digest.cpp" // NOLINT(bugprone-suspicious-include)
#include "node/rpc/node_frontend_utils.h"
#include "node/rpc/self_healing_open_handlers.h"
#include "node/rpc/serialization.h"
#include "node/session_metrics.h"
#include "node_interface.h"
#include "service/internal_tables_access.h"
#include "service/tables/local_sealing.h"
#include "service/tables/previous_service_identity.h"

#include <llhttp/llhttp.h>
#include <stdexcept>

namespace ccf
{
  struct Quote
  {
    NodeId node_id;
    std::vector<uint8_t> raw;
    std::vector<uint8_t> endorsements;
    QuoteFormat format = QuoteFormat::oe_sgx_v1;

    std::string measurement; // < Hex-encoded

    std::optional<std::vector<uint8_t>> uvm_endorsements =
      std::nullopt; // SNP only
  };

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Quote);
  DECLARE_JSON_REQUIRED_FIELDS(Quote, node_id, raw, endorsements, format);
  DECLARE_JSON_OPTIONAL_FIELDS(Quote, measurement, uvm_endorsements);

  struct Attestation : public Quote
  {};
  DECLARE_JSON_TYPE_WITH_BASE(Attestation, Quote);
  DECLARE_JSON_REQUIRED_FIELDS(Attestation);

  struct GetQuotes
  {
    using In = void;

    struct Out
    {
      std::vector<Quote> quotes;
    };
  };

  DECLARE_JSON_TYPE(GetQuotes::Out);
  DECLARE_JSON_REQUIRED_FIELDS(GetQuotes::Out, quotes);

  struct GetAttestations
  {
    using In = void;

    struct Out
    {
      std::vector<Attestation> attestations;
    };
  };

  DECLARE_JSON_TYPE(GetAttestations::Out);
  DECLARE_JSON_REQUIRED_FIELDS(GetAttestations::Out, attestations);

  struct NodeMetrics
  {
    ccf::SessionMetrics sessions;
  };

  DECLARE_JSON_TYPE(NodeMetrics);
  DECLARE_JSON_REQUIRED_FIELDS(NodeMetrics, sessions);

  struct JavaScriptMetrics
  {
    uint64_t bytecode_size = 0;
    bool bytecode_used = false;
    uint64_t max_heap_size = 0;
    uint64_t max_stack_size = 0;
    uint64_t max_execution_time = 0;
    uint64_t max_cached_interpreters = 10;
  };

  DECLARE_JSON_TYPE(JavaScriptMetrics);
  DECLARE_JSON_REQUIRED_FIELDS(
    JavaScriptMetrics,
    bytecode_size,
    bytecode_used,
    max_heap_size,
    max_stack_size,
    max_execution_time,
    max_cached_interpreters);

  struct JWTRefreshMetrics
  {
    size_t attempts = 0;
    size_t successes = 0;
    size_t failures = 0;
  };

  DECLARE_JSON_TYPE(JWTRefreshMetrics)
  DECLARE_JSON_REQUIRED_FIELDS(JWTRefreshMetrics, attempts, successes, failures)

  struct SetJwtPublicSigningKeys
  {
    std::string issuer;
    JsonWebKeySet jwks;
  };

  DECLARE_JSON_TYPE(SetJwtPublicSigningKeys);
  DECLARE_JSON_REQUIRED_FIELDS(SetJwtPublicSigningKeys, issuer, jwks);

  struct ConsensusNodeConfig
  {
    std::string address;
  };

  DECLARE_JSON_TYPE(ConsensusNodeConfig);
  DECLARE_JSON_REQUIRED_FIELDS(ConsensusNodeConfig, address);

  using ConsensusConfig = std::map<std::string, ConsensusNodeConfig>;

  struct ConsensusConfigDetails
  {
    ccf::kv::ConsensusDetails details;
  };

  DECLARE_JSON_TYPE(ConsensusConfigDetails);
  DECLARE_JSON_REQUIRED_FIELDS(ConsensusConfigDetails, details);

  struct SelfSignedNodeCertificateInfo
  {
    ccf::crypto::Pem self_signed_certificate;
  };

  DECLARE_JSON_TYPE(SelfSignedNodeCertificateInfo);
  DECLARE_JSON_REQUIRED_FIELDS(
    SelfSignedNodeCertificateInfo, self_signed_certificate);

  struct GetServicePreviousIdentity
  {
    struct Out
    {
      ccf::crypto::Pem previous_service_identity;
    };
  };

  DECLARE_JSON_TYPE(GetServicePreviousIdentity::Out);
  DECLARE_JSON_REQUIRED_FIELDS(
    GetServicePreviousIdentity::Out, previous_service_identity);

  class NodeEndpoints : public CommonEndpointRegistry
  {
  public:
    // The node frontend is exempt from backpressure rules to enable an operator
    // to access a node that is not making progress.
    [[nodiscard]] bool apply_uncommitted_tx_backpressure() const override
    {
      return false;
    }

  private:
    NetworkState& network;
    ccf::AbstractNodeOperation& node_operation;

    struct ExistingNodeInfo
    {
      NodeId node_id;
      std::optional<ccf::kv::Version> ledger_secret_seqno = std::nullopt;
      std::optional<ccf::crypto::Pem> endorsed_certificate = std::nullopt;
    };

    std::optional<ExistingNodeInfo> check_node_exists(
      ccf::kv::Tx& tx,
      const std::vector<uint8_t>& self_signed_node_der,
      std::optional<NodeStatus> node_status = std::nullopt)
    {
      // Check that a node exists by looking up its public key in the nodes
      // table.
      auto* nodes = tx.ro(network.nodes);
      auto* endorsed_node_certificates =
        tx.ro(network.node_endorsed_certificates);

      LOG_DEBUG_FMT(
        "Check node exists with certificate [{}]", self_signed_node_der);
      auto pk_pem = ccf::crypto::public_key_pem_from_cert(self_signed_node_der);

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
      ccf::kv::Tx& tx, const NodeInfoNetwork& node_info_network)
    {
      auto* nodes = tx.rw(network.nodes);

      std::optional<NodeId> duplicate_node_id = std::nullopt;
      nodes->foreach([&node_info_network, &duplicate_node_id](
                       const NodeId& nid, const NodeInfo& ni) {
        if (
          node_info_network.node_to_node_interface.published_address ==
            ni.node_to_node_interface.published_address &&
          ni.status != NodeStatus::RETIRED)
        {
          duplicate_node_id = nid;
          return false;
        }
        return true;
      });

      return duplicate_node_id;
    }

    bool is_taking_part_in_acking(NodeStatus node_status)
    {
      return node_status == NodeStatus::TRUSTED;
    }

    auto add_node(
      ccf::kv::Tx& tx,
      const std::vector<uint8_t>& node_der,
      const JoinNetworkNodeToNode::In& in,
      NodeStatus node_status,
      ServiceStatus service_status)
    {
      auto* nodes = tx.rw(network.nodes);
      auto* node_endorsed_certificates =
        tx.rw(network.node_endorsed_certificates);

      auto conflicting_node_id =
        check_conflicting_node_network(tx, in.node_info_network);
      if (conflicting_node_id.has_value())
      {
        return make_error(
          HTTP_STATUS_BAD_REQUEST,
          ccf::errors::NodeAlreadyExists,
          fmt::format(
            "A node with the same published node address {} already exists "
            "(node id: {}).",
            in.node_info_network.node_to_node_interface.published_address,
            conflicting_node_id.value()));
      }

      auto pubk_der = ccf::crypto::public_key_der_from_cert(node_der);
      NodeId joining_node_id = compute_node_id_from_pubk_der(pubk_der);

      pal::PlatformAttestationMeasurement measurement;

      QuoteVerificationResult verify_result = this->node_operation.verify_quote(
        tx, in.quote_info, pubk_der, measurement);
      if (verify_result != QuoteVerificationResult::Verified)
      {
        const auto [code, message] = quote_verification_error(verify_result);
        return make_error(code, ccf::errors::InvalidQuote, message);
      }

      std::optional<ccf::kv::Version> ledger_secret_seqno = std::nullopt;
      if (node_status == NodeStatus::TRUSTED)
      {
        ledger_secret_seqno =
          this->network.ledger_secrets->get_latest(tx).first;
      }

      // Note: All new nodes should specify a CSR from 2.x
      auto client_public_key_pem =
        ccf::crypto::public_key_pem_from_cert(node_der);
      if (in.certificate_signing_request.has_value())
      {
        // Verify that client's public key matches the one specified in the CSR
        auto csr_public_key_pem = ccf::crypto::public_key_pem_from_csr(
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
        measurement.hex_str(),
        in.certificate_signing_request,
        client_public_key_pem,
        in.node_data};

      nodes->put(joining_node_id, node_info);

      if (in.sealed_recovery_key.has_value())
      {
        auto* sealed_recovery_keys =
          tx.rw<SealedRecoveryKeys>(Tables::SEALED_RECOVERY_KEYS);
        sealed_recovery_keys->put(
          joining_node_id, in.sealed_recovery_key.value());
      }

      LOG_INFO_FMT("Node {} added as {}", joining_node_id, node_status);

      JoinNetworkNodeToNode::Out rep;
      rep.node_status = node_status;
      rep.node_id = joining_node_id;

      if (node_status == NodeStatus::TRUSTED)
      {
        node_operation.shuffle_sealed_shares(tx);
        // Joining node only submit a CSR from 2.x
        std::optional<ccf::crypto::Pem> endorsed_certificate = std::nullopt;
        if (in.certificate_signing_request.has_value())
        {
          // For a pre-open service, extract the validity period of self-signed
          // node certificate and use it verbatim in endorsed certificate
          auto [valid_from, valid_to] =
            ccf::crypto::make_verifier(node_der)->validity_period();
          endorsed_certificate = ccf::crypto::create_endorsed_cert(
            in.certificate_signing_request.value(),
            valid_from,
            valid_to,
            this->network.identity->priv_key,
            this->network.identity->cert);

          node_endorsed_certificates->put(
            joining_node_id, {endorsed_certificate.value()});
        }

        rep.network_info = JoinNetworkNodeToNode::Out::NetworkInfo{
          node_operation.is_part_of_public_network(),
          node_operation.get_last_recovered_signed_idx(),
          this->network.ledger_secrets->get(tx),
          *this->network.identity,
          service_status,
          endorsed_certificate,
          node_operation.get_cose_signatures_config()};
      }
      return make_success(rep);
    }

    JWTRefreshMetrics jwt_refresh_metrics;
    void handle_event_request_completed(
      const ccf::endpoints::RequestCompletedEvent& event) override
    {
      if (event.method == "POST" && event.dispatch_path == "/jwt_keys/refresh")
      {
        jwt_refresh_metrics.attempts += 1;
        int status_category = event.status / 100;
        if (status_category >= 4)
        {
          jwt_refresh_metrics.failures += 1;
        }
        else if (status_category == 2)
        {
          jwt_refresh_metrics.successes += 1;
        }
      }
    }

  public:
    NodeEndpoints(NetworkState& network_, ccf::AbstractNodeContext& context_) :
      CommonEndpointRegistry(get_actor_prefix(ActorsType::nodes), context_),
      network(network_),
      node_operation(*context_.get_subsystem<ccf::AbstractNodeOperation>())
    {
      openapi_info.title = "CCF Public Node API";
      openapi_info.description =
        "This API provides public, uncredentialed access to service and node "
        "state.";
      openapi_info.document_version = "4.16.0";
    }

    void init_handlers() override
    {
      CommonEndpointRegistry::init_handlers();

      auto accept = [this](auto& args, const nlohmann::json& params) {
        const auto in = params.get<JoinNetworkNodeToNode::In>();

        if (
          !this->node_operation.is_part_of_network() &&
          !this->node_operation.is_part_of_public_network() &&
          !this->node_operation.is_reading_private_ledger())
        {
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            "Target node should be part of network to accept new nodes.");
        }

        // Make sure that the joiner's snapshot is more recent than this node's
        // snapshot. Otherwise, the joiner may not be given all the ledger
        // secrets required to replay historical transactions.
        auto this_startup_seqno =
          this->node_operation.get_startup_snapshot_seqno();
        if (
          in.startup_seqno.has_value() &&
          this_startup_seqno > in.startup_seqno.value())
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::StartupSeqnoIsOld,
            fmt::format(
              "Node requested to join from seqno {} which is older than this "
              "node startup seqno {}. A snapshot at least as recent as {} must "
              "be used instead.",
              in.startup_seqno.value(),
              this_startup_seqno,
              this_startup_seqno));
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

        if (
          active_service->status == ServiceStatus::OPENING ||
          active_service->status == ServiceStatus::RECOVERING)
        {
          // If the service is opening, new nodes are trusted straight away
          NodeStatus joining_node_status = NodeStatus::TRUSTED;

          // If the node is already trusted, return network secrets
          auto existing_node_info = check_node_exists(
            args.tx,
            args.rpc_ctx->get_session_context()->caller_cert,
            joining_node_status);
          if (existing_node_info.has_value())
          {
            JoinNetworkNodeToNode::Out rep;
            rep.node_status = joining_node_status;
            rep.network_info = JoinNetworkNodeToNode::Out::NetworkInfo(
              node_operation.is_part_of_public_network(),
              node_operation.get_last_recovered_signed_idx(),
              this->network.ledger_secrets->get(
                args.tx, existing_node_info->ledger_secret_seqno),
              *this->network.identity,
              active_service->status,
              existing_node_info->endorsed_certificate,
              node_operation.get_cose_signatures_config());

            return make_success(rep);
          }

          if (consensus != nullptr && !this->node_operation.can_replicate())
          {
            auto primary_id = consensus->primary();
            if (primary_id.has_value())
            {
              const auto address = node::get_redirect_address_for_node(
                args, args.tx, primary_id.value());
              if (!address.has_value())
              {
                return already_populated_response();
              }

              args.rpc_ctx->set_response_header(
                http::headers::LOCATION,
                fmt::format("https://{}/node/join", address.value()));

              return make_error(
                HTTP_STATUS_PERMANENT_REDIRECT,
                ccf::errors::NodeCannotHandleRequest,
                "Node is not primary; cannot handle write");
            }

            return make_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              "Primary unknown");
          }

          return add_node(
            args.tx,
            args.rpc_ctx->get_session_context()->caller_cert,
            in,
            joining_node_status,
            active_service->status);
        }

        // If the service is open, new nodes are first added as pending and
        // then only trusted via member governance. It is expected that a new
        // node polls the network to retrieve the network secrets until it is
        // trusted

        auto existing_node_info = check_node_exists(
          args.tx, args.rpc_ctx->get_session_context()->caller_cert);
        if (existing_node_info.has_value())
        {
          JoinNetworkNodeToNode::Out rep;

          // If the node already exists, return network secrets if is already
          // trusted. Otherwise, only return its status
          auto node_info = nodes->get(existing_node_info->node_id);
          auto node_status = node_info->status;
          rep.node_status = node_status;
          rep.node_id = existing_node_info->node_id;
          if (is_taking_part_in_acking(node_status))
          {
            rep.network_info = JoinNetworkNodeToNode::Out::NetworkInfo(
              node_operation.is_part_of_public_network(),
              node_operation.get_last_recovered_signed_idx(),
              this->network.ledger_secrets->get(
                args.tx, existing_node_info->ledger_secret_seqno),
              *this->network.identity,
              active_service->status,
              existing_node_info->endorsed_certificate,
              node_operation.get_cose_signatures_config());

            return make_success(rep);
          }

          if (node_status == NodeStatus::PENDING)
          {
            // Only return node status and ID
            return make_success(rep);
          }

          return make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidNodeState,
            fmt::format(
              "Joining node is not in expected state ({}).", node_status));
        }

        if (consensus != nullptr && !this->node_operation.can_replicate())
        {
          auto primary_id = consensus->primary();
          if (primary_id.has_value())
          {
            const auto address = node::get_redirect_address_for_node(
              args, args.tx, primary_id.value());
            if (!address.has_value())
            {
              return already_populated_response();
            }

            args.rpc_ctx->set_response_header(
              http::headers::LOCATION,
              fmt::format("https://{}/node/join", address.value()));

            return make_error(
              HTTP_STATUS_PERMANENT_REDIRECT,
              ccf::errors::NodeCannotHandleRequest,
              "Node is not primary; cannot handle write");
          }

          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            "Primary unknown");
        }

        // If the node does not exist, add it to the KV in state pending
        return add_node(
          args.tx,
          args.rpc_ctx->get_session_context()->caller_cert,
          in,
          NodeStatus::PENDING,
          active_service->status);
      };
      make_endpoint("/join", HTTP_POST, json_adapter(accept), no_auth_required)
        .set_forwarding_required(endpoints::ForwardingRequired::Never)
        .set_openapi_hidden(true)
        .install();

      auto set_retired_committed = [this](auto& ctx, nlohmann::json&&) {
        auto nodes = ctx.tx.rw(network.nodes);
        nodes->foreach([&nodes](const auto& node_id, auto node_info) {
          auto gc_node = nodes->get_globally_committed(node_id);
          if (
            gc_node.has_value() &&
            gc_node->status == ccf::NodeStatus::RETIRED &&
            !node_info.retired_committed)
          {
            // Set retired_committed on nodes for which RETIRED status
            // has been committed.
            node_info.retired_committed = true;
            nodes->put(node_id, node_info);

            LOG_DEBUG_FMT("Setting retired_committed on node {}", node_id);
          }
          return true;
        });

        return make_success();
      };
      make_endpoint(
        "network/nodes/set_retired_committed",
        HTTP_POST,
        json_adapter(set_retired_committed),
        {std::make_shared<NodeCertAuthnPolicy>()})
        .set_openapi_hidden(true)
        .install();

      auto get_state = [this](auto& args, nlohmann::json&&) {
        GetState::Out result;
        auto [s, rts, lrs] = this->node_operation.state();
        result.node_id = this->context.get_node_id();
        result.state = s;
        result.recovery_target_seqno = rts;
        result.last_recovered_seqno = lrs;
        result.startup_seqno =
          this->node_operation.get_startup_snapshot_seqno();

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

        auto node_configuration_subsystem =
          this->context.get_subsystem<NodeConfigurationSubsystem>();
        if (!node_configuration_subsystem)
        {
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            "NodeConfigurationSubsystem is not available");
        }
        result.stop_notice =
          node_configuration_subsystem->has_received_stop_notice();

        return make_success(result);
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
          q.node_id = context.get_node_id();
          q.raw = node_quote_info.quote;
          q.endorsements = node_quote_info.endorsements;
          q.format = node_quote_info.format;
          q.uvm_endorsements = node_quote_info.uvm_endorsements;

          auto nodes = args.tx.ro(network.nodes);
          auto node_info = nodes->get(context.get_node_id());
          if (node_info.has_value() && node_info->code_digest.has_value())
          {
            q.measurement = node_info->code_digest.value();
          }
          else
          {
            auto measurement =
              AttestationProvider::get_measurement(node_quote_info);
            if (measurement.has_value())
            {
              q.measurement = measurement.value().hex_str();
            }
            else
            {
              return make_error(
                HTTP_STATUS_INTERNAL_SERVER_ERROR,
                ccf::errors::InvalidQuote,
                "Failed to extract code id from node quote.");
            }
          }

          return make_success(q);
        }

        if (result == ApiResult::NotFound)
        {
          return make_error(
            HTTP_STATUS_NOT_FOUND,
            ccf::errors::ResourceNotFound,
            "Could not find node quote.");
        }

        return make_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          fmt::format("Error code: {}", ccf::api_result_to_str(result)));
      };
      make_read_only_endpoint(
        "/quotes/self",
        HTTP_GET,
        json_read_only_adapter(get_quote),
        no_auth_required)
        .set_auto_schema<void, Quote>()
        .set_forwarding_required(endpoints::ForwardingRequired::Never)
        .install();
      make_read_only_endpoint(
        "/attestations/self",
        HTTP_GET,
        json_read_only_adapter(get_quote),
        no_auth_required)
        .set_auto_schema<void, Attestation>()
        .set_forwarding_required(endpoints::ForwardingRequired::Never)
        .install();

      auto get_quotes = [this](auto& args, nlohmann::json&&) {
        GetQuotes::Out result;

        auto nodes = args.tx.ro(network.nodes);
        nodes->foreach([&quotes = result.quotes](
                         const auto& node_id, const auto& node_info) {
          if (node_info.status == ccf::NodeStatus::TRUSTED)
          {
            Quote q;
            q.node_id = node_id;
            q.raw = node_info.quote_info.quote;
            q.endorsements = node_info.quote_info.endorsements;
            q.format = node_info.quote_info.format;
            q.uvm_endorsements = node_info.quote_info.uvm_endorsements;

            if (node_info.code_digest.has_value())
            {
              q.measurement = node_info.code_digest.value();
            }
            else
            {
              auto measurement =
                AttestationProvider::get_measurement(node_info.quote_info);
              if (measurement.has_value())
              {
                q.measurement = measurement.value().hex_str();
              }
            }
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

      auto get_attestations =
        [get_quotes](auto& args, nlohmann::json&& params) {
          auto res = get_quotes(args, std::move(params));
          const auto* body = std::get_if<nlohmann::json>(&res);
          if (body != nullptr)
          {
            auto result = nlohmann::json::object();
            result["attestations"] = (*body)["quotes"];
            return make_success(result);
          }

          return res;
        };
      make_read_only_endpoint(
        "/attestations",
        HTTP_GET,
        json_read_only_adapter(get_attestations),
        no_auth_required)
        .set_auto_schema<GetAttestations>()
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
          out.recovery_count = service_value.recovery_count.value_or(0);
          out.service_data = service_value.service_data;
          out.current_service_create_txid =
            service_value.current_service_create_txid;
          if (consensus != nullptr)
          {
            out.current_view = consensus->get_view();
            auto primary_id = consensus->primary();
            if (primary_id.has_value())
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
        .set_auto_schema<void, GetNetworkInfo::Out>()
        .install();

      auto service_previous_identity = [](auto& args, nlohmann::json&&) {
        auto psi_handle = args.tx.template ro<ccf::PreviousServiceIdentity>(
          ccf::Tables::PREVIOUS_SERVICE_IDENTITY);
        const auto psi = psi_handle->get();
        if (psi.has_value())
        {
          GetServicePreviousIdentity::Out out;
          out.previous_service_identity = psi.value();
          return make_success(out);
        }

        return make_error(
          HTTP_STATUS_NOT_FOUND,
          ccf::errors::ResourceNotFound,
          "This service is not a recovery of a previous service.");
      };
      make_read_only_endpoint(
        "/service/previous_identity",
        HTTP_GET,
        json_read_only_adapter(service_previous_identity),
        no_auth_required)
        .set_auto_schema<void, GetServicePreviousIdentity::Out>()
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
          // Convert the query argument to a JSON string, try to parse it as
          // a NodeStatus, return an error if this doesn't work
          try
          {
            status = nlohmann::json(status_str.value()).get<NodeStatus>();
          }
          catch (const ccf::JsonParseError& e)
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
        nodes->foreach([this, host, port, status, &out, nodes](
                         const NodeId& nid, const NodeInfo& ni) {
          if (status.has_value() && status.value() != ni.status)
          {
            return true;
          }

          // Match on any interface
          bool is_matched = false;
          for (auto const& interface : ni.rpc_interfaces)
          {
            const auto& [pub_host, pub_port] =
              split_net_address(interface.second.published_address);

            if (
              (!host.has_value() || host.value() == pub_host) &&
              (!port.has_value() || port.value() == pub_port))
            {
              is_matched = true;
              break;
            }
          }

          if (!is_matched)
          {
            return true;
          }

          bool is_primary = false;
          if (consensus != nullptr)
          {
            is_primary = consensus->primary() == nid;
          }

          out.nodes.push_back(
            {nid,
             ni.status,
             is_primary,
             ni.rpc_interfaces,
             ni.node_data,
             nodes->get_version_of_previous_write(nid).value_or(0)});
          return true;
        });

        return make_success(out);
      };
      make_read_only_endpoint(
        "/network/nodes",
        HTTP_GET,
        json_read_only_adapter(get_nodes),
        no_auth_required)
        .set_auto_schema<void, GetNodes::Out>()
        .add_query_parameter<std::string>(
          "host", ccf::endpoints::OptionalParameter)
        .add_query_parameter<std::string>(
          "port", ccf::endpoints::OptionalParameter)
        .add_query_parameter<std::string>(
          "status", ccf::endpoints::OptionalParameter)
        .install();

      auto get_removable_nodes = [this](auto& args, nlohmann::json&&) {
        GetNodes::Out out;

        auto nodes = args.tx.ro(this->network.nodes);
        nodes->foreach(
          [&out, nodes](const NodeId& node_id, const NodeInfo& /*ni*/) {
            // Only nodes whose retire_committed status is committed can be
            // safely removed, because any primary elected from here on would
            // consider them retired, and would consequently not need their
            // input in any quorum. We must therefore read the KV at its
            // globally committed watermark, for the purpose of this RPC. Since
            // this transaction does not perform a write, it is safe to do this.
            auto node = nodes->get_globally_committed(node_id);
            if (
              node.has_value() && node->status == ccf::NodeStatus::RETIRED &&
              node->retired_committed)
            {
              out.nodes.push_back(
                {node_id,
                 node->status,
                 false /* is_primary */,
                 node->rpc_interfaces,
                 node->node_data,
                 nodes->get_version_of_previous_write(node_id).value_or(0)});
            }
            return true;
          });

        return make_success(out);
      };

      make_read_only_endpoint(
        "/network/removable_nodes",
        HTTP_GET,
        json_read_only_adapter(get_removable_nodes),
        no_auth_required)
        .set_auto_schema<void, GetNodes::Out>()
        .install();

      auto delete_retired_committed_node =
        [this](auto& args, nlohmann::json&&) {
          GetNodes::Out out;

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

          auto nodes = args.tx.rw(this->network.nodes);
          if (!nodes->has(node_id))
          {
            return make_error(
              HTTP_STATUS_NOT_FOUND,
              ccf::errors::ResourceNotFound,
              "No such node");
          }

          auto node_endorsed_certificates =
            args.tx.rw(network.node_endorsed_certificates);

          // A node's retirement is only complete when the
          // transition of retired_committed is itself committed,
          // i.e. when the next eligible primary is guaranteed to
          // be aware the retirement is committed.
          // As a result, the handler must check node info at the
          // current committed level, rather than at the end of the
          // local suffix.
          // While this transaction does execute a write, it specifically
          // deletes the value it reads from. It is therefore safe to
          // execute on the basis of a potentially stale read-set,
          // which get_globally_committed() typically produces.
          auto node = nodes->get_globally_committed(node_id);
          if (
            node.has_value() && node->status == ccf::NodeStatus::RETIRED &&
            node->retired_committed)
          {
            nodes->remove(node_id);
            node_endorsed_certificates->remove(node_id);

            auto* sealed_recovery_keys =
              args.tx.template rw<SealedRecoveryKeys>(Tables::SEALED_RECOVERY_KEYS);
            sealed_recovery_keys->remove(node_id);
          }
          else
          {
            return make_error(
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::NodeNotRetiredCommitted,
              "Node is not completely retired");
          }

          return make_success(true);
        };

      make_endpoint(
        "/network/nodes/{node_id}",
        HTTP_DELETE,
        json_adapter(delete_retired_committed_node),
        no_auth_required)
        .set_auto_schema<void, bool>()
        .install();

      auto get_self_signed_certificate =
        [this](auto& /*args*/, nlohmann::json&&) {
          return SelfSignedNodeCertificateInfo{
            this->node_operation.get_self_signed_node_certificate()};
        };
      make_command_endpoint(
        "/self_signed_certificate",
        HTTP_GET,
        json_command_adapter(get_self_signed_certificate),
        no_auth_required)
        .set_forwarding_required(endpoints::ForwardingRequired::Never)
        .set_auto_schema<void, SelfSignedNodeCertificateInfo>()
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
        auto& ni = info.value();
        return make_success(GetNode::Out{
          node_id,
          ni.status,
          is_primary,
          ni.rpc_interfaces,
          ni.node_data,
          nodes->get_version_of_previous_write(node_id).value_or(0)});
      };
      make_read_only_endpoint(
        "/network/nodes/{node_id}",
        HTTP_GET,
        json_read_only_adapter(get_node_info),
        no_auth_required)
        .set_auto_schema<void, GetNode::Out>()
        .install();

      auto get_self_node = [this](auto& args, nlohmann::json&&) {
        auto node_id = this->context.get_node_id();
        auto nodes = args.tx.ro(this->network.nodes);
        auto info = nodes->get(node_id);

        bool is_primary = false;
        if (consensus != nullptr)
        {
          auto primary = consensus->primary();
          if (primary.has_value() && primary.value() == node_id)
          {
            is_primary = true;
          }
        }

        if (info.has_value())
        {
          // Answers from the KV are preferred, as they are more up-to-date,
          // especially status and node_data.
          auto& ni = info.value();
          return make_success(GetNode::Out{
            node_id,
            ni.status,
            is_primary,
            ni.rpc_interfaces,
            ni.node_data,
            nodes->get_version_of_previous_write(node_id).value_or(0)});
        }

        // If the node isn't in its KV yet, fall back to configuration
        auto node_configuration_subsystem =
          this->context.get_subsystem<NodeConfigurationSubsystem>();
        if (!node_configuration_subsystem)
        {
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            "NodeConfigurationSubsystem is not available");
        }
        const auto& node_startup_config =
          node_configuration_subsystem->get().node_config;
        return make_success(GetNode::Out{
          node_id,
          ccf::NodeStatus::PENDING,
          is_primary,
          node_startup_config.network.rpc_interfaces,
          node_startup_config.node_data,
          0});
      };
      make_read_only_endpoint(
        "/network/nodes/self",
        HTTP_GET,
        json_read_only_adapter(get_self_node),
        no_auth_required)
        .set_auto_schema<void, GetNode::Out>()
        .set_forwarding_required(endpoints::ForwardingRequired::Never)
        .install();

      auto get_primary_node = [this](auto& args, nlohmann::json&&) {
        if (consensus != nullptr)
        {
          auto primary_id = consensus->primary();
          if (!primary_id.has_value())
          {
            return make_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              "Primary unknown");
          }

          auto nodes = args.tx.ro(this->network.nodes);
          auto info = nodes->get(primary_id.value());
          if (!info)
          {
            return make_error(
              HTTP_STATUS_NOT_FOUND,
              ccf::errors::ResourceNotFound,
              "Node not found");
          }

          auto& ni = info.value();
          return make_success(GetNode::Out{
            primary_id.value(),
            ni.status,
            true,
            ni.rpc_interfaces,
            ni.node_data,
            nodes->get_version_of_previous_write(primary_id.value())
              .value_or(0)});
        }

        return make_error(
          HTTP_STATUS_NOT_FOUND,
          ccf::errors::ResourceNotFound,
          "No configured consensus");
      };
      make_read_only_endpoint(
        "/network/nodes/primary",
        HTTP_GET,
        json_read_only_adapter(get_primary_node),
        no_auth_required)
        .set_auto_schema<void, GetNode::Out>()
        .install();

      auto head_primary = [this](auto& args) {
        if (this->node_operation.can_replicate())
        {
          args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        }
        else
        {
          if (consensus == nullptr)
          {
            args.rpc_ctx->set_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              "Consensus not initialised");
            return;
          }

          auto primary_id = consensus->primary();
          if (!primary_id.has_value())
          {
            args.rpc_ctx->set_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              "Primary unknown");
            return;
          }

          const auto address = node::get_redirect_address_for_node(
            args, args.tx, primary_id.value());
          if (!address.has_value())
          {
            return;
          }

          args.rpc_ctx->set_response_header(
            http::headers::LOCATION,
            fmt::format("https://{}/node/primary", address.value()));
          args.rpc_ctx->set_response_status(HTTP_STATUS_PERMANENT_REDIRECT);
        }
      };
      make_read_only_endpoint(
        "/primary", HTTP_HEAD, head_primary, no_auth_required)
        .set_forwarding_required(endpoints::ForwardingRequired::Never)
        .install();

      auto get_primary = [this](auto& args) {
        if (this->node_operation.can_replicate())
        {
          args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          return;
        }

        args.rpc_ctx->set_error(
          HTTP_STATUS_NOT_FOUND,
          ccf::errors::ResourceNotFound,
          "Node is not primary");
      };
      make_read_only_endpoint(
        "/primary", HTTP_GET, get_primary, no_auth_required)
        .set_forwarding_required(endpoints::ForwardingRequired::Never)
        .install();

      auto get_backup = [this](auto& args) {
        if (!this->node_operation.can_replicate())
        {
          args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          return;
        }

        args.rpc_ctx->set_error(
          HTTP_STATUS_NOT_FOUND,
          ccf::errors::ResourceNotFound,
          "Node is not backup");
      };
      make_read_only_endpoint("/backup", HTTP_GET, get_backup, no_auth_required)
        .set_forwarding_required(endpoints::ForwardingRequired::Never)
        .install();

      auto consensus_config = [this](auto& /*args*/, nlohmann::json&&) {
        // Query node for configurations, separate current from pending
        if (consensus != nullptr)
        {
          auto cfg = consensus->get_latest_configuration();
          ConsensusConfig cc;
          for (auto& [nid, ninfo] : cfg)
          {
            cc.emplace(
              nid.value(),
              ConsensusNodeConfig{
                fmt::format("{}:{}", ninfo.hostname, ninfo.port)});
          }
          return make_success(cc);
        }

        return make_error(
          HTTP_STATUS_NOT_FOUND,
          ccf::errors::ResourceNotFound,
          "No configured consensus");
      };

      make_command_endpoint(
        "/config",
        HTTP_GET,
        json_command_adapter(consensus_config),
        no_auth_required)
        .set_forwarding_required(endpoints::ForwardingRequired::Never)
        .set_auto_schema<void, ConsensusConfig>()
        .install();

      auto consensus_state = [this](auto& /*args*/, nlohmann::json&&) {
        if (consensus != nullptr)
        {
          return make_success(ConsensusConfigDetails{consensus->get_details()});
        }

        return make_error(
          HTTP_STATUS_NOT_FOUND,
          ccf::errors::ResourceNotFound,
          "No configured consensus");
      };

      make_command_endpoint(
        "/consensus",
        HTTP_GET,
        json_command_adapter(consensus_state),
        no_auth_required)
        .set_forwarding_required(endpoints::ForwardingRequired::Never)
        .set_auto_schema<void, ConsensusConfigDetails>()
        .install();

      auto memory_usage = [](auto& args) {
        ccf::pal::MallocInfo info;
        if (ccf::pal::get_mallinfo(info))
        {
          MemoryUsage::Out mu(info);
          args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          args.rpc_ctx->set_response_header(
            http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);
          args.rpc_ctx->set_response_body(nlohmann::json(mu).dump());
          return;
        }

        args.rpc_ctx->set_response_status(HTTP_STATUS_INTERNAL_SERVER_ERROR);
        args.rpc_ctx->set_response_body("Failed to read memory usage");
      };

      make_command_endpoint("/memory", HTTP_GET, memory_usage, no_auth_required)
        .set_forwarding_required(endpoints::ForwardingRequired::Never)
        .set_auto_schema<MemoryUsage>()
        .install();

      auto node_metrics = [this](auto& args) {
        NodeMetrics nm;
        nm.sessions = node_operation.get_session_metrics();

        args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        args.rpc_ctx->set_response_header(
          http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);
        args.rpc_ctx->set_response_body(nlohmann::json(nm).dump());
      };

      make_command_endpoint(
        "/metrics", HTTP_GET, node_metrics, no_auth_required)
        .set_forwarding_required(endpoints::ForwardingRequired::Never)
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
        auto js_engine_map = args.tx.ro(this->network.js_engine);
        JavaScriptMetrics m;
        m.bytecode_size = bytecode_size;
        m.bytecode_used =
          version_val->get() == std::string(ccf::quickjs_version);

        auto options = js_engine_map->get().value_or(ccf::JSRuntimeOptions{});
        m.max_stack_size = options.max_stack_bytes;
        m.max_heap_size = options.max_heap_bytes;
        m.max_execution_time = options.max_execution_time_ms;
        m.max_cached_interpreters = options.max_cached_interpreters;

        return m;
      };

      make_read_only_endpoint(
        "/js_metrics",
        HTTP_GET,
        json_read_only_adapter(js_metrics),
        no_auth_required)
        .set_auto_schema<void, JavaScriptMetrics>()
        .install();

      auto version = [](auto&, nlohmann::json&&) {
        GetVersion::Out result;
        result.ccf_version = ccf::ccf_version;
        result.quickjs_version = ccf::quickjs_version;
        result.unsafe = false;

        return make_success(result);
      };

      make_command_endpoint(
        "/version", HTTP_GET, json_command_adapter(version), no_auth_required)
        .set_forwarding_required(endpoints::ForwardingRequired::Never)
        .set_auto_schema<GetVersion>()
        .install();

      auto create = [this](auto& ctx, nlohmann::json&& params) {
        LOG_INFO_FMT("Processing create RPC");

        bool recovering = node_operation.is_reading_public_ledger();

        // This endpoint can only be called once, directly from the starting
        // node for the genesis or end of public recovery transaction to
        // initialise the service
        if (!node_operation.is_in_initialised_state() && !recovering)
        {
          return make_error(
            HTTP_STATUS_FORBIDDEN,
            ccf::errors::InternalError,
            "Node is not in initial state.");
        }

        const auto in = params.get<CreateNetworkNodeToNode::In>();

        if (InternalTablesAccess::is_service_created(ctx.tx, in.service_cert))
        {
          return make_error(
            HTTP_STATUS_FORBIDDEN,
            ccf::errors::InternalError,
            "Service is already created.");
        }

        InternalTablesAccess::create_service(
          ctx.tx, in.service_cert, in.create_txid, in.service_data, recovering);

        // Retire all nodes, in case there are any (i.e. post recovery)
        InternalTablesAccess::retire_active_nodes(ctx.tx);

        // Genesis transaction (i.e. not after recovery)
        if (in.genesis_info.has_value())
        {
          // Note that it is acceptable to start a network without any member
          // having a recovery share. The service will check that at least one
          // recovery member is added before the service is opened.
          for (const auto& info : in.genesis_info->members)
          {
            InternalTablesAccess::add_member(ctx.tx, info);
          }

          InternalTablesAccess::init_configuration(
            ctx.tx, in.genesis_info->service_configuration);
          InternalTablesAccess::set_constitution(
            ctx.tx, in.genesis_info->constitution);
        }
        else
        {
          // On recovery, force a new ledger chunk
          auto* tx_ = static_cast<ccf::kv::CommittableTx*>(&ctx.tx);
          if (tx_ == nullptr)
          {
            throw std::logic_error("Could not cast tx to CommittableTx");
          }
          tx_->set_tx_flag(
            ccf::kv::CommittableTx::TxFlag::LEDGER_CHUNK_BEFORE_THIS_TX);
        }

        auto endorsed_certificates =
          ctx.tx.rw(network.node_endorsed_certificates);
        endorsed_certificates->put(in.node_id, in.node_endorsed_certificate);

        NodeInfo node_info = {
          in.node_info_network,
          {in.quote_info},
          in.public_encryption_key,
          NodeStatus::TRUSTED,
          std::nullopt,
          in.measurement.hex_str(),
          in.certificate_signing_request,
          in.public_key,
          in.node_data};
        InternalTablesAccess::add_node(ctx.tx, in.node_id, node_info);

        if (in.sealed_recovery_key.has_value())
        {
          auto* sealed_recovery_keys =
            ctx.tx.template rw<SealedRecoveryKeys>(Tables::SEALED_RECOVERY_KEYS);
          sealed_recovery_keys->put(in.node_id, in.sealed_recovery_key.value());
        }

        node_operation.shuffle_sealed_shares(ctx.tx);

        if (
          in.quote_info.format != QuoteFormat::amd_sev_snp_v1 ||
          !in.snp_uvm_endorsements.has_value())
        {
          // For improved serviceability on SNP, do not record trusted
          // measurements if UVM endorsements are available
          InternalTablesAccess::trust_node_measurement(
            ctx.tx, in.measurement, in.quote_info.format);
        }

        switch (in.quote_info.format)
        {
          case QuoteFormat::insecure_virtual:
          {
            auto host_data = AttestationProvider::get_host_data(in.quote_info);
            if (host_data.has_value())
            {
              InternalTablesAccess::trust_node_virtual_host_data(
                ctx.tx, host_data.value());
            }
            else
            {
              LOG_FAIL_FMT("Unable to extract host data from virtual quote");
            }
            break;
          }

          case QuoteFormat::amd_sev_snp_v1:
          {
            auto host_data =
              AttestationProvider::get_host_data(in.quote_info).value();
            InternalTablesAccess::trust_node_snp_host_data(
              ctx.tx, host_data, in.snp_security_policy);

            InternalTablesAccess::trust_node_uvm_endorsements(
              ctx.tx, in.snp_uvm_endorsements);

            auto attestation =
              AttestationProvider::get_snp_attestation(in.quote_info).value();
            InternalTablesAccess::trust_node_snp_tcb_version(
              ctx.tx, attestation);
            break;
          }

          default:
          {
            break;
          }
        }

        std::optional<ccf::ClaimsDigest::Digest> digest =
          ccf::get_create_tx_claims_digest(ctx.tx);
        if (digest.has_value())
        {
          auto digest_value = digest.value();
          ctx.rpc_ctx->set_claims_digest(std::move(digest_value));
        }

        this->node_operation.self_healing_open().reset_state(ctx.tx);
        this->node_operation.self_healing_open().try_start(ctx.tx, recovering);

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
        catch (const ccf::JsonParseError& e)
        {
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            "Unable to parse body.");
        }

        auto issuers = ctx.tx.ro(this->network.jwt_issuers);
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

      auto get_jwt_metrics =
        [this](auto& /*args*/, const nlohmann::json& /*params*/) {
          return make_success(jwt_refresh_metrics);
        };
      make_read_only_endpoint(
        "/jwt_keys/refresh/metrics",
        HTTP_GET,
        json_read_only_adapter(get_jwt_metrics),
        no_auth_required)
        .set_auto_schema<void, JWTRefreshMetrics>()
        .install();

      auto service_config_handler =
        [this](auto& args, const nlohmann::json& /*params*/) {
          return make_success(args.tx.ro(network.config)->get());
        };
      make_endpoint(
        "/service/configuration",
        HTTP_GET,
        json_adapter(service_config_handler),
        no_auth_required)
        .set_forwarding_required(endpoints::ForwardingRequired::Never)
        .set_auto_schema<void, ServiceConfiguration>()
        .install();

      auto list_indexing_strategies = [this](
                                        auto& /*args*/,
                                        const nlohmann::json& /*params*/) {
        return make_success(this->context.get_indexing_strategies().describe());
      };

      make_endpoint(
        "/index/strategies",
        HTTP_GET,
        json_adapter(list_indexing_strategies),
        no_auth_required)
        .set_forwarding_required(endpoints::ForwardingRequired::Never)
        .set_auto_schema<void, nlohmann::json>()
        .install();

      auto get_ready_app =
        [this](const ccf::endpoints::ReadOnlyEndpointContext& ctx) {
          auto node_configuration_subsystem =
            this->context.get_subsystem<NodeConfigurationSubsystem>();
          if (!node_configuration_subsystem)
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              "NodeConfigurationSubsystem is not available");
            return;
          }
          if (
            !node_configuration_subsystem->has_received_stop_notice() &&
            this->node_operation.is_part_of_network() &&
            this->node_operation.is_user_frontend_open())
          {
            ctx.rpc_ctx->set_response_status(HTTP_STATUS_NO_CONTENT);
          }
          else
          {
            ctx.rpc_ctx->set_response_status(HTTP_STATUS_SERVICE_UNAVAILABLE);
          }
          return;
        };
      make_read_only_endpoint(
        "/ready/app", HTTP_GET, get_ready_app, no_auth_required)
        .set_auto_schema<void, void>()
        .set_forwarding_required(endpoints::ForwardingRequired::Never)
        .install();

      auto get_ready_gov =
        [this](const ccf::endpoints::ReadOnlyEndpointContext& ctx) {
          auto node_configuration_subsystem =
            this->context.get_subsystem<NodeConfigurationSubsystem>();
          if (!node_configuration_subsystem)
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              "NodeConfigurationSubsystem is not available");
            return;
          }
          if (
            !node_configuration_subsystem->has_received_stop_notice() &&
            this->node_operation.is_accessible_to_members() &&
            this->node_operation.is_member_frontend_open())
          {
            ctx.rpc_ctx->set_response_status(HTTP_STATUS_NO_CONTENT);
          }
          else
          {
            ctx.rpc_ctx->set_response_status(HTTP_STATUS_SERVICE_UNAVAILABLE);
          }
          return;
        };
      make_read_only_endpoint(
        "/ready/gov", HTTP_GET, get_ready_gov, no_auth_required)
        .set_auto_schema<void, void>()
        .set_forwarding_required(endpoints::ForwardingRequired::Never)
        .install();

      ccf::node::init_self_healing_open_handlers(*this, context);

      ccf::node::init_file_serving_handlers(*this, context);
    }
  };

  class NodeRpcFrontend : public RpcFrontend
  {
  protected:
    NodeEndpoints node_endpoints;

  public:
    NodeRpcFrontend(NetworkState& network, ccf::AbstractNodeContext& context) :
      RpcFrontend(*network.tables, node_endpoints, context),
      node_endpoints(network, context)
    {}
  };
}
