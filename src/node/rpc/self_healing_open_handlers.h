// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/common_auth_policies.h"
#include "ccf/endpoint_context.h"
#include "ccf/json_handler.h"
#include "ccf/node_context.h"
#include "ccf/odata_error.h"
#include "ccf/service/tables/self_healing_open.h"
#include "node/node_configuration_subsystem.h"
#include "node/rpc/node_frontend_utils.h"
#include "node/self_healing_open_impl.h"

namespace ccf::node
{
  template <typename Input>
  using SelfHealingOpenHandler = std::function<std::optional<ErrorDetails>(
    endpoints::EndpointContext& args, Input& in)>;

  template <typename Input>
  static HandlerJsonParamsAndForward wrap_self_healing_open(
    SelfHealingOpenHandler<Input> cb, ccf::AbstractNodeContext& node_context)
  {
    return [cb = std::move(cb), node_context](
             endpoints::EndpointContext& args, const nlohmann::json& params) {
      auto config = node_context.get_subsystem<NodeConfigurationSubsystem>();
      auto node_operation = node_context.get_subsystem<AbstractNodeOperation>();
      if (config == nullptr || node_operation == nullptr)
      {
        return make_error(
          HTTP_STATUS_BAD_REQUEST,
          ccf::errors::InvalidNodeState,
          "Unable to open self-healing-open subsystems");
      }

      if (!config->get().node_config.recover.self_healing_open.has_value())
      {
        return make_error(
          HTTP_STATUS_BAD_REQUEST,
          ccf::errors::InvalidNodeState,
          "This node cannot do self-healing-open");
      }

      auto in = params.get<Input>();
      self_healing_open::RequestNodeInfo info = in.info;

      // ---- Validate the quote and store the node info ----

      auto cert_der = ccf::crypto::public_key_der_from_cert(
        args.rpc_ctx->get_session_context()->caller_cert);

      pal::PlatformAttestationMeasurement measurement;
      QuoteVerificationResult verify_result = node_operation->verify_quote(
        args.tx, info.quote_info, cert_der, measurement);
      if (verify_result != QuoteVerificationResult::Verified)
      {
        const auto [code, message] = quote_verification_error(verify_result);
        LOG_FAIL_FMT(
          "Self-healing-open message from {} has an invalid quote: {} ({})",
          info.identity.intrinsic_id,
          code,
          message);
        return make_error(code, ccf::errors::InvalidQuote, message);
      }

      LOG_TRACE_FMT(
        "Self-healing-open message from intrinsic id {} has a valid quote",
        info.identity.intrinsic_id);

      // Validating that we haven't heard from this node before, of if we have
      // that the cert hasn't changed
      auto* node_info_handle = args.tx.rw<self_healing_open::NodeInfoMap>(
        Tables::SELF_HEALING_OPEN_NODES);
      auto existing_node_info =
        node_info_handle->get(info.identity.intrinsic_id);

      if (existing_node_info.has_value())
      {
        // If we have seen this node before, check that the cert is the same
        if (existing_node_info->cert_der != cert_der)
        {
          auto message = fmt::format(
            "Self-healing-open message from intrinsic id {} is invalid: "
            "certificate has changed",
            info.identity.intrinsic_id);
          LOG_FAIL_FMT("{}", message);
          return make_error(
            HTTP_STATUS_BAD_REQUEST, ccf::errors::NodeAlreadyExists, message);
        }
      }
      else
      {
        self_healing_open::NodeInfo src_info{
          .quote_info = info.quote_info,
          .identity = info.identity,
          .cert_der = cert_der,
          .service_identity = info.service_identity};
        node_info_handle->put(info.identity.intrinsic_id, src_info);
      }

      // ---- Run callback ----

      auto ret = cb(args, in);
      if (ret.has_value())
      {
        jsonhandler::JsonAdapterResponse res = ret.value();
        return res;
      }

      // ---- Advance state machine ----

      try
      {
        node_operation->self_healing_open().advance(args.tx, false);
      }
      catch (const std::logic_error& e)
      {
        LOG_FAIL_FMT("Self-healing-open failed to advance state: {}", e.what());
        return make_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          fmt::format(
            "Failed to advance self-healing-open state: {}", e.what()));
      }

      return make_success();
    };
  }

  static void init_self_healing_open_handlers(
    endpoints::EndpointRegistry& registry,
    ccf::AbstractNodeContext& node_context)
  {
    auto self_healing_open_gossip =
      [](
        auto& args,
        self_healing_open::GossipRequest in) -> std::optional<ErrorDetails> {
      LOG_TRACE_FMT(
        "Self-healing-open: receive gossip from {}",
        in.info.identity.intrinsic_id);

      // Stop accepting gossips once a node has voted
      auto chosen_replica = args.tx.template ro<self_healing_open::ChosenNode>(
        Tables::SELF_HEALING_OPEN_CHOSEN_NODE);
      if (chosen_replica->get().has_value())
      {
        return ErrorDetails{
          .status = HTTP_STATUS_INTERNAL_SERVER_ERROR,
          .code = ccf::errors::InternalError,
          .msg = fmt::format(
            "This node has already voted for {}",
            chosen_replica->get().value())};
      }

      auto gossip_handle = args.tx.template rw<self_healing_open::Gossips>(
        Tables::SELF_HEALING_OPEN_GOSSIPS);
      if (gossip_handle->get(in.info.identity.intrinsic_id).has_value())
      {
        LOG_INFO_FMT(
          "Node {} already gossiped, skipping", in.info.identity.intrinsic_id);
        return std::nullopt;
      }
      gossip_handle->put(in.info.identity.intrinsic_id, in.txid);
      return std::nullopt;
    };
    registry
      .make_endpoint(
        "/self_healing_open/gossip",
        HTTP_PUT,
        json_adapter(wrap_self_healing_open<self_healing_open::GossipRequest>(
          self_healing_open_gossip, node_context)),
        no_auth_required)
      .set_forwarding_required(endpoints::ForwardingRequired::Never)
      .set_openapi_hidden(true)
      .install();

    auto self_healing_open_vote =
      [](auto& args, self_healing_open::TaggedWithNodeInfo in)
      -> std::optional<ErrorDetails> {
      LOG_TRACE_FMT(
        "Self-healing-open: receive vote from {}",
        in.info.identity.intrinsic_id);

      args.tx
        .template rw<self_healing_open::Votes>(Tables::SELF_HEALING_OPEN_VOTES)
        ->insert(in.info.identity.intrinsic_id);

      return std::nullopt;
    };
    registry
      .make_endpoint(
        "/self_healing_open/vote",
        HTTP_PUT,
        json_adapter(
          wrap_self_healing_open<self_healing_open::TaggedWithNodeInfo>(
            self_healing_open_vote, node_context)),
        no_auth_required)
      .set_forwarding_required(endpoints::ForwardingRequired::Never)
      .set_openapi_hidden(true)
      .install();

    auto self_healing_open_iamopen =
      [](auto& args, self_healing_open::TaggedWithNodeInfo in)
      -> std::optional<ErrorDetails> {
      LOG_TRACE_FMT(
        "Self-healing-open: receive IAmOpen from {}",
        in.info.identity.intrinsic_id);
      args.tx
        .template rw<self_healing_open::SMState>(
          Tables::SELF_HEALING_OPEN_SM_STATE)
        ->put(self_healing_open::StateMachine::JOINING);
      args.tx
        .template rw<self_healing_open::ChosenNode>(
          Tables::SELF_HEALING_OPEN_CHOSEN_NODE)
        ->put(in.info.identity.intrinsic_id);
      return std::nullopt;
    };
    registry
      .make_endpoint(
        "/self_healing_open/iamopen",
        HTTP_PUT,
        json_adapter(
          wrap_self_healing_open<self_healing_open::TaggedWithNodeInfo>(
            self_healing_open_iamopen, node_context)),
        no_auth_required)
      .set_forwarding_required(endpoints::ForwardingRequired::Never)
      .set_openapi_hidden(true)
      .install();

    auto self_healing_open_timeout =
      [&](auto& args, const nlohmann::json& params) {
        (void)params;
        auto config = node_context.get_subsystem<NodeConfigurationSubsystem>();
        auto node_operation =
          node_context.get_subsystem<AbstractNodeOperation>();
        if (config == nullptr || node_operation == nullptr)
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidNodeState,
            "Unable to open self-healing-open subsystems");
        }

        if (!config->get().node_config.recover.self_healing_open.has_value())
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidNodeState,
            "This node cannot do self-healing-open");
        }

        LOG_TRACE_FMT("Self-healing-open timeout received");

        // Must ensure that the request originates from the primary
        auto primary_id = node_operation->get_primary();
        if (!primary_id.has_value())
        {
          LOG_FAIL_FMT("self-healing-open timeout: primary unknown");
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            "Primary is unknown");
        }
        const auto& sig_auth_ident =
          args.template get_caller<ccf::NodeCertAuthnIdentity>();
        if (primary_id.value() != sig_auth_ident.node_id)
        {
          LOG_FAIL_FMT(
            "self-healing-open timeout: request does not originate from "
            "primary");
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            "Request does not originate from primary.");
        }

        try
        {
          node_operation->self_healing_open().advance(args.tx, true);
        }
        catch (const std::logic_error& e)
        {
          LOG_FAIL_FMT(
            "Self-healing-open gossip failed to advance state: {}", e.what());
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            fmt::format(
              "Failed to advance self-healing-open state: {}", e.what()));
        }
        return make_success("Self-healing-open timeout processed successfully");
      };
    registry
      .make_endpoint(
        "/self_healing_open/timeout",
        HTTP_PUT,
        json_adapter(self_healing_open_timeout),
        {std::make_shared<NodeCertAuthnPolicy>()})
      .set_forwarding_required(endpoints::ForwardingRequired::Never)
      .set_openapi_hidden(true)
      .install();
  }
}
