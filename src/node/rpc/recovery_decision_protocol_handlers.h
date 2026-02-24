// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/common_auth_policies.h"
#include "ccf/crypto/verifier.h"
#include "ccf/endpoint_context.h"
#include "ccf/json_handler.h"
#include "ccf/node_context.h"
#include "ccf/odata_error.h"
#include "ccf/service/operator_feature.h"
#include "ccf/service/tables/nodes.h"
#include "ccf/service/tables/recovery_decision_protocol.h"
#include "node/node_configuration_subsystem.h"
#include "node/recovery_decision_protocol.h"
#include "node/rpc/node_frontend_utils.h"

namespace ccf::node
{
  template <typename Input>
  using RecoveryDecisionProtocolHandler =
    std::function<std::optional<ErrorDetails>(
      endpoints::EndpointContext& args, Input& in)>;

  template <typename Input>
  static HandlerJsonParamsAndForward wrap_recovery_decision_protocol(
    RecoveryDecisionProtocolHandler<Input> cb,
    ccf::AbstractNodeContext& node_context)
  {
    return [cb = std::move(cb), &node_context](
             endpoints::EndpointContext& args, const nlohmann::json& params) {
      auto config = node_context.get_subsystem<NodeConfigurationSubsystem>();
      auto node_operation = node_context.get_subsystem<AbstractNodeOperation>();
      if (config == nullptr || node_operation == nullptr)
      {
        return make_error(
          HTTP_STATUS_BAD_REQUEST,
          ccf::errors::InvalidNodeState,
          "Unable to open recovery-decision-protocol subsystems");
      }

      if (
        !config->get().node_config.sealing_recovery.has_value() ||
        !config->get()
           .node_config.sealing_recovery->recovery_decision_protocol
           .has_value())
      {
        return make_error(
          HTTP_STATUS_BAD_REQUEST,
          ccf::errors::InvalidNodeState,
          "This node cannot do recovery-decision-protocol");
      }

      auto in = params.get<Input>();
      recovery_decision_protocol::RequestNodeInfo info = in.info;

      // ---- Validate the quote against our store and store the node info ----

      auto cert_der = ccf::crypto::public_key_der_from_cert(
        args.rpc_ctx->get_session_context()->caller_cert);

      pal::PlatformAttestationMeasurement measurement;
      QuoteVerificationResult verify_result = node_operation->verify_quote(
        args.tx, info.quote_info, cert_der, measurement);
      if (verify_result != QuoteVerificationResult::Verified)
      {
        const auto [code, message] = quote_verification_error(verify_result);
        LOG_FAIL_FMT(
          "Recovery-decision-protocol message from {} has an invalid quote: {} "
          "({})",
          info.identity.intrinsic_id,
          code,
          message);
        return make_error(code, ccf::errors::InvalidQuote, message);
      }

      LOG_TRACE_FMT(
        "Recovery-decision-protocol message from intrinsic id {} has a valid "
        "quote",
        info.identity.intrinsic_id);

      // ---- The sender now has trusted code ----

      // Validating that we haven't heard from this node before, of if we have
      // that the cert hasn't changed
      auto* node_info_handle =
        args.tx.rw<recovery_decision_protocol::NodeInfoMap>(
          Tables::RECOVERY_DECISION_PROTOCOL_NODES);
      auto existing_node_info =
        node_info_handle->get(info.identity.intrinsic_id);

      if (existing_node_info.has_value())
      {
        // If we have seen this node before, check that the cert is the same
        if (existing_node_info->node_cert_der != cert_der)
        {
          auto message = fmt::format(
            "Recovery-decision-protocol message from intrinsic id {} is "
            "invalid: "
            "certificate public key has changed",
            info.identity.intrinsic_id);
          LOG_FAIL_FMT("{}", message);
          return make_error(
            HTTP_STATUS_BAD_REQUEST, ccf::errors::NodeAlreadyExists, message);
        }
      }
      else
      {
        recovery_decision_protocol::NodeInfo src_info{
          info,
          cert_der,
        };
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
        node_operation->recovery_decision_protocol().advance(args.tx, false);
      }
      catch (const std::logic_error& e)
      {
        LOG_FAIL_FMT(
          "Recovery-decision-protocol failed to advance state: {}", e.what());
        return make_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          fmt::format(
            "Failed to advance recovery-decision-protocol state: {}",
            e.what()));
      }

      return make_success();
    };
  }

  static void init_recovery_decision_protocol_handlers(
    endpoints::EndpointRegistry& registry,
    ccf::AbstractNodeContext& node_context)
  {
    auto recovery_decision_protocol_gossip =
      [](auto& args, recovery_decision_protocol::GossipRequest in)
      -> std::optional<ErrorDetails> {
      LOG_TRACE_FMT(
        "Recovery-decision-protocol: receive gossip from {}",
        in.info.identity.intrinsic_id);

      // Stop accepting gossips once a node has voted
      auto chosen_replica =
        args.tx.template ro<recovery_decision_protocol::ChosenNode>(
          Tables::RECOVERY_DECISION_PROTOCOL_CHOSEN_NODE);
      if (chosen_replica->get().has_value())
      {
        return ErrorDetails{
          .status = HTTP_STATUS_INTERNAL_SERVER_ERROR,
          .code = ccf::errors::InternalError,
          .msg = fmt::format(
            "This node has already voted for {}",
            chosen_replica->get().value())};
      }

      auto gossip_handle =
        args.tx.template rw<recovery_decision_protocol::Gossips>(
          Tables::RECOVERY_DECISION_PROTOCOL_GOSSIPS);
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
        "/recovery_decision_protocol/gossip",
        HTTP_PUT,
        json_adapter(wrap_recovery_decision_protocol<
                     recovery_decision_protocol::GossipRequest>(
          recovery_decision_protocol_gossip, node_context)),
        no_auth_required)
      .set_forwarding_required(endpoints::ForwardingRequired::Never)
      .set_openapi_hidden(true)
      .install();

    auto recovery_decision_protocol_vote =
      [](auto& args, recovery_decision_protocol::TaggedWithNodeInfo in)
      -> std::optional<ErrorDetails> {
      LOG_TRACE_FMT(
        "Recovery-decision-protocol: receive vote from {}",
        in.info.identity.intrinsic_id);

      args.tx
        .template rw<recovery_decision_protocol::Votes>(
          Tables::RECOVERY_DECISION_PROTOCOL_VOTES)
        ->insert(in.info.identity.intrinsic_id);

      return std::nullopt;
    };
    registry
      .make_endpoint(
        "/recovery_decision_protocol/vote",
        HTTP_PUT,
        json_adapter(wrap_recovery_decision_protocol<
                     recovery_decision_protocol::TaggedWithNodeInfo>(
          recovery_decision_protocol_vote, node_context)),
        no_auth_required)
      .set_forwarding_required(endpoints::ForwardingRequired::Never)
      .set_openapi_hidden(true)
      .install();

    auto recovery_decision_protocol_iamopen =
      [&node_context](auto& args, recovery_decision_protocol::IAmOpenRequest in)
      -> std::optional<ErrorDetails> {
      auto sm_state = args.tx
                        .template ro<recovery_decision_protocol::SMState>(
                          Tables::RECOVERY_DECISION_PROTOCOL_SM_STATE)
                        ->get();
      if (!sm_state.has_value())
      {
        throw std::logic_error(
          "Recovery-decision-protocol state machine state is not set");
      }

      if (
        sm_state.value() == recovery_decision_protocol::StateMachine::OPENING ||
        sm_state.value() == recovery_decision_protocol::StateMachine::OPEN)
      {
        auto node_operation =
          node_context.get_subsystem<AbstractNodeOperation>();
        auto& self_iamopen_request =
          node_operation->recovery_decision_protocol().get_iamopen_request(
            args.tx);

        auto myid = fmt::format(
          "{}:{} previously {}@{}",
          self_iamopen_request.info.identity.intrinsic_id,
          recovery_decision_protocol::service_fingerprint_from_pem(
            crypto::cert_der_to_pem(
              self_iamopen_request.info.service_cert_der)),
          self_iamopen_request.prev_service_fingerprint,
          self_iamopen_request.txid.to_str());
        auto inid = fmt::format(
          "{}:{} previously {}@{}",
          in.info.identity.intrinsic_id,
          recovery_decision_protocol::service_fingerprint_from_pem(
            crypto::cert_der_to_pem(in.info.service_cert_der)),
          in.prev_service_fingerprint,
          in.txid.to_str());
        LOG_INFO_FMT(
          "{} is already open, ignoring IAmOpen from {}", myid, inid);

        return ErrorDetails{
          .status = HTTP_STATUS_BAD_REQUEST,
          .code = ccf::errors::InvalidNodeState,
          .msg = "Node is already open, ignoring iamopen request"};
      }

      LOG_TRACE_FMT(
        "Recovery-decision-protocol: receive IAmOpen from {}",
        in.info.identity.intrinsic_id);
      args.tx
        .template rw<recovery_decision_protocol::SMState>(
          Tables::RECOVERY_DECISION_PROTOCOL_SM_STATE)
        ->put(recovery_decision_protocol::StateMachine::JOINING);
      args.tx
        .template rw<recovery_decision_protocol::ChosenNode>(
          Tables::RECOVERY_DECISION_PROTOCOL_CHOSEN_NODE)
        ->put(in.info.identity.intrinsic_id);
      return std::nullopt;
    };
    registry
      .make_endpoint(
        "/recovery_decision_protocol/iamopen",
        HTTP_PUT,
        json_adapter(wrap_recovery_decision_protocol<
                     recovery_decision_protocol::IAmOpenRequest>(
          recovery_decision_protocol_iamopen, node_context)),
        no_auth_required)
      .set_forwarding_required(endpoints::ForwardingRequired::Never)
      .set_openapi_hidden(true)
      .install();

    auto recovery_decision_protocol_timeout = [&](
                                                auto& args,
                                                const nlohmann::json& params) {
      (void)params;
      auto config = node_context.get_subsystem<NodeConfigurationSubsystem>();
      auto node_operation = node_context.get_subsystem<AbstractNodeOperation>();
      if (config == nullptr || node_operation == nullptr)
      {
        return make_error(
          HTTP_STATUS_BAD_REQUEST,
          ccf::errors::InvalidNodeState,
          "Unable to open recovery-decision-protocol subsystems");
      }

      auto sealing_recovery_config = config->get().node_config.sealing_recovery;

      if (
        !sealing_recovery_config.has_value() ||
        !sealing_recovery_config->recovery_decision_protocol.has_value())
      {
        return make_error(
          HTTP_STATUS_BAD_REQUEST,
          ccf::errors::InvalidNodeState,
          "This node cannot do recovery-decision-protocol");
      }

      LOG_TRACE_FMT("Recovery-decision-protocol timeout received");

      // Must ensure that the request originates from the primary
      auto primary_id = node_operation->get_primary();
      if (!primary_id.has_value())
      {
        LOG_FAIL_FMT("recovery-decision-protocol timeout: primary unknown");
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
          "recovery-decision-protocol timeout: request does not originate from "
          "primary");
        return make_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          "Request does not originate from primary.");
      }

      try
      {
        node_operation->recovery_decision_protocol().advance(args.tx, true);
      }
      catch (const std::logic_error& e)
      {
        LOG_FAIL_FMT(
          "Recovery-decision-protocol failed to advance state: {}", e.what());
        return make_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          fmt::format(
            "Failed to advance recovery-decision-protocol state: {}",
            e.what()));
      }
      return make_success(
        "Recovery-decision-protocol timeout processed successfully");
    };
    registry
      .make_endpoint(
        "/recovery_decision_protocol/timeout",
        HTTP_PUT,
        json_adapter(recovery_decision_protocol_timeout),
        {std::make_shared<NodeCertAuthnPolicy>()})
      .set_forwarding_required(endpoints::ForwardingRequired::Never)
      .set_openapi_hidden(true)
      .install();
  }
}
