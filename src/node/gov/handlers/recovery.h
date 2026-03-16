// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/base_endpoint_registry.h"
#include "node/gov/api_version.h"
#include "node/gov/handlers/helpers.h"
#include "node/share_manager.h"

namespace ccf::gov::endpoints
{
  inline void init_recovery_handlers(
    ccf::BaseEndpointRegistry& registry,
    ShareManager& share_manager,
    ccf::AbstractNodeContext& node_context)
  {
    auto get_encrypted_share_for_member =
      [&](auto& ctx, ApiVersion api_version) {
        switch (api_version)
        {
          case ApiVersion::preview_v1:
          case ApiVersion::v1:
          default:
          {
            ccf::MemberId member_id;
            if (!detail::try_parse_member_id(ctx.rpc_ctx, member_id))
            {
              return;
            }

            auto encrypted_share =
              ShareManager::get_encrypted_share(ctx.tx, member_id);

            if (!encrypted_share.has_value())
            {
              detail::set_gov_error(
                ctx.rpc_ctx,
                HTTP_STATUS_NOT_FOUND,
                ccf::errors::ResourceNotFound,
                fmt::format(
                  "Recovery share not found for member {}.", member_id));
              return;
            }

            auto response_body = nlohmann::json::object();
            response_body["memberId"] = member_id;
            response_body["encryptedShare"] =
              ccf::crypto::b64_from_raw(encrypted_share.value());

            ctx.rpc_ctx->set_response_json(response_body, HTTP_STATUS_OK);
            return;
          }
        }
      };
    registry
      .make_read_only_endpoint(
        "/recovery/encrypted-shares/{memberId}",
        HTTP_GET,
        api_version_adapter(get_encrypted_share_for_member),
        ccf::no_auth_required)
      .set_openapi_hidden(true)
      .install();

    auto submit_recovery_share = [&](auto& ctx, ApiVersion api_version) {
      switch (api_version)
      {
        case ApiVersion::preview_v1:
        case ApiVersion::v1:
        default:
        {
          if (
            InternalTablesAccess::get_service_status(ctx.tx) !=
            ServiceStatus::WAITING_FOR_RECOVERY_SHARES)
          {
            detail::set_gov_error(
              ctx.rpc_ctx,
              HTTP_STATUS_FORBIDDEN,
              errors::ServiceNotWaitingForRecoveryShares,
              "Service is not waiting for recovery shares.");
            return;
          }

          auto node_operation =
            node_context.get_subsystem<AbstractNodeOperation>();
          if (node_operation == nullptr)
          {
            detail::set_gov_error(
              ctx.rpc_ctx,
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              "Could not access NodeOperation subsystem.");
            return;
          }

          if (node_operation->is_reading_private_ledger())
          {
            detail::set_gov_error(
              ctx.rpc_ctx,
              HTTP_STATUS_FORBIDDEN,
              errors::NodeAlreadyRecovering,
              "Node is already recovering private ledger.");
            return;
          }

          ccf::MemberId member_id;
          if (!detail::try_parse_member_id(ctx.rpc_ctx, member_id))
          {
            return;
          }

          const auto& cose_ident =
            ctx.template get_caller<ccf::MemberCOSESign1AuthnIdentity>();

          auto params = nlohmann::json::parse(cose_ident.content);
          if (cose_ident.member_id != member_id)
          {
            detail::set_gov_error(
              ctx.rpc_ctx,
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::InvalidAuthenticationInfo,
              fmt::format(
                "Member ID from path parameter ({}) does not match "
                "member ID from body signature ({}).",
                member_id,
                cose_ident.member_id));
            return;
          }

          auto raw_recovery_share = ccf::crypto::raw_from_b64(
            params["share"].template get<std::string>());

          size_t submitted_shares_count = 0;
          bool full_key_submitted = false;
          try
          {
            submitted_shares_count = share_manager.submit_recovery_share(
              ctx.tx, member_id, raw_recovery_share);

            full_key_submitted = ShareManager::is_full_key(raw_recovery_share);

            OPENSSL_cleanse(
              raw_recovery_share.data(), raw_recovery_share.size());
          }
          catch (const std::exception& e)
          {
            OPENSSL_cleanse(
              raw_recovery_share.data(), raw_recovery_share.size());

            constexpr auto error_msg = "Error submitting recovery shares.";
            GOV_FAIL_FMT(error_msg);
            GOV_DEBUG_FMT("Error: {}", e.what());
            detail::set_gov_error(
              ctx.rpc_ctx,
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              errors::InternalError,
              error_msg);
            return;
          }

          const auto threshold =
            InternalTablesAccess::get_recovery_threshold(ctx.tx);

          std::string message;
          if (full_key_submitted)
          {
            message = "Full recovery key successfully submitted";
          }
          else
          {
            // Same format of message, whether this is sufficient to trigger
            // recovery or not
            message = fmt::format(
              "{}/{} recovery shares successfully submitted",
              submitted_shares_count,
              threshold);
          }

          if (submitted_shares_count >= threshold || full_key_submitted)
          {
            message += "\nEnd of recovery procedure initiated";
            GOV_INFO_FMT("{} - initiating recovery", message);

            // Initiate recovery
            try
            {
              node_operation->initiate_private_recovery(ctx.tx);
            }
            catch (const std::exception& e)
            {
              // Clear the submitted shares if combination fails so that members
              // can start over.
              constexpr auto error_msg = "Failed to initiate private recovery.";
              GOV_FAIL_FMT(error_msg);
              GOV_DEBUG_FMT("Error: {}", e.what());
              ShareManager::clear_submitted_recovery_shares(ctx.tx);
              ctx.rpc_ctx->set_apply_writes(true);
              detail::set_gov_error(
                ctx.rpc_ctx,
                HTTP_STATUS_INTERNAL_SERVER_ERROR,
                errors::InternalError,
                error_msg);
              return;
            }
          }

          auto response_body = nlohmann::json::object();
          response_body["message"] = message;
          response_body["submittedCount"] = submitted_shares_count;
          response_body["recoveryThreshold"] = threshold;
          response_body["fullKeySubmitted"] = full_key_submitted;

          ctx.rpc_ctx->set_response_json(response_body, HTTP_STATUS_OK);
          return;
        }
      }
    };
    registry
      .make_endpoint(
        "/recovery/members/{memberId}:recover",
        HTTP_POST,
        api_version_adapter(submit_recovery_share),
        detail::active_member_sig_only_policies("recovery_share"))
      .set_openapi_hidden(true)
      .install();
  }
}