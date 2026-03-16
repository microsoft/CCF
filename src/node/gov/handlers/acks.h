// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/base_endpoint_registry.h"
#include "node/gov/api_version.h"
#include "node/gov/handlers/helpers.h"
#include "node/share_manager.h"
#include "service/internal_tables_access.h"

namespace ccf::gov::endpoints
{
  inline void init_ack_handlers(
    ccf::BaseEndpointRegistry& registry,
    NetworkState& /*network*/,
    ShareManager& share_manager)
  {
    auto get_state_digest = [&](auto& ctx, ApiVersion api_version) {
      switch (api_version)
      {
        case ApiVersion::preview_v1:
        case ApiVersion::v1:
        default:
        {
          // Get memberId from path parameter
          std::string error;
          std::string member_id_str;
          if (!ccf::endpoints::get_path_param(
                ctx.rpc_ctx->get_request_path_params(),
                "memberId",
                member_id_str,
                error))
          {
            detail::set_gov_error(
              ctx.rpc_ctx,
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::InvalidResourceName,
              std::move(error));
            return;
          }

          // Read member's ack from KV
          ccf::MemberId member_id(member_id_str);
          auto acks_handle =
            ctx.tx.template ro<ccf::MemberAcks>(Tables::MEMBER_ACKS);
          auto ack = acks_handle->get(member_id);
          if (!ack.has_value())
          {
            detail::set_gov_error(
              ctx.rpc_ctx,
              HTTP_STATUS_NOT_FOUND,
              ccf::errors::ResourceNotFound,
              fmt::format("No ACK record exists for member {}.", member_id));
            return;
          }

          auto response_body = nlohmann::json::object();
          response_body["memberId"] = member_id_str;
          response_body["stateDigest"] = ack->state_digest;
          ctx.rpc_ctx->set_response_json(response_body, HTTP_STATUS_OK);
          return;
        }
      }
    };
    registry
      .make_read_only_endpoint(
        "/members/state-digests/{memberId}",
        HTTP_GET,
        api_version_adapter(get_state_digest),
        no_auth_required)
      .set_openapi_hidden(true)
      .install();

    auto update_state_digest = [&](auto& ctx, ApiVersion api_version) {
      switch (api_version)
      {
        case ApiVersion::preview_v1:
        case ApiVersion::v1:
        default:
        {
          // Get memberId from path parameter
          std::string error;
          std::string member_id_str;
          if (!ccf::endpoints::get_path_param(
                ctx.rpc_ctx->get_request_path_params(),
                "memberId",
                member_id_str,
                error))
          {
            detail::set_gov_error(
              ctx.rpc_ctx,
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::InvalidResourceName,
              std::move(error));
            return;
          }

          // Confirm this matches memberId from signature
          ccf::MemberId member_id(member_id_str);
          const auto& cose_ident =
            ctx.template get_caller<ccf::MemberCOSESign1AuthnIdentity>();
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

          ccf::MemberAck ack;

          // Get previous ack, if it exists
          auto acks_handle =
            ctx.tx.template rw<ccf::MemberAcks>(Tables::MEMBER_ACKS);
          auto ack_opt = acks_handle->get(member_id);
          if (ack_opt.has_value())
          {
            ack = ack_opt.value();
          }

          // Get signature, containing merkle root state digest
          auto sigs_handle =
            ctx.tx.template ro<ccf::Signatures>(Tables::SIGNATURES);
          auto sig = sigs_handle->get();
          if (!sig.has_value())
          {
            detail::set_gov_error(
              ctx.rpc_ctx,
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              "Service has no signatures to ack yet - try again soon.");
            return;
          }

          // Write ack back to the KV
          ack.state_digest = sig->root.hex_str();
          acks_handle->put(member_id, ack);

          auto body = nlohmann::json::object();
          body["memberId"] = member_id_str;
          body["stateDigest"] = ack.state_digest;
          ctx.rpc_ctx->set_response_json(body, HTTP_STATUS_OK);
          return;
        }
      }
    };
    registry
      .make_endpoint(
        "/members/state-digests/{memberId}:update",
        HTTP_POST,
        api_version_adapter(update_state_digest),
        detail::member_sig_only_policies("state_digest"))
      .set_openapi_hidden(true)
      .install();

    auto ack_state_digest = [&](auto& ctx, ApiVersion api_version) {
      switch (api_version)
      {
        case ApiVersion::preview_v1:
        case ApiVersion::v1:
        default:
        {
          // Get memberId from path parameter
          std::string error;
          std::string member_id_str;
          if (!ccf::endpoints::get_path_param(
                ctx.rpc_ctx->get_request_path_params(),
                "memberId",
                member_id_str,
                error))
          {
            detail::set_gov_error(
              ctx.rpc_ctx,
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::InvalidResourceName,
              std::move(error));
            return;
          }

          // Confirm this matches memberId from signature
          ccf::MemberId member_id(member_id_str);
          const auto& cose_ident =
            ctx.template get_caller<ccf::MemberCOSESign1AuthnIdentity>();
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

          // Check an expected digest for this member is in the KV
          auto acks_handle =
            ctx.tx.template rw<ccf::MemberAcks>(Tables::MEMBER_ACKS);
          auto ack = acks_handle->get(member_id);
          if (!ack.has_value())
          {
            detail::set_gov_error(
              ctx.rpc_ctx,
              HTTP_STATUS_FORBIDDEN,
              ccf::errors::AuthorizationFailed,
              fmt::format("No ACK record exists for member {}.", member_id));
            return;
          }

          // Check signed digest matches expected digest in KV
          const auto expected_digest = ack->state_digest;
          const auto signed_body = nlohmann::json::parse(cose_ident.content);
          const auto actual_digest =
            signed_body["stateDigest"].template get<std::string>();
          if (expected_digest != actual_digest)
          {
            detail::set_gov_error(
              ctx.rpc_ctx,
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::StateDigestMismatch,
              fmt::format(
                "Submitted state digest is not valid.\n"
                "Expected\n"
                " {}\n"
                "Received\n"
                " {}",
                expected_digest,
                actual_digest));
            return;
          }

          // Ensure old HTTP signed req is nulled
          ack->signed_req = std::nullopt;

          // Insert new signature
          ack->cose_sign1_req = std::vector<uint8_t>(
            cose_ident.envelope.begin(), cose_ident.envelope.end());

          // Store signed ACK in KV
          acks_handle->put(member_id, ack.value());

          // Update member details
          {
            // Update member status to ACTIVE
            bool newly_active = false;
            try
            {
              newly_active =
                InternalTablesAccess::activate_member(ctx.tx, member_id);
            }
            catch (const std::logic_error& e)
            {
              detail::set_gov_error(
                ctx.rpc_ctx,
                HTTP_STATUS_INTERNAL_SERVER_ERROR,
                ccf::errors::InternalError,
                fmt::format("Error activating member: {}", e.what()));
              return;
            }

            // If this is a newly-active recovery participant/owner in an open
            // service, allocate them a recovery share immediately
            if (
              newly_active &&
              InternalTablesAccess::is_recovery_participant_or_owner(
                ctx.tx, member_id))
            {
              auto service_status =
                InternalTablesAccess::get_service_status(ctx.tx);
              if (!service_status.has_value())
              {
                detail::set_gov_error(
                  ctx.rpc_ctx,
                  HTTP_STATUS_INTERNAL_SERVER_ERROR,
                  ccf::errors::InternalError,
                  "No service currently available.");
                return;
              }

              if (service_status.value() == ServiceStatus::OPEN)
              {
                try
                {
                  share_manager.shuffle_recovery_shares(ctx.tx);
                }
                catch (const std::logic_error& e)
                {
                  detail::set_gov_error(
                    ctx.rpc_ctx,
                    HTTP_STATUS_INTERNAL_SERVER_ERROR,
                    ccf::errors::InternalError,
                    fmt::format(
                      "Error issuing new recovery shares: {}", e.what()));
                  return;
                }
              }
            }
          }

          ctx.rpc_ctx->set_response_status(HTTP_STATUS_NO_CONTENT);
          return;
          break;
        }
      }
    };
    registry
      .make_endpoint(
        "/members/state-digests/{memberId}:ack",
        HTTP_POST,
        api_version_adapter(ack_state_digest),
        {std::make_shared<MemberCOSESign1AuthnPolicy>("ack")})
      .set_openapi_hidden(true)
      .install();
  }
}