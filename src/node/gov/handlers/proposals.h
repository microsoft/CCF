// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/base_endpoint_registry.h"
#include "node/gov/api_version.h"

namespace ccf::gov::endpoints
{
  bool resolve_proposal(
    kv::Tx& tx,
    const ProposalId& proposal_id,
    const std::vector<uint8_t>& proposal,
    const std::string& constitution)
  {
    return true;
  }

  void init_proposals_handlers(ccf::BaseEndpointRegistry& registry)
  {
    //// implementation of TSP interface Proposals
    auto create_proposal =
      [&](auto& ctx, nlohmann::json&& params, ApiVersion api_version) {
        switch (api_version)
        {
          case ApiVersion::v0_0_1_preview:
          default:
          {
            return make_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::NotImplemented,
              "TODO: Placeholder");
            break;
          }
        }
      };
    registry
      .make_endpoint(
        "/members/proposals:create",
        HTTP_POST,
        json_adapter(json_api_version_adapter(create_proposal)),
        no_auth_required)
      .set_openapi_hidden(true)
      .install();

    auto withdraw_proposal =
      [&](auto& ctx, nlohmann::json&& params, ApiVersion api_version) {
        switch (api_version)
        {
          case ApiVersion::v0_0_1_preview:
          default:
          {
            return make_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::NotImplemented,
              "TODO: Placeholder");
            break;
          }
        }
      };
    registry
      .make_endpoint(
        "/members/proposals/{proposalId}:withdraw",
        HTTP_POST,
        json_adapter(json_api_version_adapter(withdraw_proposal)),
        no_auth_required)
      .set_openapi_hidden(true)
      .install();

    auto get_proposal =
      [&](auto& ctx, nlohmann::json&& params, ApiVersion api_version) {
        switch (api_version)
        {
          case ApiVersion::v0_0_1_preview:
          default:
          {
            return make_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::NotImplemented,
              "TODO: Placeholder");
            break;
          }
        }
      };
    registry
      .make_read_only_endpoint(
        "/members/proposals/{proposalId}",
        HTTP_GET,
        json_read_only_adapter(json_api_version_adapter(get_proposal)),
        no_auth_required)
      .set_openapi_hidden(true)
      .install();

    auto list_proposals =
      [&](auto& ctx, nlohmann::json&& params, ApiVersion api_version) {
        switch (api_version)
        {
          case ApiVersion::v0_0_1_preview:
          default:
          {
            return make_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::NotImplemented,
              "TODO: Placeholder");
            break;
          }
        }
      };
    registry
      .make_read_only_endpoint(
        "/members/proposals",
        HTTP_GET,
        json_read_only_adapter(json_api_version_adapter(list_proposals)),
        no_auth_required)
      .set_openapi_hidden(true)
      .install();

    auto get_actions =
      [&](auto& ctx, nlohmann::json&& params, ApiVersion api_version) {
        switch (api_version)
        {
          case ApiVersion::v0_0_1_preview:
          default:
          {
            return make_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::NotImplemented,
              "TODO: Placeholder");
            break;
          }
        }
      };
    registry
      .make_read_only_endpoint(
        "/members/proposals/{proposalId}/actions",
        HTTP_GET,
        json_read_only_adapter(json_api_version_adapter(get_actions)),
        no_auth_required)
      .set_openapi_hidden(true)
      .install();

    //// implementation of TSP interface Ballots
    auto submit_ballot = [&](
                           ccf::endpoints::EndpointContext& ctx,
                           ApiVersion api_version) {
      switch (api_version)
      {
        case ApiVersion::v0_0_1_preview:
        default:
        {
          std::string error;

          ccf::ProposalId proposal_id;
          {
            // Extract proposal ID from path parameter
            std::string proposal_id_str;
            if (!ccf::endpoints::get_path_param(
                  ctx.rpc_ctx->get_request_path_params(),
                  "proposalId",
                  proposal_id_str,
                  error))
            {
              ctx.rpc_ctx->set_error(
                HTTP_STATUS_BAD_REQUEST,
                ccf::errors::InvalidResourceName,
                std::move(error));
              return;
            }

            // Parse proposal ID from string
            // TODO: Validate
            proposal_id = proposal_id_str;
          }

          // Confirm this matches proposalId from signature
          const auto& cose_ident =
            ctx.template get_caller<ccf::MemberCOSESign1AuthnIdentity>();
          const auto& signed_proposal_id =
            cose_ident.protected_header.gov_msg_proposal_id;
          if (
            !signed_proposal_id.has_value() ||
            signed_proposal_id.value() != proposal_id)
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::InvalidResourceName,
              "Authenticated proposal id does not match URL");
            return;
          }

          const auto member_id = cose_ident.member_id;

          // Look up proposal info and check expected state
          auto proposal_info_handle =
            ctx.tx.template rw<ccf::jsgov::ProposalInfoMap>(
              jsgov::Tables::PROPOSALS_INFO);
          auto proposal_info = proposal_info_handle->get(proposal_id);
          if (!proposal_info.has_value())
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_NOT_FOUND,
              ccf::errors::ProposalNotFound,
              fmt::format("Could not find proposal {}.", proposal_id));
            return;
          }

          if (proposal_info->state != ccf::ProposalState::OPEN)
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::ProposalNotOpen,
              fmt::format(
                "Proposal {} is currently in state {} - only {} proposals can "
                "receive votes",
                proposal_id,
                proposal_info->state,
                ProposalState::OPEN));
            return;
          }

          // Look up proposal contents
          auto proposals_handle = ctx.tx.template ro<ccf::jsgov::ProposalMap>(
            ccf::jsgov::Tables::PROPOSALS);
          const auto proposal = proposals_handle->get(proposal_id);
          if (!proposal.has_value())
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_NOT_FOUND,
              ccf::errors::ProposalNotFound,
              fmt::format("Could not find proposal {}.", proposal_id));
            return;
          }

          // Parse and validate incoming ballot
          const auto params = nlohmann::json::parse(cose_ident.content);
          const auto ballot_it = params.find("ballot");
          if (ballot_it == params.end() || !ballot_it.value().is_string())
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::InvalidInput,
              "Signed request body is not a JSON object containing required "
              "string field \"ballot\"");
            return;
          }

          const auto info_ballot_it = proposal_info->ballots.find(member_id);
          if (info_ballot_it != proposal_info->ballots.end())
          {
            // TODO: This doesn't seem very idempotent
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::VoteAlreadyExists,
              "Vote already submitted.");
            return;
          }

          // Store newly provided ballot
          proposal_info->ballots.emplace_hint(
            info_ballot_it, member_id, ballot_it.value().get<std::string>());

          // Access constitution to evaluate ballots
          const auto constitution =
            ctx.tx.template ro<ccf::Constitution>(ccf::Tables::CONSTITUTION)
              ->get();
          if (!constitution.has_value())
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              "No constitution is set - ballots cannot be evaluated");
            return;
          }

          const auto resolve_result = resolve_proposal(
            ctx.tx, proposal_id, proposal.value(), constitution.value());

          // TODO: Implement resolve_proposal, and construct response

          ctx.rpc_ctx->set_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::NotImplemented,
            "TODO: Placeholder");
          return;
        }
      }
    };
    registry
      .make_endpoint(
        "/members/proposals/{proposalId}/ballots",
        HTTP_POST,
        api_version_adapter(submit_ballot),
        // TODO: Helper function for this
        {std::make_shared<MemberCOSESign1AuthnPolicy>("ballot")})
      .set_openapi_hidden(true)
      .install();

    auto get_ballot = [&](auto& ctx, ApiVersion api_version) {
      switch (api_version)
      {
        case ApiVersion::v0_0_1_preview:
        default:
        {
          std::string error;

          ccf::ProposalId proposal_id;
          {
            // Extract proposal ID from path parameter
            std::string proposal_id_str;
            if (!ccf::endpoints::get_path_param(
                  ctx.rpc_ctx->get_request_path_params(),
                  "proposalId",
                  proposal_id_str,
                  error))
            {
              ctx.rpc_ctx->set_error(
                HTTP_STATUS_BAD_REQUEST,
                ccf::errors::InvalidResourceName,
                std::move(error));
              return;
            }

            // Parse proposal ID from string
            // TODO: Validate
            proposal_id = proposal_id_str;
          }

          ccf::MemberId member_id;
          {
            // Extract member ID from path parameter
            std::string member_id_str;
            if (!ccf::endpoints::get_path_param(
                  ctx.rpc_ctx->get_request_path_params(),
                  "memberId",
                  member_id_str,
                  error))
            {
              ctx.rpc_ctx->set_error(
                HTTP_STATUS_BAD_REQUEST,
                ccf::errors::InvalidResourceName,
                std::move(error));
              return;
            }

            // Parse member ID from string
            // TODO: Validate
            member_id = member_id_str;
          }

          // Look up proposal
          auto proposal_info_handle =
            ctx.tx.template ro<ccf::jsgov::ProposalInfoMap>(
              ccf::jsgov::Tables::PROPOSALS_INFO);

          // NB: Logically constant (read-only), but non-const so we can
          // eventually move a field out
          auto proposal_info = proposal_info_handle->get(proposal_id);
          if (!proposal_info.has_value())
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_NOT_FOUND,
              ccf::errors::ProposalNotFound,
              fmt::format("Proposal {} does not exist.", proposal_id));
            return;
          }

          // Look up ballot
          auto ballot_it = proposal_info->ballots.find(member_id);
          if (ballot_it == proposal_info->ballots.end())
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_NOT_FOUND,
              ccf::errors::VoteNotFound,
              fmt::format(
                "Member {} has not voted for proposal {}.",
                member_id,
                proposal_id));
            return;
          }

          // Return the raw ballot, with appropriate content-type
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          ctx.rpc_ctx->set_response_body(std::move(ballot_it->second));
          ctx.rpc_ctx->set_response_header(
            http::headers::CONTENT_TYPE,
            http::headervalues::contenttype::JAVASCRIPT);
          return;
        }
      }
    };
    registry
      .make_read_only_endpoint(
        "/members/proposals/{proposalId}/ballots/{memberId}",
        HTTP_GET,
        api_version_adapter(get_ballot),
        no_auth_required)
      .set_openapi_hidden(true)
      .install();
  }
}