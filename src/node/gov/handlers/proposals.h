// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/base_endpoint_registry.h"
#include "node/gov/api_version.h"

namespace ccf::gov::endpoints
{
  // TODO: De-duplicate
  void remove_all_other_non_open_proposals(
    kv::Tx& tx, const ProposalId& proposal_id)
  {
    auto p = tx.rw<ccf::jsgov::ProposalMap>(jsgov::Tables::PROPOSALS);
    auto pi = tx.rw<ccf::jsgov::ProposalInfoMap>(jsgov::Tables::PROPOSALS_INFO);
    std::vector<ProposalId> to_be_removed;
    pi->foreach(
      [&to_be_removed, &proposal_id](
        const ProposalId& pid, const ccf::jsgov::ProposalInfo& pinfo) {
        if (pid != proposal_id && pinfo.state != ProposalState::OPEN)
        {
          to_be_removed.push_back(pid);
        }
        return true;
      });
    for (const auto& pr : to_be_removed)
    {
      p->remove(pr);
      pi->remove(pr);
    }
  }

  ccf::jsgov::ProposalInfoSummary resolve_proposal(
    ccfapp::AbstractNodeContext& context,
    kv::Tx& tx,
    const ProposalId& proposal_id,
    const std::vector<uint8_t>& proposal,
    ccf::jsgov::ProposalInfo proposal_info,
    const std::string& constitution)
  {
    std::vector<std::pair<MemberId, bool>> votes;
    std::optional<jsgov::Failure> failure = std::nullopt;
    std::optional<ccf::jsgov::Votes> final_votes = std::nullopt;
    std::optional<ccf::jsgov::VoteFailures> vote_failures = std::nullopt;

    // Evaluate ballots
    for (const auto& [mid, mb] : proposal_info.ballots)
    {
      js::Context js_context(js::TxAccess::GOV_RO);
      js_context.runtime().set_runtime_options(&tx);
      js::TxContext txctx{&tx};
      js::populate_global_ccf_kv(&txctx, js_context);
      auto ballot_func = js_context.function(
        mb,
        "vote",
        fmt::format(
          "public:ccf.gov.proposal_info[{}].ballots[{}]", proposal_id, mid));

      std::vector<js::JSWrappedValue> argv = {
        js_context.new_string_len(
          (const char*)proposal.data(), proposal.size()),
        js_context.new_string_len(
          proposal_info.proposer_id.data(), proposal_info.proposer_id.size())};

      auto val = js_context.call(ballot_func, argv);
      if (!JS_IsException(val))
      {
        votes.emplace_back(mid, JS_ToBool(js_context, val));
      }
      else
      {
        if (!vote_failures.has_value())
        {
          vote_failures = ccf::jsgov::VoteFailures();
        }

        auto [reason, trace] = js::js_error_message(js_context);

        if (js_context.interrupt_data.request_timed_out)
        {
          reason = "Operation took too long to complete.";
        }
        vote_failures.value()[mid] = ccf::jsgov::Failure{reason, trace};
      }
    }

    // Evaluate resolve function
    {
      {
        js::Context js_context(js::TxAccess::GOV_RO);
        js_context.runtime().set_runtime_options(&tx);
        js::TxContext txctx{&tx};
        js::populate_global_ccf_kv(&txctx, js_context);
        auto resolve_func = js_context.function(
          constitution, "resolve", "public:ccf.gov.constitution[0]");

        std::vector<js::JSWrappedValue> argv;
        argv.push_back(js_context.new_string_len(
          (const char*)proposal.data(), proposal.size()));

        argv.push_back(js_context.new_string_len(
          proposal_info.proposer_id.data(), proposal_info.proposer_id.size()));

        auto vs = js_context.new_array();
        size_t index = 0;
        for (auto& [mid, vote] : votes)
        {
          auto v = JS_NewObject(js_context);
          auto member_id = JS_NewStringLen(js_context, mid.data(), mid.size());
          JS_DefinePropertyValueStr(
            js_context, v, "member_id", member_id, JS_PROP_C_W_E);
          auto vote_status = JS_NewBool(js_context, vote);
          JS_DefinePropertyValueStr(
            js_context, v, "vote", vote_status, JS_PROP_C_W_E);
          JS_DefinePropertyValueUint32(
            js_context, vs, index++, v, JS_PROP_C_W_E);
        }
        argv.push_back(vs);

        auto val = js_context.call(resolve_func, argv);

        if (JS_IsException(val))
        {
          proposal_info.state = ProposalState::FAILED;
          auto [reason, trace] = js::js_error_message(js_context);
          if (js_context.interrupt_data.request_timed_out)
          {
            reason = "Operation took too long to complete.";
          }
          failure = ccf::jsgov::Failure{
            fmt::format("Failed to resolve(): {}", reason), trace};
        }
        else if (JS_IsString(val))
        {
          auto status = js_context.to_str(val).value_or("");
          if (status == "Open")
          {
            proposal_info.state = ProposalState::OPEN;
          }
          else if (status == "Accepted")
          {
            proposal_info.state = ProposalState::ACCEPTED;
          }
          else if (status == "Withdrawn")
          {
            proposal_info.state = ProposalState::FAILED;
          }
          else if (status == "Rejected")
          {
            proposal_info.state = ProposalState::REJECTED;
          }
          else if (status == "Failed")
          {
            proposal_info.state = ProposalState::FAILED;
          }
          else if (status == "Dropped")
          {
            proposal_info.state = ProposalState::DROPPED;
          }
          else
          {
            proposal_info.state = ProposalState::FAILED;
            failure = ccf::jsgov::Failure{
              fmt::format(
                "resolve() returned invalid status value: \"{}\"", status),
              std::nullopt};
          }
        }
        else
        {
          proposal_info.state = ProposalState::FAILED;
          failure = ccf::jsgov::Failure{
            "resolve() returned invalid status value", std::nullopt};
        }
      }

      if (proposal_info.state != ProposalState::OPEN)
      {
        remove_all_other_non_open_proposals(tx, proposal_id);
        final_votes = std::unordered_map<ccf::MemberId, bool>();
        for (auto& [mid, vote] : votes)
        {
          final_votes.value()[mid] = vote;
        }
        if (proposal_info.state == ProposalState::ACCEPTED)
        {
          js::Context js_context(js::TxAccess::GOV_RW);
          js_context.runtime().set_runtime_options(&tx);
          js::TxContext txctx{&tx};

          auto gov_effects = context.get_subsystem<AbstractGovernanceEffects>();
          if (gov_effects == nullptr)
          {
            throw std::logic_error(
              "Unexpected: Could not access GovEffects subsytem");
          }

          js::populate_global_ccf_kv(&txctx, js_context);
          auto apply_func = js_context.function(
            constitution, "apply", "public:ccf.gov.constitution[0]");

          std::vector<js::JSWrappedValue> argv = {
            js_context.new_string_len(
              (const char*)proposal.data(), proposal.size()),
            js_context.new_string_len(proposal_id.c_str(), proposal_id.size())};

          auto val = js_context.call(apply_func, argv);

          if (JS_IsException(val))
          {
            proposal_info.state = ProposalState::FAILED;
            auto [reason, trace] = js::js_error_message(js_context);
            if (js_context.interrupt_data.request_timed_out)
            {
              reason = "Operation took too long to complete.";
            }
            failure = ccf::jsgov::Failure{
              fmt::format("Failed to apply(): {}", reason), trace};
          }
        }
      }

      return jsgov::ProposalInfoSummary{
        proposal_id,
        proposal_info.proposer_id,
        proposal_info.state,
        proposal_info.ballots.size(),
        final_votes,
        vote_failures,
        failure};
    }
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

    auto get_actions = [&](auto& ctx, ApiVersion api_version) {
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

          auto proposal_handle = ctx.tx.template ro<ccf::jsgov::ProposalMap>(
            jsgov::Tables::PROPOSALS);

          const auto proposal = proposal_handle->get(proposal_id);
          if (!proposal.has_value())
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_NOT_FOUND,
              ccf::errors::ProposalNotFound,
              fmt::format("Could not find proposal {}.", proposal_id));
            return;
          }

          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          ctx.rpc_ctx->set_response_body(proposal.value());
          break;
        }
      }
    };
    registry
      .make_read_only_endpoint(
        "/members/proposals/{proposalId}/actions",
        HTTP_GET,
        api_version_adapter(get_actions),
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
            registry.context,
            ctx.tx,
            proposal_id,
            proposal.value(),
            proposal_info.value(),
            constitution.value());

          // TODO: Do this in a separate function for reuse?
          auto response_body = nlohmann::json::object();
          response_body["proposalId"] = resolve_result.proposal_id;
          response_body["proposerId"] = resolve_result.proposer_id;
          response_body["proposalState"] =
            resolve_result.state; // TODO: Case conversion?
          response_body["ballotCount"] = resolve_result.ballot_count;

          if (resolve_result.votes.has_value())
          {
            auto final_votes = nlohmann::json::object();
            for (const auto& [voter_id, vote_result] : *resolve_result.votes)
            {
              final_votes[voter_id.value()] = vote_result;
            }
            response_body["finalVotes"] = final_votes;
          }

          if (resolve_result.vote_failures.has_value())
          {
            auto vote_failures = nlohmann::json::object();
            for (const auto& [failer_id, failure] :
                 *resolve_result.vote_failures)
            {
              vote_failures[failer_id.value()] = failure;
            }
            response_body["voteFailures"] = vote_failures;
          }

          if (resolve_result.failure.has_value())
          {
            auto failure = nlohmann::json::object();
            response_body["failure"] = *resolve_result.failure;
          }

          ctx.rpc_ctx->set_response_json(response_body, HTTP_STATUS_OK);
          return;
        }
      }
    };
    registry
      .make_endpoint(
        "/members/proposals/{proposalId}/ballots/{memberId}:submit",
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