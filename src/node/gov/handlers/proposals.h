// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/base_endpoint_registry.h"
#include "node/gov/api_version.h"
#include "node/gov/handlers/helpers.h"

namespace ccf::gov::endpoints
{
  namespace detail
  {
    struct ProposalSubmissionResult
    {
      enum class Status
      {
        Acceptable,
        DuplicateInWindow,
        TooOld
      } status;

      // May be empty, a colliding proposal ID, or a min_created_at value,
      // depending on status
      std::string info = "";
    };

    ProposalSubmissionResult validate_proposal_submission_time(
      kv::Tx& tx,
      const std::string& created_at,
      const std::vector<uint8_t>& request_digest,
      const ccf::ProposalId& proposal_id)
    {
      auto cose_recent_proposals =
        tx.rw<ccf::COSERecentProposals>(ccf::Tables::COSE_RECENT_PROPOSALS);
      auto key = fmt::format("{}:{}", created_at, ds::to_hex(request_digest));

      if (cose_recent_proposals->has(key))
      {
        auto colliding_proposal_id = cose_recent_proposals->get(key).value();
        return {
          ProposalSubmissionResult::Status::DuplicateInWindow,
          colliding_proposal_id};
      }

      std::vector<std::string> replay_keys;
      cose_recent_proposals->foreach_key(
        [&replay_keys](const std::string& replay_key) {
          replay_keys.push_back(replay_key);
          return true;
        });

      std::sort(replay_keys.begin(), replay_keys.end());

      // New proposal must be more recent than median proposal kept
      if (!replay_keys.empty())
      {
        const auto [min_created_at, _] =
          nonstd::split_1(replay_keys[replay_keys.size() / 2], ":");
        auto [key_ts, __] = nonstd::split_1(key, ":");
        if (key_ts < min_created_at)
        {
          return {
            ProposalSubmissionResult::Status::TooOld,
            std::string(min_created_at)};
        }
      }

      size_t window_size = ccf::default_recent_cose_proposals_window_size;
      auto config_handle =
        tx.ro<ccf::Configuration>(ccf::Tables::CONFIGURATION);
      auto config = config_handle->get();
      if (
        config.has_value() &&
        config->recent_cose_proposals_window_size.has_value())
      {
        window_size = config->recent_cose_proposals_window_size.value();
      }
      cose_recent_proposals->put(key, proposal_id);
      // Only keep the most recent window_size proposals, to avoid
      // unbounded memory usage
      if (replay_keys.size() >= (window_size - 1) /* We just added one */)
      {
        for (size_t i = 0; i < (replay_keys.size() - (window_size - 1)); i++)
        {
          cose_recent_proposals->remove(replay_keys[i]);
        }
      }
      return {ProposalSubmissionResult::Status::Acceptable};
    }

    void record_cose_governance_history(
      kv::Tx& tx,
      const MemberId& caller_id,
      const std::span<const uint8_t>& cose_sign1)
    {
      auto cose_governance_history =
        tx.wo<ccf::COSEGovernanceHistory>(ccf::Tables::COSE_GOV_HISTORY);
      cose_governance_history->put(
        caller_id, {cose_sign1.begin(), cose_sign1.end()});
    }

    void remove_all_other_non_open_proposals(
      kv::Tx& tx, const ProposalId& proposal_id)
    {
      auto p = tx.rw<ccf::jsgov::ProposalMap>(jsgov::Tables::PROPOSALS);
      auto pi =
        tx.rw<ccf::jsgov::ProposalInfoMap>(jsgov::Tables::PROPOSALS_INFO);
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
      ccf::NetworkState& network,
      kv::Tx& tx,
      const ProposalId& proposal_id,
      const std::span<const uint8_t>& proposal,
      ccf::jsgov::ProposalInfo& proposal_info,
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
        js::populate_global_ccf_kv(tx, js_context);
        auto ballot_func = js_context.function(
          mb,
          "vote",
          fmt::format(
            "public:ccf.gov.proposal_info[{}].ballots[{}]", proposal_id, mid));

        std::vector<js::JSWrappedValue> argv = {
          js_context.new_string_len(
            (const char*)proposal.data(), proposal.size()),
          js_context.new_string_len(
            proposal_info.proposer_id.data(),
            proposal_info.proposer_id.size())};

        auto val = js_context.call_with_rt_options(
          ballot_func,
          argv,
          &tx,
          js::RuntimeLimitsPolicy::NO_LOWER_THAN_DEFAULTS);

        if (!val.is_exception())
        {
          votes.emplace_back(mid, val.is_true());
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
          js::populate_global_ccf_kv(tx, js_context);
          auto resolve_func = js_context.function(
            constitution, "resolve", "public:ccf.gov.constitution[0]");

          std::vector<js::JSWrappedValue> argv;
          argv.push_back(js_context.new_string_len(
            (const char*)proposal.data(), proposal.size()));

          argv.push_back(js_context.new_string_len(
            proposal_info.proposer_id.data(),
            proposal_info.proposer_id.size()));

          auto vs = js_context.new_array();
          size_t index = 0;
          for (auto& [mid, vote] : votes)
          {
            auto v = JS_NewObject(js_context);
            auto member_id =
              JS_NewStringLen(js_context, mid.data(), mid.size());
            JS_DefinePropertyValueStr(
              js_context, v, "member_id", member_id, JS_PROP_C_W_E);
            auto vote_status = JS_NewBool(js_context, vote);
            JS_DefinePropertyValueStr(
              js_context, v, "vote", vote_status, JS_PROP_C_W_E);
            JS_DefinePropertyValueUint32(
              js_context, vs, index++, v, JS_PROP_C_W_E);
          }
          argv.push_back(vs);

          auto val = js_context.call_with_rt_options(
            resolve_func,
            argv,
            &tx,
            js::RuntimeLimitsPolicy::NO_LOWER_THAN_DEFAULTS);

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
          else
          {
            auto status = js_context.to_str(val).value_or("");
            // NB: It is not possible to produce every possible ProposalState
            // here! WITHDRAWN and DROPPED are states that we transition to
            // elsewhere, but not valid return values from resolve()
            const std::unordered_map<std::string, ProposalState>
              js_str_to_status = {
                {"Open", ProposalState::OPEN},
                {"Accepted", ProposalState::ACCEPTED},
                {"Rejected", ProposalState::REJECTED}};
            const auto it = js_str_to_status.find(status);
            if (it != js_str_to_status.end())
            {
              proposal_info.state = it->second;
            }
            else
            {
              proposal_info.state = ProposalState::FAILED;
              failure = ccf::jsgov::Failure{
                fmt::format(
                  "resolve() returned invalid status value: \"{}\"", status),
                std::nullopt // No trace
              };
            }
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
            // Evaluate apply function
            js::Context js_context(js::TxAccess::GOV_RW);

            auto gov_effects =
              context.get_subsystem<AbstractGovernanceEffects>();
            if (gov_effects == nullptr)
            {
              throw std::logic_error(
                "Unexpected: Could not access GovEffects subsytem");
            }

            js::populate_global_ccf_kv(tx, js_context);
            js::populate_global_ccf_node(gov_effects.get(), js_context);
            js::populate_global_ccf_network(&network, js_context);
            js::populate_global_ccf_gov_actions(js_context);

            auto apply_func = js_context.function(
              constitution, "apply", "public:ccf.gov.constitution[0]");

            std::vector<js::JSWrappedValue> argv = {
              js_context.new_string_len(
                (const char*)proposal.data(), proposal.size()),
              js_context.new_string_len(
                proposal_id.c_str(), proposal_id.size())};

            auto val = js_context.call_with_rt_options(
              apply_func,
              argv,
              &tx,
              js::RuntimeLimitsPolicy::NO_LOWER_THAN_DEFAULTS);

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

    // We have several structurally-similar types for representing proposals (in
    // KV vs post-exec vs fully expanded). This aims to take any, and produce
    // the same API-compatible description.
    template <typename TProposal>
    nlohmann::json convert_proposal_to_api_format(const TProposal& summary)
    {
      auto response_body = nlohmann::json::object();

      response_body["proposerId"] = summary.proposer_id;
      response_body["proposalState"] = summary.state;

      std::optional<ccf::jsgov::Votes> votes;

      if constexpr (std::is_same_v<TProposal, ccf::jsgov::ProposalInfoSummary>)
      {
        response_body["proposalId"] = summary.proposal_id;
        response_body["ballotCount"] = summary.ballot_count;

        votes = summary.votes;
      }
      else if constexpr (std::is_same_v<TProposal, ccf::jsgov::ProposalInfo>)
      {
        response_body["ballotCount"] = summary.ballots.size();

        votes = summary.final_votes;
      }

      if (votes.has_value())
      {
        auto final_votes = nlohmann::json::object();
        for (const auto& [voter_id, vote_result] : *votes)
        {
          final_votes[voter_id.value()] = vote_result;
        }
        response_body["finalVotes"] = final_votes;
      }

      if (summary.vote_failures.has_value())
      {
        auto vote_failures = nlohmann::json::object();
        for (const auto& [failer_id, failure] : *summary.vote_failures)
        {
          vote_failures[failer_id.value()] = failure;
        }
        response_body["voteFailures"] = vote_failures;
      }

      if (summary.failure.has_value())
      {
        auto failure = nlohmann::json::object();
        response_body["failure"] = *summary.failure;
      }

      return response_body;
    }
  }

  void init_proposals_handlers(
    ccf::BaseEndpointRegistry& registry,
    NetworkState& network,
    ccfapp::AbstractNodeContext& node_context)
  {
    //// implementation of TSP interface Proposals
    auto create_proposal = [&](auto& ctx, ApiVersion api_version) {
      switch (api_version)
      {
        case ApiVersion::preview_v1:
        default:
        {
          std::span<const uint8_t> proposal_body;
          ccf::jsgov::ProposalInfo proposal_info;
          std::optional<std::string> constitution;

          const auto& cose_ident =
            ctx.template get_caller<ccf::MemberCOSESign1AuthnIdentity>();

          // Construct proposal_id, as digest of request and root
          ProposalId proposal_id;
          std::vector<uint8_t> request_digest;
          {
            auto root_at_read = ctx.tx.get_root_at_read_version();
            if (!root_at_read.has_value())
            {
              detail::set_gov_error(
                ctx.rpc_ctx,
                HTTP_STATUS_INTERNAL_SERVER_ERROR,
                ccf::errors::InternalError,
                "Proposal failed to bind to state.");
              return;
            }

            auto hasher = crypto::make_incremental_sha256();
            hasher->update_hash(root_at_read.value().h);

            request_digest = crypto::sha256(
              cose_ident.signature.data(), cose_ident.signature.size());

            hasher->update_hash(request_digest);

            const crypto::Sha256Hash proposal_hash = hasher->finalise();
            proposal_id = proposal_hash.hex_str();
          }

          // Validate proposal, by calling into JS constitution
          {
            constitution =
              ctx.tx.template ro<ccf::Constitution>(ccf::Tables::CONSTITUTION)
                ->get();
            if (!constitution.has_value())
            {
              detail::set_gov_error(
                ctx.rpc_ctx,
                HTTP_STATUS_INTERNAL_SERVER_ERROR,
                ccf::errors::InternalError,
                "No constitution is set - proposals cannot be evaluated");
              return;
            }

            js::Context context(js::TxAccess::GOV_RO);
            js::populate_global_ccf_kv(ctx.tx, context);

            auto validate_func = context.function(
              constitution.value(),
              "validate",
              "public:ccf.gov.constitution[0]");

            proposal_body = cose_ident.content;
            auto proposal_arg = context.new_string_len(
              (const char*)proposal_body.data(), proposal_body.size());
            auto validate_result = context.call_with_rt_options(
              validate_func,
              {proposal_arg},
              &ctx.tx,
              js::RuntimeLimitsPolicy::NO_LOWER_THAN_DEFAULTS);

            // Handle error cases of validation
            {
              if (validate_result.is_exception())
              {
                auto [reason, trace] = js_error_message(context);
                if (context.interrupt_data.request_timed_out)
                {
                  reason = "Operation took too long to complete.";
                }
                detail::set_gov_error(
                  ctx.rpc_ctx,
                  HTTP_STATUS_INTERNAL_SERVER_ERROR,
                  ccf::errors::InternalError,
                  fmt::format(
                    "Failed to execute validation: {} {}",
                    reason,
                    trace.value_or("")));
                return;
              }

              if (!validate_result.is_obj())
              {
                detail::set_gov_error(
                  ctx.rpc_ctx,
                  HTTP_STATUS_INTERNAL_SERVER_ERROR,
                  ccf::errors::InternalError,
                  "Validation failed to return an object");
                return;
              }

              std::string description;
              auto desc = validate_result["description"];
              if (desc.is_str())
              {
                description = context.to_str(desc).value_or("");
              }

              auto valid = validate_result["valid"];
              if (!valid.is_true())
              {
                detail::set_gov_error(
                  ctx.rpc_ctx,
                  HTTP_STATUS_BAD_REQUEST,
                  ccf::errors::ProposalFailedToValidate,
                  fmt::format("Proposal failed to validate: {}", description));
                return;
              }
            }

            // Write proposal to KV
            {
              auto proposals_handle =
                ctx.tx.template rw<ccf::jsgov::ProposalMap>(
                  jsgov::Tables::PROPOSALS);
              // Introduce a read dependency, so that if identical proposal
              // creations are in-flight and reading at the same version, all
              // except the first conflict and are re-executed. If we ever
              // produce a proposal ID which already exists, we must have a
              // hash collision.
              if (proposals_handle->has(proposal_id))
              {
                detail::set_gov_error(
                  ctx.rpc_ctx,
                  HTTP_STATUS_INTERNAL_SERVER_ERROR,
                  ccf::errors::InternalError,
                  "Proposal ID collision.");
                return;
              }
              proposals_handle->put(
                proposal_id, {proposal_body.begin(), proposal_body.end()});

              auto proposal_info_handle =
                ctx.tx.template wo<ccf::jsgov::ProposalInfoMap>(
                  jsgov::Tables::PROPOSALS_INFO);

              proposal_info.proposer_id = cose_ident.member_id;
              proposal_info.state = ccf::ProposalState::OPEN;

              proposal_info_handle->put(proposal_id, proposal_info);

              detail::record_cose_governance_history(
                ctx.tx, cose_ident.member_id, cose_ident.envelope);
            }
          }

          // Validate proposal's created_at time
          {
            // created_at, submitted as a binary integer number of seconds
            // since epoch in the COSE Sign1 envelope, is converted to a
            // decimal representation in ASCII, stored as a string, and
            // compared alphanumerically. This is partly to keep governance as
            // text-based as possible, to faciliate audit, but also to be able
            // to benefit from future planned ordering support in the KV. To
            // compare correctly, the string representation needs to be padded
            // with leading zeroes, and must therefore not exceed a fixed
            // digit width. 10 digits is enough to last until November 2286,
            // ie. long enough.
            if (cose_ident.protected_header.gov_msg_created_at > 9'999'999'999)
            {
              detail::set_gov_error(
                ctx.rpc_ctx,
                HTTP_STATUS_BAD_REQUEST,
                ccf::errors::InvalidCreatedAt,
                "Header parameter created_at value is too large");
              return;
            }

            const auto created_at_str = fmt::format(
              "{:0>10}", cose_ident.protected_header.gov_msg_created_at);

            ccf::ProposalId colliding_proposal_id;
            std::string min_created_at;

            const auto subtime_result =
              detail::validate_proposal_submission_time(
                ctx.tx, created_at_str, request_digest, proposal_id);
            switch (subtime_result.status)
            {
              case detail::ProposalSubmissionResult::Status::TooOld:
              {
                detail::set_gov_error(
                  ctx.rpc_ctx,
                  HTTP_STATUS_BAD_REQUEST,
                  ccf::errors::ProposalCreatedTooLongAgo,
                  fmt::format(
                    "Proposal created too long ago, created_at must be greater "
                    "than {}",
                    subtime_result.info));
                return;
              }

              case detail::ProposalSubmissionResult::Status::DuplicateInWindow:
              {
                detail::set_gov_error(
                  ctx.rpc_ctx,
                  HTTP_STATUS_BAD_REQUEST,
                  ccf::errors::ProposalReplay,
                  fmt::format(
                    "Proposal submission replay, already exists as proposal {}",
                    subtime_result.info));
                return;
              }

              case detail::ProposalSubmissionResult::Status::Acceptable:
              {
                break;
              }

              default:
              {
                throw std::runtime_error(
                  "Invalid ProposalSubmissionStatus value");
              }
            }
          }

          // Resolve proposal (may pass immediately)
          {
            const auto resolve_result = detail::resolve_proposal(
              node_context,
              network,
              ctx.tx,
              proposal_id,
              proposal_body,
              proposal_info,
              constitution.value());

            if (resolve_result.state == ProposalState::FAILED)
            {
              // If the proposal failed to apply, we want to discard the tx and
              // not apply its side-effects to the KV state, because it may have
              // failed mid-execution (eg - thrown an exception), in which case
              // we do not want to apply partial writes. Note this differs from
              // a failure that happens after a vote, in that this proposal is
              // not recorded in the KV at all.
              detail::set_gov_error(
                ctx.rpc_ctx,
                HTTP_STATUS_INTERNAL_SERVER_ERROR,
                ccf::errors::InternalError,
                fmt::format("{}", resolve_result.failure));
              return;
            }

            // Write updated proposal info
            {
              auto proposal_info_handle =
                ctx.tx.template wo<ccf::jsgov::ProposalInfoMap>(
                  jsgov::Tables::PROPOSALS_INFO);

              proposal_info.state = resolve_result.state;
              proposal_info.failure = resolve_result.failure;

              proposal_info_handle->put(proposal_id, proposal_info);
            }

            const auto response_body =
              detail::convert_proposal_to_api_format(resolve_result);

            ctx.rpc_ctx->set_response_json(response_body, HTTP_STATUS_OK);
            return;
          }
        }
      }
    };
    registry
      .make_endpoint(
        "/members/proposals:create",
        HTTP_POST,
        api_version_adapter(create_proposal),
        detail::active_member_sig_only_policies("proposal"))
      .set_openapi_hidden(true)
      .install();

    auto withdraw_proposal = [&](auto& ctx, ApiVersion api_version) {
      switch (api_version)
      {
        case ApiVersion::preview_v1:
        default:
        {
          const auto& cose_ident =
            ctx.template get_caller<ccf::MemberCOSESign1AuthnIdentity>();
          ccf::ProposalId proposal_id;

          if (!detail::try_parse_signed_proposal_id(
                cose_ident, ctx.rpc_ctx, proposal_id))
          {
            return;
          }

          auto proposal_info_handle =
            ctx.tx.template rw<ccf::jsgov::ProposalInfoMap>(
              jsgov::Tables::PROPOSALS_INFO);

          // Check proposal exists
          auto proposal_info = proposal_info_handle->get(proposal_id);
          if (!proposal_info.has_value())
          {
            // If it doesn't, then withdrawal is idempotent - we don't know if
            // this previously existed or not, was withdrawn or accepted, but
            // return a 204
            ctx.rpc_ctx->set_response_status(HTTP_STATUS_NO_CONTENT);
            return;
          }

          // Check caller is proposer
          const auto member_id = cose_ident.member_id;
          if (member_id != proposal_info->proposer_id)
          {
            detail::set_gov_error(
              ctx.rpc_ctx,
              HTTP_STATUS_FORBIDDEN,
              ccf::errors::AuthorizationFailed,
              fmt::format(
                "Proposal {} can only be withdrawn by proposer {}, not caller "
                "{}.",
                proposal_id,
                proposal_info->proposer_id,
                member_id));
            return;
          }

          // If proposal is still known, and state is neither OPEN nor
          // WITHDRAWN, return an error - caller has done something wrong
          if (
            proposal_info->state != ProposalState::OPEN &&
            proposal_info->state != ProposalState::WITHDRAWN)
          {
            detail::set_gov_error(
              ctx.rpc_ctx,
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::ProposalNotOpen,
              fmt::format(
                "Proposal {} is currently in state {} and cannot be withdrawn.",
                proposal_id,
                proposal_info->state));
            return;
          }

          // Check proposal is open - only write withdrawal if currently
          // open
          if (proposal_info->state == ProposalState::OPEN)
          {
            proposal_info->state = ProposalState::WITHDRAWN;
            proposal_info_handle->put(proposal_id, proposal_info.value());

            detail::remove_all_other_non_open_proposals(ctx.tx, proposal_id);
            detail::record_cose_governance_history(
              ctx.tx, cose_ident.member_id, cose_ident.envelope);
          }

          auto response_body =
            detail::convert_proposal_to_api_format(proposal_info.value());
          response_body["proposalId"] = proposal_id;

          ctx.rpc_ctx->set_response_json(response_body, HTTP_STATUS_OK);
          return;
        }
      }
    };
    registry
      .make_endpoint(
        "/members/proposals/{proposalId}:withdraw",
        HTTP_POST,
        api_version_adapter(withdraw_proposal),
        detail::active_member_sig_only_policies("withdrawal"))
      .set_openapi_hidden(true)
      .install();

    auto get_proposal = [&](auto& ctx, ApiVersion api_version) {
      switch (api_version)
      {
        case ApiVersion::preview_v1:
        default:
        {
          ccf::ProposalId proposal_id;
          if (!detail::try_parse_proposal_id(ctx.rpc_ctx, proposal_id))
          {
            return;
          }

          auto proposal_info_handle =
            ctx.tx.template ro<ccf::jsgov::ProposalInfoMap>(
              jsgov::Tables::PROPOSALS_INFO);
          auto proposal_info = proposal_info_handle->get(proposal_id);
          if (!proposal_info.has_value())
          {
            detail::set_gov_error(
              ctx.rpc_ctx,
              HTTP_STATUS_NOT_FOUND,
              ccf::errors::ProposalNotFound,
              fmt::format("Could not find proposal {}.", proposal_id));
            return;
          }

          auto response_body =
            detail::convert_proposal_to_api_format(proposal_info.value());
          response_body["proposalId"] = proposal_id;

          ctx.rpc_ctx->set_response_json(response_body, HTTP_STATUS_OK);
          return;
        }
      }
    };
    registry
      .make_read_only_endpoint(
        "/members/proposals/{proposalId}",
        HTTP_GET,
        api_version_adapter(get_proposal),
        no_auth_required)
      .set_openapi_hidden(true)
      .install();

    auto list_proposals = [&](auto& ctx, ApiVersion api_version) {
      switch (api_version)
      {
        case ApiVersion::preview_v1:
        default:
        {
          auto proposal_info_handle =
            ctx.tx.template ro<ccf::jsgov::ProposalInfoMap>(
              jsgov::Tables::PROPOSALS_INFO);

          auto proposal_list = nlohmann::json::array();
          proposal_info_handle->foreach(
            [&proposal_list](
              const auto& proposal_id, const auto& proposal_info) {
              auto api_proposal =
                detail::convert_proposal_to_api_format(proposal_info);
              api_proposal["proposalId"] = proposal_id;
              proposal_list.push_back(api_proposal);
              return true;
            });

          auto response_body = nlohmann::json::object();
          response_body["value"] = proposal_list;

          ctx.rpc_ctx->set_response_json(response_body, HTTP_STATUS_OK);
          return;
        }
      }
    };
    registry
      .make_read_only_endpoint(
        "/members/proposals",
        HTTP_GET,
        api_version_adapter(list_proposals),
        no_auth_required)
      .set_openapi_hidden(true)
      .install();

    auto get_actions = [&](auto& ctx, ApiVersion api_version) {
      switch (api_version)
      {
        case ApiVersion::preview_v1:
        default:
        {
          ccf::ProposalId proposal_id;
          if (!detail::try_parse_proposal_id(ctx.rpc_ctx, proposal_id))
          {
            return;
          }

          auto proposal_handle = ctx.tx.template ro<ccf::jsgov::ProposalMap>(
            jsgov::Tables::PROPOSALS);

          const auto proposal = proposal_handle->get(proposal_id);
          if (!proposal.has_value())
          {
            detail::set_gov_error(
              ctx.rpc_ctx,
              HTTP_STATUS_NOT_FOUND,
              ccf::errors::ProposalNotFound,
              fmt::format("Could not find proposal {}.", proposal_id));
            return;
          }

          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          ctx.rpc_ctx->set_response_body(proposal.value());
          return;
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
    auto submit_ballot =
      [&](ccf::endpoints::EndpointContext& ctx, ApiVersion api_version) {
        switch (api_version)
        {
          case ApiVersion::preview_v1:
          default:
          {
            const auto& cose_ident =
              ctx.template get_caller<ccf::MemberCOSESign1AuthnIdentity>();

            ccf::ProposalId proposal_id;
            if (!detail::try_parse_signed_proposal_id(
                  cose_ident, ctx.rpc_ctx, proposal_id))
            {
              return;
            }

            ccf::MemberId member_id;
            if (!detail::try_parse_signed_member_id(
                  cose_ident, ctx.rpc_ctx, member_id))
            {
              return;
            }

            // Look up proposal info and check expected state
            auto proposal_info_handle =
              ctx.tx.template rw<ccf::jsgov::ProposalInfoMap>(
                jsgov::Tables::PROPOSALS_INFO);
            auto proposal_info = proposal_info_handle->get(proposal_id);
            if (!proposal_info.has_value())
            {
              detail::set_gov_error(
                ctx.rpc_ctx,
                HTTP_STATUS_NOT_FOUND,
                ccf::errors::ProposalNotFound,
                fmt::format("Could not find proposal {}.", proposal_id));
              return;
            }

            if (proposal_info->state != ccf::ProposalState::OPEN)
            {
              detail::set_gov_error(
                ctx.rpc_ctx,
                HTTP_STATUS_BAD_REQUEST,
                ccf::errors::ProposalNotOpen,
                fmt::format(
                  "Proposal {} is currently in state {} - only {} proposals "
                  "can receive votes",
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
              detail::set_gov_error(
                ctx.rpc_ctx,
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
              detail::set_gov_error(
                ctx.rpc_ctx,
                HTTP_STATUS_BAD_REQUEST,
                ccf::errors::InvalidInput,
                "Signed request body is not a JSON object containing required "
                "string field \"ballot\"");
              return;
            }

            // Access constitution to evaluate ballots
            const auto constitution =
              ctx.tx.template ro<ccf::Constitution>(ccf::Tables::CONSTITUTION)
                ->get();
            if (!constitution.has_value())
            {
              detail::set_gov_error(
                ctx.rpc_ctx,
                HTTP_STATUS_INTERNAL_SERVER_ERROR,
                ccf::errors::InternalError,
                "No constitution is set - ballots cannot be evaluated");
              return;
            }

            const auto ballot = ballot_it.value().get<std::string>();

            const auto info_ballot_it = proposal_info->ballots.find(member_id);
            if (info_ballot_it != proposal_info->ballots.end())
            {
              // If ballot matches previously submitted, aim for idempotent
              // matching response
              if (info_ballot_it->second == ballot)
              {
                const auto response_body =
                  detail::convert_proposal_to_api_format(proposal_info.value());

                ctx.rpc_ctx->set_response_json(response_body, HTTP_STATUS_OK);
                return;
              }
              else
              {
                detail::set_gov_error(
                  ctx.rpc_ctx,
                  HTTP_STATUS_BAD_REQUEST,
                  ccf::errors::VoteAlreadyExists,
                  fmt::format(
                    "Different ballot already submitted by {} for {}.",
                    member_id,
                    proposal_id));
                return;
              }
            }

            // Store newly provided ballot
            proposal_info->ballots.insert_or_assign(
              info_ballot_it, member_id, ballot_it.value().get<std::string>());

            detail::record_cose_governance_history(
              ctx.tx, cose_ident.member_id, cose_ident.envelope);

            const auto resolve_result = detail::resolve_proposal(
              node_context,
              network,
              ctx.tx,
              proposal_id,
              proposal.value(),
              proposal_info.value(),
              constitution.value());

            if (resolve_result.state == ProposalState::FAILED)
            {
              // If the proposal failed to apply, we want to discard the tx and
              // not apply its side-effects to the KV state, because it may have
              // failed mid-execution (eg - thrown an exception), in which case
              // we do not want to apply partial writes
              detail::set_gov_error(
                ctx.rpc_ctx,
                HTTP_STATUS_INTERNAL_SERVER_ERROR,
                ccf::errors::InternalError,
                fmt::format("{}", resolve_result.failure));
              return;
            }

            // Write updated proposal info
            {
              proposal_info->state = resolve_result.state;
              proposal_info->failure = resolve_result.failure;

              proposal_info_handle->put(proposal_id, proposal_info.value());
            }

            const auto response_body =
              detail::convert_proposal_to_api_format(resolve_result);

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
        detail::active_member_sig_only_policies("ballot"))
      .set_openapi_hidden(true)
      .install();

    auto get_ballot = [&](auto& ctx, ApiVersion api_version) {
      switch (api_version)
      {
        case ApiVersion::preview_v1:
        default:
        {
          ccf::ProposalId proposal_id;
          if (!detail::try_parse_proposal_id(ctx.rpc_ctx, proposal_id))
          {
            return;
          }

          ccf::MemberId member_id;
          if (!detail::try_parse_member_id(ctx.rpc_ctx, member_id))
          {
            return;
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
            detail::set_gov_error(
              ctx.rpc_ctx,
              HTTP_STATUS_NOT_FOUND,
              ccf::errors::ProposalNotFound,
              fmt::format("Proposal {} does not exist.", proposal_id));
            return;
          }

          // Look up ballot
          auto ballot_it = proposal_info->ballots.find(member_id);
          if (ballot_it == proposal_info->ballots.end())
          {
            detail::set_gov_error(
              ctx.rpc_ctx,
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