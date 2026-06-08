// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "ccf/common_auth_policies.h"
#include "ccf/common_endpoint_registry.h"
#include "ccf/crypto/base64.h"
#include "ccf/crypto/key_pair.h"
#include "ccf/crypto/sha256.h"
#include "ccf/ds/nonstd.h"
#include "ccf/http_query.h"
#include "ccf/js/common_context.h"
#include "ccf/json_handler.h"
#include "ccf/node/quote.h"
#include "ccf/service/tables/gov.h"
#include "ccf/service/tables/jwt.h"
#include "ccf/service/tables/members.h"
#include "ccf/service/tables/nodes.h"
#include "ccf/service/tables/tcb_verification.h"
#include "frontend.h"
#include "js/extensions/ccf/network.h"
#include "js/extensions/ccf/node.h"
#include "node/gov/gov_endpoint_registry.h"
#include "node/rpc/call_types.h"
#include "node/rpc/gov_effects_interface.h"
#include "node/rpc/gov_logging.h"
#include "node/rpc/node_operation_interface.h"
#include "node/rpc/serialization.h"
#include "node/share_manager.h"
#include "node_interface.h"
#include "service/internal_tables_access.h"
#include "service/tables/config.h"
#include "service/tables/endpoints.h"

#include <charconv>
#include <exception>
#include <initializer_list>
#include <map>
#include <memory>
#include <openssl/crypto.h>
#include <set>
#include <sstream>

namespace ccf
{
  struct SetModule
  {
    std::string name;
    Module module;
  };
  DECLARE_JSON_TYPE(SetModule)
  DECLARE_JSON_REQUIRED_FIELDS(SetModule, name, module)

  using JsBundleEndpoint =
    std::map<std::string, ccf::endpoints::EndpointProperties>;

  struct JsBundleMetadata
  {
    std::map<std::string, JsBundleEndpoint> endpoints;
  };
  DECLARE_JSON_TYPE(JsBundleMetadata)
  DECLARE_JSON_REQUIRED_FIELDS(JsBundleMetadata, endpoints)

  struct JsBundle
  {
    JsBundleMetadata metadata;
    std::vector<SetModule> modules;
  };
  DECLARE_JSON_TYPE(JsBundle)
  DECLARE_JSON_REQUIRED_FIELDS(JsBundle, metadata, modules)

  struct KeyIdInfo
  {
    JwtIssuer issuer;
    ccf::crypto::Pem cert;
    std::string public_key;
  };
  DECLARE_JSON_TYPE(KeyIdInfo)
  DECLARE_JSON_REQUIRED_FIELDS(KeyIdInfo, issuer, cert)

  struct FullMemberDetails : public ccf::MemberDetails
  {
    ccf::crypto::Pem cert;
    std::optional<ccf::crypto::Pem> public_encryption_key;
  };
  DECLARE_JSON_TYPE(FullMemberDetails);
  DECLARE_JSON_REQUIRED_FIELDS(
    FullMemberDetails, status, member_data, cert, public_encryption_key);

  enum class ProposalSubmissionStatus
  {
    Acceptable,
    DuplicateInWindow,
    TooOld
  };

  class MemberEndpoints : public GovEndpointRegistry
  {
  private:
    // Wrapper for reporting errors, which both logs them under the [gov] tag
    // and sets the HTTP response
    static void set_gov_error(
      const std::shared_ptr<ccf::RpcContext>& rpc_ctx,
      ccf::http_status status,
      const std::string& code,
      std::string&& msg)
    {
      GOV_INFO_FMT(
        "{} {} returning error {}: {}",
        rpc_ctx->get_request_verb().c_str(),
        rpc_ctx->get_request_path(),
        status,
        msg);

      rpc_ctx->set_error(status, code, std::move(msg));
    }

    void remove_all_other_non_open_proposals(
      ccf::kv::Tx& tx, const ProposalId& proposal_id)
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
      ccf::kv::Tx& tx,
      const ProposalId& proposal_id,
      const std::span<const uint8_t>& proposal_bytes,
      const std::string& constitution)
    {
      auto pi =
        tx.rw<ccf::jsgov::ProposalInfoMap>(jsgov::Tables::PROPOSALS_INFO);
      auto pi_ = pi->get(proposal_id);

      const std::string_view proposal{
        (const char*)proposal_bytes.data(), proposal_bytes.size()};

      std::vector<std::pair<MemberId, bool>> votes;
      std::optional<ccf::jsgov::Votes> final_votes = std::nullopt;
      std::optional<ccf::jsgov::VoteFailures> vote_failures = std::nullopt;
      for (const auto& [mid, mb] : pi_->ballots)
      {
        js::CommonContextWithLocalTx context(js::TxAccess::GOV_RO, &tx);

        auto ballot_func = context.get_exported_function(
          mb,
          "vote",
          fmt::format(
            "{}[{}].ballots[{}]",
            ccf::jsgov::Tables::PROPOSALS_INFO,
            proposal_id,
            mid));

        std::vector<js::core::JSWrappedValue> argv = {
          context.new_string(proposal),
          context.new_string(pi_->proposer_id.value()),
          // Also pass the proposal_id as a string. This is useful for proposals
          // that want to refer to themselves in the resolve function, for
          // example to examine/distinguish themselves other pending proposals.
          context.new_string(proposal_id)};

        auto val = context.call_with_rt_options(
          ballot_func,
          argv,
          tx.ro<ccf::JSEngine>(ccf::Tables::JSENGINE)->get(),
          js::core::RuntimeLimitsPolicy::NO_LOWER_THAN_DEFAULTS);

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

          auto [reason, trace] = context.error_message();

          if (context.interrupt_data.request_timed_out)
          {
            reason = "Operation took too long to complete.";
          }
          vote_failures.value()[mid] = ccf::jsgov::Failure{reason, trace};
        }
      }

      {
        js::CommonContextWithLocalTx js_context(js::TxAccess::GOV_RO, &tx);

        auto resolve_func = js_context.get_exported_function(
          constitution,
          "resolve",
          fmt::format("{}[0]", ccf::Tables::CONSTITUTION));

        std::vector<js::core::JSWrappedValue> argv;
        argv.push_back(js_context.new_string(proposal));

        argv.push_back(js_context.new_string(pi_->proposer_id.value()));

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
            js_context, vs.val, index++, v, JS_PROP_C_W_E);
        }
        argv.push_back(vs);

        auto val = js_context.call_with_rt_options(
          resolve_func,
          argv,
          tx.ro<ccf::JSEngine>(ccf::Tables::JSENGINE)->get(),
          js::core::RuntimeLimitsPolicy::NO_LOWER_THAN_DEFAULTS);

        std::optional<jsgov::Failure> failure = std::nullopt;
        if (val.is_exception())
        {
          pi_.value().state = ProposalState::FAILED;
          auto [reason, trace] = js_context.error_message();
          if (js_context.interrupt_data.request_timed_out)
          {
            reason = "Operation took too long to complete.";
          }
          failure = ccf::jsgov::Failure{
            fmt::format("Failed to resolve(): {}", reason), trace};
        }
        else if (val.is_str())
        {
          auto status = js_context.to_str(val).value_or("");
          if (status == "Open")
          {
            pi_.value().state = ProposalState::OPEN;
          }
          else if (status == "Accepted")
          {
            pi_.value().state = ProposalState::ACCEPTED;
          }
          else if (status == "Withdrawn")
          {
            pi_.value().state = ProposalState::FAILED;
          }
          else if (status == "Rejected")
          {
            pi_.value().state = ProposalState::REJECTED;
          }
          else if (status == "Failed")
          {
            pi_.value().state = ProposalState::FAILED;
          }
          else if (status == "Dropped")
          {
            pi_.value().state = ProposalState::DROPPED;
          }
          else
          {
            pi_.value().state = ProposalState::FAILED;
            failure = ccf::jsgov::Failure{
              fmt::format(
                "resolve() returned invalid status value: \"{}\"", status),
              std::nullopt};
          }
        }
        else
        {
          pi_.value().state = ProposalState::FAILED;
          failure = ccf::jsgov::Failure{
            "resolve() returned invalid status value", std::nullopt};
        }

        if (pi_.value().state != ProposalState::OPEN)
        {
          remove_all_other_non_open_proposals(tx, proposal_id);
          final_votes = std::unordered_map<ccf::MemberId, bool>();
          for (auto& [mid, vote] : votes)
          {
            final_votes.value()[mid] = vote;
          }
          if (pi_.value().state == ProposalState::ACCEPTED)
          {
            auto gov_effects =
              context.get_subsystem<AbstractGovernanceEffects>();
            if (gov_effects == nullptr)
            {
              throw std::logic_error(
                "Unexpected: Could not access GovEffects subsytem");
            }

            js::CommonContextWithLocalTx apply_js_context(
              js::TxAccess::GOV_RW, &tx);

            apply_js_context.add_extension(
              std::make_shared<ccf::js::extensions::NodeExtension>(
                gov_effects.get(), &tx));
            apply_js_context.add_extension(
              std::make_shared<ccf::js::extensions::NetworkExtension>(
                &network, &tx));
            apply_js_context.add_extension(
              std::make_shared<ccf::js::extensions::GovEffectsExtension>(&tx));

            auto apply_func = apply_js_context.get_exported_function(
              constitution,
              "apply",
              fmt::format("{}[0]", ccf::Tables::CONSTITUTION));

            std::vector<js::core::JSWrappedValue> apply_argv = {
              apply_js_context.new_string(proposal),
              apply_js_context.new_string(proposal_id)};

            auto apply_val = apply_js_context.call_with_rt_options(
              apply_func,
              apply_argv,
              tx.ro<ccf::JSEngine>(ccf::Tables::JSENGINE)->get(),
              js::core::RuntimeLimitsPolicy::NO_LOWER_THAN_DEFAULTS);

            if (apply_val.is_exception())
            {
              pi_.value().state = ProposalState::FAILED;
              auto [reason, trace] = apply_js_context.error_message();
              if (apply_js_context.interrupt_data.request_timed_out)
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
          pi_->proposer_id,
          pi_.value().state,
          pi_.value().ballots.size(),
          final_votes,
          vote_failures,
          failure};
      }
    }

    bool check_member_active(ccf::kv::ReadOnlyTx& tx, const MemberId& id)
    {
      return check_member_status(tx, id, {MemberStatus::ACTIVE});
    }

    bool check_member_status(
      ccf::kv::ReadOnlyTx& tx,
      const MemberId& id,
      std::initializer_list<MemberStatus> allowed)
    {
      auto member = tx.ro(this->network.member_info)->get(id);
      if (!member.has_value())
      {
        return false;
      }
      for (const auto s : allowed)
      {
        if (member->status == s)
        {
          return true;
        }
      }
      return false;
    }

    void record_voting_history(
      ccf::kv::Tx& tx,
      const MemberId& caller_id,
      const SignedReq& signed_request)
    {
      auto governance_history = tx.rw(network.governance_history);
      governance_history->put(caller_id, {signed_request});
    }

    void record_cose_governance_history(
      ccf::kv::Tx& tx,
      const MemberId& caller_id,
      const std::span<const uint8_t>& cose_sign1)
    {
      auto cose_governance_history = tx.rw(network.cose_governance_history);
      cose_governance_history->put(
        caller_id, {cose_sign1.begin(), cose_sign1.end()});
    }

    ProposalSubmissionStatus is_proposal_submission_acceptable(
      ccf::kv::Tx& tx,
      const std::string& created_at,
      const std::vector<uint8_t>& request_digest,
      const ccf::ProposalId& proposal_id,
      ccf::ProposalId& colliding_proposal_id,
      std::string& min_created_at)
    {
      auto cose_recent_proposals = tx.rw(network.cose_recent_proposals);
      auto key = fmt::format("{}:{}", created_at, ds::to_hex(request_digest));

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
        min_created_at = std::get<0>(
          ccf::nonstd::split_1(replay_keys[replay_keys.size() / 2], ":"));
        auto [key_ts, __] = ccf::nonstd::split_1(key, ":");
        if (key_ts < min_created_at)
        {
          return ProposalSubmissionStatus::TooOld;
        }
      }

      if (cose_recent_proposals->has(key))
      {
        colliding_proposal_id = cose_recent_proposals->get(key).value();
        return ProposalSubmissionStatus::DuplicateInWindow;
      }
      else
      {
        size_t window_size = ccf::default_recent_cose_proposals_window_size;
        auto service = tx.ro(network.config);
        auto service_config = service->get();
        if (
          service_config.has_value() &&
          service_config->recent_cose_proposals_window_size.has_value())
        {
          window_size =
            service_config->recent_cose_proposals_window_size.value();
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
        return ProposalSubmissionStatus::Acceptable;
      }
    }

    bool get_proposal_id_from_path(
      const ccf::PathParams& params,
      ProposalId& proposal_id,
      std::string& error)
    {
      return get_path_param(params, "proposal_id", proposal_id, error);
    }

    bool get_member_id_from_path(
      const ccf::PathParams& params, MemberId& member_id, std::string& error)
    {
      return get_path_param(params, "member_id", member_id.value(), error);
    }

    template <typename T>
    void add_kv_wrapper_endpoint(T table)
    {
      constexpr bool is_map =
        ccf::nonstd::is_specialization<T, ccf::kv::TypedMap>::value;
      constexpr bool is_value =
        ccf::nonstd::is_specialization<T, ccf::kv::TypedValue>::value;
      constexpr bool is_set =
        ccf::nonstd::is_specialization<T, ccf::kv::TypedSet>::value;

      if constexpr (!(is_map || is_value || is_set))
      {
        static_assert(
          ccf::nonstd::dependent_false_v<T>, "Unsupported table type");
      }

      auto getter =
        [&, table](endpoints::ReadOnlyEndpointContext& ctx, nlohmann::json&&) {
          GOV_TRACE_FMT("Called getter for {}", table.get_name());
          auto response_body = nlohmann::json::object();

          auto handle = ctx.tx.template ro(table);
          if constexpr (is_map)
          {
            handle->foreach([&response_body](const auto& k, const auto& v) {
              if constexpr (
                std::is_same_v<typename T::Key, ccf::crypto::Sha256Hash> ||
                pal::is_attestation_measurement<typename T::Key>::value ||
                std::is_same_v<typename T::Key, ccf::pal::snp::CPUID>)
              {
                response_body[k.hex_str()] = v;
              }
              else if constexpr (std::is_same_v<
                                   typename T::Key,
                                   ccf::endpoints::EndpointKey>)
              {
                response_body[k.to_str()] = v;
              }
              else
              {
                response_body[k] = v;
              }
              return true;
            });
          }
          else if constexpr (is_value)
          {
            response_body = handle->get();
          }
          else if constexpr (is_set)
          {
            response_body = nlohmann::json::array();
            handle->foreach([&response_body](const auto& k) {
              response_body.push_back(k);
              return true;
            });
          }

          return ccf::make_success(response_body);
        };

      std::string uri = table.get_name();
      constexpr auto gov_prefix = "public:ccf.gov.";
      if (uri.starts_with(gov_prefix))
      {
        uri.erase(0, strlen(gov_prefix));
      }
      else
      {
        throw std::logic_error(fmt::format(
          "Should only be used to wrap governance tables. '{}' is not "
          "supported",
          uri));
      }

      // Replace . separators with /
      {
        auto idx = uri.find('.');
        while (idx != std::string::npos)
        {
          uri[idx] = '/';
          idx = uri.find('.', idx);
        }
      }

      auto endpoint = make_read_only_endpoint(
        fmt::format("/kv/{}", uri),
        HTTP_GET,
        json_read_only_adapter(getter),
        ccf::no_auth_required);

      if constexpr (is_map)
      {
        endpoint.template set_auto_schema<
          void,
          std::map<typename T::Key, typename T::Value>>();
      }
      else if constexpr (is_value)
      {
        endpoint.template set_auto_schema<void, typename T::Value>();
      }

      endpoint.set_openapi_summary(
        "This route is auto-generated from the KV schema.");
      endpoint.set_openapi_deprecated(true);

      endpoint.install();
    }

    void add_kv_wrapper_endpoints()
    {
      const auto all_gov_tables = network.get_all_builtin_governance_tables();
      ccf::nonstd::tuple_for_each(
        all_gov_tables, [this](auto table) { add_kv_wrapper_endpoint(table); });
    }

    NetworkState& network;
    ShareManager share_manager;

  public:
    MemberEndpoints(
      NetworkState& network_, ccf::AbstractNodeContext& context_) :
      GovEndpointRegistry(network_, context_),
      network(network_),
      share_manager(network_.ledger_secrets)
    {
      openapi_info.title = "CCF Governance API";
      openapi_info.description =
        "This API is used to submit and query proposals which affect CCF's "
        "public governance tables.";
      openapi_info.document_version = "4.7.6";
    }

    static std::optional<MemberId> get_caller_member_id(
      endpoints::CommandEndpointContext& ctx)
    {
      if (
        const auto* cose_ident =
          ctx.try_get_caller<ccf::MemberCOSESign1AuthnIdentity>())
      {
        return cose_ident->member_id;
      }
      else if (
        const auto* cert_ident =
          ctx.try_get_caller<ccf::MemberCertAuthnIdentity>())
      {
        return cert_ident->member_id;
      }

      GOV_FAIL_FMT("Request was not authenticated with a member auth policy");
      return std::nullopt;
    }

    bool authnz_active_member(
      ccf::endpoints::EndpointContext& ctx,
      std::optional<MemberId>& member_id,
      std::optional<ccf::MemberCOSESign1AuthnIdentity>& cose_auth_id,
      bool must_be_active = true)
    {
      if (
        const auto* cose_ident =
          ctx.try_get_caller<ccf::MemberCOSESign1AuthnIdentity>())
      {
        member_id = cose_ident->member_id;
        cose_auth_id = *cose_ident;
      }
      else
      {
        set_gov_error(
          ctx.rpc_ctx,
          HTTP_STATUS_FORBIDDEN,
          ccf::errors::AuthorizationFailed,
          "Caller is a not a valid member id");

        return false;
      }

      if (must_be_active && !check_member_active(ctx.tx, member_id.value()))
      {
        set_gov_error(
          ctx.rpc_ctx,
          HTTP_STATUS_FORBIDDEN,
          ccf::errors::AuthorizationFailed,
          fmt::format("Member {} is not active.", member_id.value()));
        return false;
      }

      return true;
    }

    AuthnPolicies member_sig_only_policies(const std::string& gov_msg_type)
    {
      return {std::make_shared<MemberCOSESign1AuthnPolicy>(gov_msg_type)};
    }

    AuthnPolicies member_cert_or_sig_policies(const std::string& gov_msg_type)
    {
      return {
        member_cert_auth_policy,
        std::make_shared<MemberCOSESign1AuthnPolicy>(gov_msg_type)};
    }

    void init_handlers() override
    {
      GovEndpointRegistry::init_handlers();

      //! A member acknowledges state
      auto ack = [this](ccf::endpoints::EndpointContext& ctx) {
        std::optional<ccf::MemberCOSESign1AuthnIdentity> cose_auth_id =
          std::nullopt;
        std::optional<MemberId> member_id = std::nullopt;
        if (!authnz_active_member(ctx, member_id, cose_auth_id, false))
        {
          return;
        }

        auto params = nlohmann::json::parse(
          cose_auth_id.has_value() ? cose_auth_id->content :
                                     ctx.rpc_ctx->get_request_body());

        auto mas = ctx.tx.rw(this->network.member_acks);
        const auto ma = mas->get(member_id.value());
        if (!ma)
        {
          set_gov_error(
            ctx.rpc_ctx,
            HTTP_STATUS_FORBIDDEN,
            ccf::errors::AuthorizationFailed,
            fmt::format(
              "No ACK record exists for caller {}.", member_id.value()));
          return;
        }

        const auto digest = params.get<StateDigest>();
        if (ma->state_digest != digest.state_digest)
        {
          set_gov_error(
            ctx.rpc_ctx,
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::StateDigestMismatch,
            "Submitted state digest is not valid.");
          return;
        }

        auto sig = ctx.tx.rw(this->network.signatures);
        const auto s = sig->get();
        if (cose_auth_id.has_value())
        {
          std::vector<uint8_t> cose_sign1 = {
            cose_auth_id->envelope.begin(), cose_auth_id->envelope.end()};
          if (!s)
          {
            mas->put(member_id.value(), MemberAck({}, cose_sign1));
          }
          else
          {
            mas->put(member_id.value(), MemberAck(s->root, cose_sign1));
          }
        }

        // update member status to ACTIVE
        try
        {
          InternalTablesAccess::activate_member(ctx.tx, member_id.value());
        }
        catch (const std::logic_error& e)
        {
          set_gov_error(
            ctx.rpc_ctx,
            HTTP_STATUS_FORBIDDEN,
            ccf::errors::AuthorizationFailed,
            fmt::format("Error activating new member: {}", e.what()));
          return;
        }

        auto service_status = InternalTablesAccess::get_service_status(ctx.tx);
        if (!service_status.has_value())
        {
          set_gov_error(
            ctx.rpc_ctx,
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            "No service currently available.");
          return;
        }

        auto members = ctx.tx.rw(this->network.member_info);
        auto member_info = members->get(member_id.value());
        if (
          service_status.value() == ServiceStatus::OPEN &&
          InternalTablesAccess::is_recovery_participant_or_owner(
            ctx.tx, member_id.value()))
        {
          // When the service is OPEN and the new active member is a recovery
          // participant/owner, all recovery members are allocated new recovery
          // shares
          try
          {
            share_manager.shuffle_recovery_shares(ctx.tx);
          }
          catch (const std::logic_error& e)
          {
            set_gov_error(
              ctx.rpc_ctx,
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              fmt::format("Error issuing new recovery shares: {}", e.what()));
            return;
          }
        }
        ctx.rpc_ctx->set_response_status(HTTP_STATUS_NO_CONTENT);
        return;
      };
      make_endpoint("/ack", HTTP_POST, ack, member_sig_only_policies("ack"))
        .set_openapi_summary(
          "Provide a member endorsement of a service state digest")
        .set_auto_schema<StateDigest, void>()
        .set_openapi_deprecated_replaced(
          "5.0.0", "POST /gov/members/state-digests/{memberId}:ack")
        .install();

      //! A member asks for a fresher state digest
      auto update_state_digest = [this](ccf::endpoints::EndpointContext& ctx) {
        const auto member_id = get_caller_member_id(ctx);
        if (!member_id.has_value())
        {
          set_gov_error(
            ctx.rpc_ctx,
            HTTP_STATUS_FORBIDDEN,
            ccf::errors::AuthorizationFailed,
            "Caller is a not a valid member id");
          return;
        }

        auto mas = ctx.tx.rw(this->network.member_acks);
        auto sig = ctx.tx.rw(this->network.signatures);
        auto ma = mas->get(member_id.value());
        if (!ma)
        {
          set_gov_error(
            ctx.rpc_ctx,
            HTTP_STATUS_FORBIDDEN,
            ccf::errors::AuthorizationFailed,
            fmt::format(
              "No ACK record exists for caller {}.", member_id.value()));
          return;
        }

        auto s = sig->get();
        if (s)
        {
          ma->state_digest = s->root.hex_str();
          mas->put(member_id.value(), ma.value());
        }
        nlohmann::json j;
        j["state_digest"] = ma->state_digest;

        ctx.rpc_ctx->set_response_header(
          ccf::http::headers::CONTENT_TYPE,
          http::headervalues::contenttype::JSON);
        ctx.rpc_ctx->set_response_body(j.dump());
        ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        return;
      };
      make_endpoint(
        "/ack/update_state_digest",
        HTTP_POST,
        update_state_digest,
        member_cert_or_sig_policies("state_digest"))
        .set_auto_schema<void, StateDigest>()
        .set_openapi_summary(
          "Update and fetch a service state digest, for the purpose of member "
          "endorsement")
        .set_openapi_deprecated_replaced(
          "5.0.0", "POST /gov/members/state-digests/{memberId}:update")
        .install();

      auto get_encrypted_recovery_share =
        [this](ccf::endpoints::EndpointContext& ctx) {
          const auto member_id = get_caller_member_id(ctx);
          if (!member_id.has_value())
          {
            set_gov_error(
              ctx.rpc_ctx,
              HTTP_STATUS_FORBIDDEN,
              ccf::errors::AuthorizationFailed,
              "Member is unknown.");
            return;
          }
          if (!check_member_active(ctx.tx, member_id.value()))
          {
            set_gov_error(
              ctx.rpc_ctx,
              HTTP_STATUS_FORBIDDEN,
              ccf::errors::AuthorizationFailed,
              "Only active members are given recovery shares.");
            return;
          }

          auto encrypted_share =
            share_manager.get_encrypted_share(ctx.tx, member_id.value());

          if (!encrypted_share.has_value())
          {
            set_gov_error(
              ctx.rpc_ctx,
              HTTP_STATUS_NOT_FOUND,
              ccf::errors::ResourceNotFound,
              fmt::format(
                "Recovery share not found for member {}.", member_id->value()));
            return;
          }

          auto rec_share = GetRecoveryShare::Out{
            ccf::crypto::b64_from_raw(encrypted_share.value())};
          ctx.rpc_ctx->set_response_header(
            ccf::http::headers::CONTENT_TYPE,
            http::headervalues::contenttype::JSON);
          ctx.rpc_ctx->set_response_body(nlohmann::json(rec_share).dump());
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          return;
        };
      make_endpoint(
        "/recovery_share",
        HTTP_GET,
        get_encrypted_recovery_share,
        member_cert_or_sig_policies("encrypted_recovery_share"))
        .set_auto_schema<GetRecoveryShare>()
        .set_openapi_summary("A member's recovery share")
        .set_openapi_deprecated_replaced(
          "5.0.0", "GET /gov/recovery/encrypted-shares/{memberId}")
        .install();

      auto get_encrypted_recovery_share_for_member =
        [this](ccf::endpoints::EndpointContext& ctx) {
          std::string error_msg;
          MemberId member_id;
          if (!get_member_id_from_path(
                ctx.rpc_ctx->get_request_path_params(), member_id, error_msg))
          {
            set_gov_error(
              ctx.rpc_ctx,
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::InvalidResourceName,
              std::move(error_msg));
            return;
          }

          auto encrypted_share =
            share_manager.get_encrypted_share(ctx.tx, member_id);

          if (!encrypted_share.has_value())
          {
            set_gov_error(
              ctx.rpc_ctx,
              HTTP_STATUS_NOT_FOUND,
              ccf::errors::ResourceNotFound,
              fmt::format(
                "Recovery share not found for member {}.", member_id));
            return;
          }

          auto rec_share = GetRecoveryShare::Out{
            ccf::crypto::b64_from_raw(encrypted_share.value())};
          ctx.rpc_ctx->set_response_header(
            ccf::http::headers::CONTENT_TYPE,
            http::headervalues::contenttype::JSON);
          ctx.rpc_ctx->set_response_body(nlohmann::json(rec_share).dump());
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          return;
        };
      make_endpoint(
        "/encrypted_recovery_share/{member_id}",
        HTTP_GET,
        get_encrypted_recovery_share_for_member,
        ccf::no_auth_required)
        .set_auto_schema<GetRecoveryShare>()
        .set_openapi_summary("A member's recovery share")
        .set_openapi_deprecated_replaced(
          "5.0.0", "GET /gov/recovery/encrypted-shares/{memberId}")
        .install();

      auto submit_recovery_share = [this](
                                     ccf::endpoints::EndpointContext& ctx) {
        // Only active members can submit their shares for recovery
        const auto member_id = get_caller_member_id(ctx);
        if (!member_id.has_value())
        {
          set_gov_error(
            ctx.rpc_ctx,
            HTTP_STATUS_FORBIDDEN,
            ccf::errors::AuthorizationFailed,
            "Member is unknown.");
          return;
        }
        if (!check_member_active(ctx.tx, member_id.value()))
        {
          set_gov_error(
            ctx.rpc_ctx,
            HTTP_STATUS_FORBIDDEN,
            errors::AuthorizationFailed,
            "Member is not active.");
          return;
        }

        const auto* cose_auth_id =
          ctx.try_get_caller<ccf::MemberCOSESign1AuthnIdentity>();
        auto params = nlohmann::json::parse(
          cose_auth_id ? cose_auth_id->content :
                         ctx.rpc_ctx->get_request_body());

        if (
          InternalTablesAccess::get_service_status(ctx.tx) !=
          ServiceStatus::WAITING_FOR_RECOVERY_SHARES)
        {
          set_gov_error(
            ctx.rpc_ctx,
            HTTP_STATUS_FORBIDDEN,
            errors::ServiceNotWaitingForRecoveryShares,
            "Service is not waiting for recovery shares.");
          return;
        }

        auto node_operation = context.get_subsystem<AbstractNodeOperation>();
        if (node_operation == nullptr)
        {
          throw std::logic_error(
            "Unexpected: Could not access NodeOperation subsystem");
        }

        if (node_operation->is_reading_private_ledger())
        {
          set_gov_error(
            ctx.rpc_ctx,
            HTTP_STATUS_FORBIDDEN,
            errors::NodeAlreadyRecovering,
            "Node is already recovering private ledger.");
          return;
        }

        std::string share = params["share"];
        auto raw_recovery_share = ccf::crypto::raw_from_b64(share);
        OPENSSL_cleanse(const_cast<char*>(share.data()), share.size());

        size_t submitted_shares_count = 0;
        bool full_key_submitted = false;
        try
        {
          submitted_shares_count = share_manager.submit_recovery_share(
            ctx.tx, member_id.value(), raw_recovery_share);

          full_key_submitted = ShareManager::is_full_key(raw_recovery_share);

          OPENSSL_cleanse(raw_recovery_share.data(), raw_recovery_share.size());
        }
        catch (const std::exception& e)
        {
          OPENSSL_cleanse(raw_recovery_share.data(), raw_recovery_share.size());

          constexpr auto error_msg = "Error submitting recovery shares.";
          GOV_FAIL_FMT(error_msg);
          GOV_DEBUG_FMT("Error: {}", e.what());
          set_gov_error(
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
            set_gov_error(
              ctx.rpc_ctx,
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              errors::InternalError,
              error_msg);
            return;
          }
        }

        auto recovery_share = SubmitRecoveryShare::Out{message};
        ctx.rpc_ctx->set_response_header(
          ccf::http::headers::CONTENT_TYPE,
          http::headervalues::contenttype::JSON);
        ctx.rpc_ctx->set_response_body(nlohmann::json(recovery_share).dump());
        ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        return;
      };
      make_endpoint(
        "/recovery_share",
        HTTP_POST,
        submit_recovery_share,
        member_cert_or_sig_policies("recovery_share"))
        .set_auto_schema<SubmitRecoveryShare>()
        .set_openapi_summary(
          "Provide a recovery share for the purpose of completing a service "
          "recovery")
        .set_openapi_deprecated_replaced(
          "5.0.0", "POST /gov/recovery/members/{memberId}:recover")
        .install();

      using JWTKeyMap = std::map<JwtKeyId, std::vector<KeyIdInfo>>;

      auto get_jwt_keys = [this](auto& ctx, nlohmann::json&& body) {
        auto keys = ctx.tx.ro(network.jwt_public_signing_keys_metadata);
        JWTKeyMap kmap;
        keys->foreach([&kmap](const auto& k, const auto& v) {
          std::vector<KeyIdInfo> info;
          for (const auto& metadata : v)
          {
            info.push_back(KeyIdInfo{
              .issuer = metadata.issuer,
              .cert = ccf::crypto::Pem(),
              .public_key = ccf::crypto::b64_from_raw(metadata.public_key)});
          }
          kmap.emplace(k, std::move(info));
          return true;
        });

        return make_success(kmap);
      };
      make_endpoint(
        "/jwt_keys/all", HTTP_GET, json_adapter(get_jwt_keys), no_auth_required)
        .set_auto_schema<void, JWTKeyMap>()
        .set_openapi_deprecated_replaced("5.0.0", "POST /gov/service/jwk")
        .install();

      auto post_proposals_js = [this](ccf::endpoints::EndpointContext& ctx) {
        std::optional<ccf::MemberCOSESign1AuthnIdentity> cose_auth_id =
          std::nullopt;
        std::optional<MemberId> member_id = std::nullopt;
        if (!authnz_active_member(ctx, member_id, cose_auth_id))
        {
          return;
        }

        if (!consensus)
        {
          set_gov_error(
            ctx.rpc_ctx,
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            "No consensus available.");
          return;
        }

        std::vector<uint8_t> request_digest;
        if (cose_auth_id.has_value())
        {
          std::span<const uint8_t> sig = cose_auth_id->signature;
          request_digest = ccf::crypto::sha256(sig);
        }

        ProposalId proposal_id;
        auto root_at_read = ctx.tx.get_root_at_read_version();
        if (!root_at_read.has_value())
        {
          set_gov_error(
            ctx.rpc_ctx,
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            "Proposal failed to bind to state.");
          return;
        }

        // caller_identity.request_digest is set when getting the
        // MemberSignatureAuthnIdentity identity. The proposal id is a
        // digest of the root of the state tree at the read version and the
        // request digest.
        std::vector<uint8_t> acc(
          root_at_read.value().h.begin(), root_at_read.value().h.end());
        acc.insert(acc.end(), request_digest.begin(), request_digest.end());
        const ccf::crypto::Sha256Hash proposal_digest(acc);
        proposal_id = proposal_digest.hex_str();

        auto constitution = ctx.tx.ro(network.constitution)->get();
        if (!constitution.has_value())
        {
          set_gov_error(
            ctx.rpc_ctx,
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            "No constitution is set - proposals cannot be evaluated");
          return;
        }

        auto validate_script = constitution.value();

        js::CommonContextWithLocalTx context(js::TxAccess::GOV_RO, &ctx.tx);

        auto validate_func = context.get_exported_function(
          validate_script,
          "validate",
          fmt::format("{}[0]", ccf::Tables::CONSTITUTION));

        const std::span<const uint8_t> proposal_body =
          cose_auth_id.has_value() ? cose_auth_id->content :
                                     ctx.rpc_ctx->get_request_body();

        auto body = reinterpret_cast<const char*>(proposal_body.data());
        auto body_len = proposal_body.size();

        auto proposal = context.new_string_len(body, body_len);
        auto val = context.call_with_rt_options(
          validate_func,
          {proposal},
          ctx.tx.ro<ccf::JSEngine>(ccf::Tables::JSENGINE)->get(),
          js::core::RuntimeLimitsPolicy::NO_LOWER_THAN_DEFAULTS);

        if (val.is_exception())
        {
          auto [reason, trace] = context.error_message();
          if (context.interrupt_data.request_timed_out)
          {
            reason = "Operation took too long to complete.";
          }
          set_gov_error(
            ctx.rpc_ctx,
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            fmt::format(
              "Failed to execute validation: {} {}",
              reason,
              trace.value_or("")));
          return;
        }

        if (!val.is_obj())
        {
          set_gov_error(
            ctx.rpc_ctx,
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            "Validation failed to return an object");
          return;
        }

        std::string description;
        auto desc = val["description"];
        if (desc.is_str())
        {
          description = context.to_str(desc).value_or("");
        }

        auto valid = val["valid"];
        if (!valid.is_true())
        {
          set_gov_error(
            ctx.rpc_ctx,
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::ProposalFailedToValidate,
            fmt::format("Proposal failed to validate: {}", description));
          return;
        }

        auto pm = ctx.tx.rw<ccf::jsgov::ProposalMap>(jsgov::Tables::PROPOSALS);
        // Introduce a read dependency, so that if identical proposal
        // creations are in-flight and reading at the same version, all except
        // the first conflict and are re-executed. If we ever produce a
        // proposal ID which already exists, we must have a hash collision.
        if (pm->has(proposal_id))
        {
          set_gov_error(
            ctx.rpc_ctx,
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            "Proposal ID collision.");
          return;
        }
        pm->put(proposal_id, {proposal_body.begin(), proposal_body.end()});

        auto pi =
          ctx.tx.rw<ccf::jsgov::ProposalInfoMap>(jsgov::Tables::PROPOSALS_INFO);
        pi->put(proposal_id, {member_id.value(), ccf::ProposalState::OPEN, {}});

        if (cose_auth_id.has_value())
        {
          record_cose_governance_history(
            ctx.tx, member_id.value(), cose_auth_id->envelope);
          ccf::ProposalId colliding_proposal_id = proposal_id;
          std::string min_created_at = "";
          // created_at, submitted as a binary integer number of seconds since
          // epoch in the COSE Sign1 envelope, is converted to a decimal
          // representation in ASCII, stored as a string, and compared
          // alphanumerically. This is partly to keep governance as text-based
          // as possible, to faciliate audit, but also to be able to benefit
          // from future planned ordering support in the KV. To compare
          // correctly, the string representation needs to be padded with
          // leading zeroes, and must therefore not exceed a fixed digit width.
          // 10 digits is enough to last until November 2286, ie. long enough.
          if (cose_auth_id->protected_header.gov_msg_created_at > 9'999'999'999)
          {
            set_gov_error(
              ctx.rpc_ctx,
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::InvalidCreatedAt,
              "Header parameter created_at value is too large");
            return;
          }
          std::string created_at_str = fmt::format(
            "{:0>10}", cose_auth_id->protected_header.gov_msg_created_at);
          const auto acceptable = is_proposal_submission_acceptable(
            ctx.tx,
            created_at_str,
            request_digest,
            proposal_id,
            colliding_proposal_id,
            min_created_at);
          switch (acceptable)
          {
            case ProposalSubmissionStatus::TooOld:
            {
              set_gov_error(
                ctx.rpc_ctx,
                HTTP_STATUS_BAD_REQUEST,
                ccf::errors::ProposalCreatedTooLongAgo,
                fmt::format(
                  "Proposal created too long ago, created_at must be greater "
                  "than {}",
                  min_created_at));
              return;
            }
            case ProposalSubmissionStatus::DuplicateInWindow:
            {
              set_gov_error(
                ctx.rpc_ctx,
                HTTP_STATUS_BAD_REQUEST,
                ccf::errors::ProposalReplay,
                fmt::format(
                  "Proposal submission replay, already exists as proposal {}",
                  colliding_proposal_id));
              return;
            }
            case ProposalSubmissionStatus::Acceptable:
              break;
            default:
              throw std::runtime_error(
                "Invalid ProposalSubmissionStatus value");
          };
        }

        auto rv = resolve_proposal(
          ctx.tx, proposal_id, proposal_body, constitution.value());

        if (rv.state == ProposalState::FAILED)
        {
          // If the proposal failed to apply, we want to discard the tx and not
          // apply its side-effects to the KV state.
          set_gov_error(
            ctx.rpc_ctx,
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            fmt::format("{}", rv.failure));
          return;
        }
        else
        {
          pi->put(
            proposal_id,
            {member_id.value(), rv.state, {}, {}, std::nullopt, rv.failure});
          ctx.rpc_ctx->set_response_header(
            ccf::http::headers::CONTENT_TYPE,
            http::headervalues::contenttype::JSON);
          ctx.rpc_ctx->set_response_body(nlohmann::json(rv).dump());
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          return;
        }
      };

      make_endpoint(
        "/proposals",
        HTTP_POST,
        post_proposals_js,
        member_sig_only_policies("proposal"))
        .set_auto_schema<jsgov::Proposal, jsgov::ProposalInfoSummary>()
        .set_openapi_deprecated_replaced(
          "5.0.0", "POST /gov/members/proposals:create")
        .install();

      using AllOpenProposals = std::map<ProposalId, jsgov::ProposalInfo>;
      auto get_open_proposals_js =
        [this](endpoints::ReadOnlyEndpointContext& ctx, nlohmann::json&&) {
          auto proposal_info = ctx.tx.ro<ccf::jsgov::ProposalInfoMap>(
            jsgov::Tables::PROPOSALS_INFO);
          AllOpenProposals response;
          proposal_info->foreach(
            [&response](
              const ProposalId& pid, const ccf::jsgov::ProposalInfo& pinfo) {
              if (pinfo.state == ProposalState::OPEN)
              {
                response[pid] = pinfo;
              }
              return true;
            });
          return make_success(response);
        };

      make_read_only_endpoint(
        "/proposals",
        HTTP_GET,
        json_read_only_adapter(get_open_proposals_js),
        ccf::no_auth_required)
        .set_auto_schema<void, AllOpenProposals>()
        .set_openapi_summary(
          "Proposed changes to the service pending resolution")
        .set_openapi_deprecated_replaced("5.0.0", "GET /gov/members/proposals")
        .install();

      auto get_proposal_js = [this](
                               endpoints::ReadOnlyEndpointContext& ctx,
                               nlohmann::json&&) {
        // Take expand=ballots, return eg. "ballots": 3 if not set
        // or "ballots": list of ballots in full if passed

        ProposalId proposal_id;
        std::string error;
        if (!get_proposal_id_from_path(
              ctx.rpc_ctx->get_request_path_params(), proposal_id, error))
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST, ccf::errors::InvalidResourceName, error);
        }

        auto pm = ctx.tx.ro<ccf::jsgov::ProposalMap>(jsgov::Tables::PROPOSALS);
        auto p = pm->get(proposal_id);

        if (!p)
        {
          return make_error(
            HTTP_STATUS_NOT_FOUND,
            ccf::errors::ProposalNotFound,
            fmt::format("Proposal {} does not exist.", proposal_id));
        }

        auto pi =
          ctx.tx.ro<ccf::jsgov::ProposalInfoMap>(jsgov::Tables::PROPOSALS_INFO);
        auto pi_ = pi->get(proposal_id);

        if (!pi_)
        {
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            fmt::format(
              "No proposal info associated with {} exists.", proposal_id));
        }

        return make_success(pi_.value());
      };

      make_read_only_endpoint(
        "/proposals/{proposal_id}",
        HTTP_GET,
        json_read_only_adapter(get_proposal_js),
        ccf::no_auth_required)
        .set_auto_schema<void, jsgov::ProposalInfo>()
        .set_openapi_summary(
          "Information about a proposed change to the service")
        .set_openapi_deprecated_replaced(
          "5.0.0", "GET /gov/members/proposals/{proposalId}")
        .install();

      auto withdraw_js = [this](ccf::endpoints::EndpointContext& ctx) {
        std::optional<ccf::MemberCOSESign1AuthnIdentity> cose_auth_id =
          std::nullopt;
        std::optional<MemberId> member_id = std::nullopt;
        if (!authnz_active_member(ctx, member_id, cose_auth_id))
        {
          return;
        }

        ProposalId proposal_id;
        std::string error;
        if (!get_proposal_id_from_path(
              ctx.rpc_ctx->get_request_path_params(), proposal_id, error))
        {
          set_gov_error(
            ctx.rpc_ctx,
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidResourceName,
            std::move(error));
          return;
        }

        if (cose_auth_id.has_value())
        {
          if (!(cose_auth_id->protected_header.gov_msg_proposal_id
                  .has_value() &&
                cose_auth_id->protected_header.gov_msg_proposal_id.value() ==
                  proposal_id))
          {
            set_gov_error(
              ctx.rpc_ctx,
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::InvalidResourceName,
              "Authenticated proposal id does not match URL");
            return;
          }
        }

        auto pi =
          ctx.tx.rw<ccf::jsgov::ProposalInfoMap>(jsgov::Tables::PROPOSALS_INFO);
        auto pi_ = pi->get(proposal_id);

        if (!pi_)
        {
          set_gov_error(
            ctx.rpc_ctx,
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::ProposalNotFound,
            fmt::format("Proposal {} does not exist.", proposal_id));
          return;
        }

        if (member_id.value() != pi_->proposer_id)
        {
          set_gov_error(
            ctx.rpc_ctx,
            HTTP_STATUS_FORBIDDEN,
            ccf::errors::AuthorizationFailed,
            fmt::format(
              "Proposal {} can only be withdrawn by proposer {}, not caller "
              "{}.",
              proposal_id,
              pi_->proposer_id,
              member_id.value()));
          return;
        }

        if (pi_->state != ProposalState::OPEN)
        {
          set_gov_error(
            ctx.rpc_ctx,
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::ProposalNotOpen,
            fmt::format(
              "Proposal {} is currently in state {} - only {} proposals can be "
              "withdrawn.",
              proposal_id,
              pi_->state,
              ProposalState::OPEN));
          return;
        }

        pi_->state = ProposalState::WITHDRAWN;
        pi->put(proposal_id, pi_.value());

        remove_all_other_non_open_proposals(ctx.tx, proposal_id);
        if (cose_auth_id.has_value())
        {
          record_cose_governance_history(
            ctx.tx, member_id.value(), cose_auth_id->envelope);
        }

        ctx.rpc_ctx->set_response_header(
          ccf::http::headers::CONTENT_TYPE,
          http::headervalues::contenttype::JSON);
        ctx.rpc_ctx->set_response_body(nlohmann::json(pi_.value()).dump());
        ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
      };

      make_endpoint(
        "/proposals/{proposal_id}/withdraw",
        HTTP_POST,
        withdraw_js,
        member_sig_only_policies("withdrawal"))
        .set_auto_schema<void, jsgov::ProposalInfo>()
        .set_openapi_summary("Withdraw a proposed change to the service")
        .set_openapi_deprecated_replaced(
          "5.0.0", "POST /gov/members/proposals/{proposalId}:withdraw")
        .install();

      auto get_proposal_actions_js =
        [this](ccf::endpoints::ReadOnlyEndpointContext& ctx) {
          ProposalId proposal_id;
          std::string error;
          if (!get_proposal_id_from_path(
                ctx.rpc_ctx->get_request_path_params(), proposal_id, error))
          {
            set_gov_error(
              ctx.rpc_ctx,
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::InvalidResourceName,
              std::move(error));
            return;
          }

          auto pm =
            ctx.tx.ro<ccf::jsgov::ProposalMap>(jsgov::Tables::PROPOSALS);
          auto p = pm->get(proposal_id);

          if (!p)
          {
            set_gov_error(
              ctx.rpc_ctx,
              HTTP_STATUS_NOT_FOUND,
              ccf::errors::ProposalNotFound,
              fmt::format("Proposal {} does not exist.", proposal_id));
            return;
          }

          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          ctx.rpc_ctx->set_response_header(
            ccf::http::headers::CONTENT_TYPE,
            http::headervalues::contenttype::JSON);
          ctx.rpc_ctx->set_response_body(std::move(p.value()));
        };

      make_read_only_endpoint(
        "/proposals/{proposal_id}/actions",
        HTTP_GET,
        get_proposal_actions_js,
        ccf::no_auth_required)
        .set_auto_schema<void, jsgov::Proposal>()
        .set_openapi_summary(
          "Actions contained in a proposed change to the service")
        .set_openapi_deprecated_replaced(
          "5.0.0", "GET /gov/members/proposals/{proposalId}/actions")
        .install();

      auto vote_js = [this](ccf::endpoints::EndpointContext& ctx) {
        std::optional<ccf::MemberCOSESign1AuthnIdentity> cose_auth_id =
          std::nullopt;
        std::optional<MemberId> member_id = std::nullopt;
        if (!authnz_active_member(ctx, member_id, cose_auth_id))
        {
          return;
        }

        ProposalId proposal_id;
        std::string error;
        if (!get_proposal_id_from_path(
              ctx.rpc_ctx->get_request_path_params(), proposal_id, error))
        {
          set_gov_error(
            ctx.rpc_ctx,
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidResourceName,
            std::move(error));
          return;
        }
        if (cose_auth_id.has_value())
        {
          if (!(cose_auth_id->protected_header.gov_msg_proposal_id
                  .has_value() &&
                cose_auth_id->protected_header.gov_msg_proposal_id.value() ==
                  proposal_id))
          {
            set_gov_error(
              ctx.rpc_ctx,
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::InvalidResourceName,
              "Authenticated proposal id does not match URL");
            return;
          }
        }

        auto constitution = ctx.tx.ro(network.constitution)->get();
        if (!constitution.has_value())
        {
          set_gov_error(
            ctx.rpc_ctx,
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            "No constitution is set - proposals cannot be evaluated");
          return;
        }

        auto pi =
          ctx.tx.rw<ccf::jsgov::ProposalInfoMap>(jsgov::Tables::PROPOSALS_INFO);
        auto pi_ = pi->get(proposal_id);
        if (!pi_)
        {
          set_gov_error(
            ctx.rpc_ctx,
            HTTP_STATUS_NOT_FOUND,
            ccf::errors::ProposalNotFound,
            fmt::format("Could not find proposal {}.", proposal_id));
          return;
        }

        if (pi_.value().state != ProposalState::OPEN)
        {
          set_gov_error(
            ctx.rpc_ctx,
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::ProposalNotOpen,
            fmt::format(
              "Proposal {} is currently in state {} - only {} proposals can "
              "receive votes.",
              proposal_id,
              pi_.value().state,
              ProposalState::OPEN));
          return;
        }

        auto pm = ctx.tx.ro<ccf::jsgov::ProposalMap>(jsgov::Tables::PROPOSALS);
        auto p = pm->get(proposal_id);

        if (!p)
        {
          set_gov_error(
            ctx.rpc_ctx,
            HTTP_STATUS_NOT_FOUND,
            ccf::errors::ProposalNotFound,
            fmt::format("Proposal {} does not exist.", proposal_id));
          return;
        }

        if (pi_->ballots.find(member_id.value()) != pi_->ballots.end())
        {
          set_gov_error(
            ctx.rpc_ctx,
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::VoteAlreadyExists,
            "Vote already submitted.");
          return;
        }
        // Validate vote

        auto params = nlohmann::json::parse(
          cose_auth_id.has_value() ? cose_auth_id->content :
                                     ctx.rpc_ctx->get_request_body());

        {
          js::core::Context context(js::TxAccess::GOV_RO);
          const auto options_handle =
            ctx.tx.ro<ccf::JSEngine>(ccf::Tables::JSENGINE);
          context.runtime().set_runtime_options(
            options_handle->get(),
            js::core::RuntimeLimitsPolicy::NO_LOWER_THAN_DEFAULTS);
          auto ballot_func = context.get_exported_function(
            params["ballot"], "vote", "body[\"ballot\"]");
        }

        pi_->ballots[member_id.value()] = params["ballot"];
        pi->put(proposal_id, pi_.value());

        if (cose_auth_id.has_value())
        {
          record_cose_governance_history(
            ctx.tx, member_id.value(), cose_auth_id->envelope);
        }

        auto rv = resolve_proposal(
          ctx.tx, proposal_id, p.value(), constitution.value());
        if (rv.state == ProposalState::FAILED)
        {
          // If the proposal failed to apply, we want to discard the tx and not
          // apply its side-effects to the KV state.
          set_gov_error(
            ctx.rpc_ctx,
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            fmt::format("{}", rv.failure));
          return;
        }
        else
        {
          pi_.value().state = rv.state;
          pi_.value().final_votes = rv.votes;
          pi_.value().vote_failures = rv.vote_failures;
          pi_.value().failure = rv.failure;
          pi->put(proposal_id, pi_.value());
          ctx.rpc_ctx->set_response_header(
            ccf::http::headers::CONTENT_TYPE,
            http::headervalues::contenttype::JSON);
          ctx.rpc_ctx->set_response_body(nlohmann::json(rv).dump());
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          return;
        }
      };
      make_endpoint(
        "/proposals/{proposal_id}/ballots",
        HTTP_POST,
        vote_js,
        member_sig_only_policies("ballot"))
        .set_auto_schema<jsgov::Ballot, jsgov::ProposalInfoSummary>()
        .set_openapi_summary(
          "Submit a ballot for a proposed change to the service")
        .set_openapi_deprecated_replaced(
          "5.0.0",
          "POST /gov/members/proposals/{proposalId}/ballots/{memberId}:submit")
        .install();

      auto get_vote_js =
        [this](endpoints::ReadOnlyEndpointContext& ctx, nlohmann::json&&) {
          std::string error;
          ProposalId proposal_id;
          if (!get_proposal_id_from_path(
                ctx.rpc_ctx->get_request_path_params(), proposal_id, error))
          {
            return make_error(
              HTTP_STATUS_BAD_REQUEST, ccf::errors::InvalidResourceName, error);
          }

          MemberId vote_member_id;
          if (!get_member_id_from_path(
                ctx.rpc_ctx->get_request_path_params(), vote_member_id, error))
          {
            return make_error(
              HTTP_STATUS_BAD_REQUEST, ccf::errors::InvalidResourceName, error);
          }

          auto pi = ctx.tx.ro<ccf::jsgov::ProposalInfoMap>(
            jsgov::Tables::PROPOSALS_INFO);
          auto pi_ = pi->get(proposal_id);
          if (!pi_)
          {
            return make_error(
              HTTP_STATUS_NOT_FOUND,
              ccf::errors::ProposalNotFound,
              fmt::format("Proposal {} does not exist.", proposal_id));
          }

          const auto vote_it = pi_->ballots.find(vote_member_id);
          if (vote_it == pi_->ballots.end())
          {
            return make_error(
              HTTP_STATUS_NOT_FOUND,
              ccf::errors::VoteNotFound,
              fmt::format(
                "Member {} has not voted for proposal {}.",
                vote_member_id,
                proposal_id));
          }

          return make_success(jsgov::Ballot{vote_it->second});
        };
      make_read_only_endpoint(
        "/proposals/{proposal_id}/ballots/{member_id}",
        HTTP_GET,
        json_read_only_adapter(get_vote_js),
        ccf::no_auth_required)
        .set_auto_schema<void, jsgov::Ballot>()
        .set_openapi_summary(
          "Ballot for a given member about a proposed change to the service")
        .set_openapi_deprecated_replaced(
          "5.0.0", "GET /gov/members/proposals/{proposalId}/ballots/{memberId}")
        .install();

      using AllMemberDetails = std::map<ccf::MemberId, FullMemberDetails>;
      auto get_all_members =
        [this](endpoints::ReadOnlyEndpointContext& ctx, nlohmann::json&&) {
          auto members = ctx.tx.ro<ccf::MemberInfo>(ccf::Tables::MEMBER_INFO);
          auto member_certs =
            ctx.tx.ro<ccf::MemberCerts>(ccf::Tables::MEMBER_CERTS);
          auto member_public_encryption_keys =
            ctx.tx.ro<ccf::MemberPublicEncryptionKeys>(
              ccf::Tables::MEMBER_ENCRYPTION_PUBLIC_KEYS);

          AllMemberDetails response;

          members->foreach(
            [&response, member_certs, member_public_encryption_keys](
              const auto& k, const auto& v) {
              FullMemberDetails md;
              md.status = v.status;
              md.member_data = v.member_data;

              const auto cert = member_certs->get(k);
              if (cert.has_value())
              {
                md.cert = cert.value();
              }

              const auto public_encryption_key =
                member_public_encryption_keys->get(k);
              if (public_encryption_key.has_value())
              {
                md.public_encryption_key = public_encryption_key.value();
              }

              response[k] = md;
              return true;
            });

          return make_success(response);
        };
      make_read_only_endpoint(
        "/members",
        HTTP_GET,
        json_read_only_adapter(get_all_members),
        ccf::no_auth_required)
        .set_auto_schema<void, AllMemberDetails>()
        .set_openapi_deprecated_replaced("5.0.0", "GET /gov/service/members")
        .install();

      add_kv_wrapper_endpoints();
    }

    bool request_needs_root(const RpcContext& rpc_ctx) override
    {
      return GovEndpointRegistry::request_needs_root(rpc_ctx) ||
        (rpc_ctx.get_request_verb() == HTTP_POST &&
         rpc_ctx.get_request_path() == "/gov/proposals");
    }
  };

  class MemberRpcFrontend : public RpcFrontend
  {
  protected:
    MemberEndpoints member_endpoints;

  public:
    MemberRpcFrontend(
      NetworkState& network, ccf::AbstractNodeContext& context) :
      RpcFrontend(*network.tables, member_endpoints, context),
      member_endpoints(network, context)
    {}
  };
} // namespace ccf
