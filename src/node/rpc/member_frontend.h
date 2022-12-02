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
#include "ccf/json_handler.h"
#include "ccf/node/quote.h"
#include "ccf/service/tables/gov.h"
#include "ccf/service/tables/jwt.h"
#include "ccf/service/tables/members.h"
#include "ccf/service/tables/nodes.h"
#include "frontend.h"
#include "js/wrap.h"
#include "node/rpc/call_types.h"
#include "node/rpc/gov_effects_interface.h"
#include "node/rpc/node_operation_interface.h"
#include "node/rpc/serialization.h"
#include "node/share_manager.h"
#include "node_interface.h"
#include "service/genesis_gen.h"
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
    crypto::Pem cert;
  };
  DECLARE_JSON_TYPE(KeyIdInfo)
  DECLARE_JSON_REQUIRED_FIELDS(KeyIdInfo, issuer, cert)

  struct FullMemberDetails : public ccf::MemberDetails
  {
    crypto::Pem cert;
    std::optional<crypto::Pem> public_encryption_key;
  };
  DECLARE_JSON_TYPE(FullMemberDetails);
  DECLARE_JSON_REQUIRED_FIELDS(
    FullMemberDetails, status, member_data, cert, public_encryption_key);

  class MemberEndpoints : public CommonEndpointRegistry
  {
  private:
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc99-extensions"

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
      kv::Tx& tx,
      const ProposalId& proposal_id,
      const std::vector<uint8_t>& proposal,
      const std::string& constitution)
    {
      auto pi =
        tx.rw<ccf::jsgov::ProposalInfoMap>(jsgov::Tables::PROPOSALS_INFO);
      auto pi_ = pi->get(proposal_id);

      std::vector<std::pair<MemberId, bool>> votes;
      std::optional<ccf::jsgov::Votes> final_votes = std::nullopt;
      std::optional<ccf::jsgov::VoteFailures> vote_failures = std::nullopt;
      for (const auto& [mid, mb] : pi_->ballots)
      {
        js::Runtime rt(&tx);
        js::Context context(rt, js::TxAccess::GOV_RO);
        rt.add_ccf_classdefs();
        js::TxContext txctx{&tx};
        js::populate_global(
          &txctx,
          nullptr,
          nullptr,
          std::nullopt,
          nullptr,
          nullptr,
          nullptr,
          nullptr,
          nullptr,
          nullptr,
          context);
        auto ballot_func = context.function(
          mb,
          "vote",
          fmt::format(
            "public:ccf.gov.proposal_info[{}].ballots[{}]", proposal_id, mid));

        std::vector<js::JSWrappedValue> argv = {
          context.new_string_len((const char*)proposal.data(), proposal.size()),
          context.new_string_len(
            pi_->proposer_id.data(), pi_->proposer_id.size())};

        auto val = context.call(ballot_func, argv);
        if (!JS_IsException(val))
        {
          votes.emplace_back(mid, JS_ToBool(context, val));
        }
        else
        {
          if (!vote_failures.has_value())
          {
            vote_failures = ccf::jsgov::VoteFailures();
          }

          auto [reason, trace] = js::js_error_message(context);

          if (context.host_time.request_timed_out)
          {
            reason = "Operation took too long to complete.";
          }
          vote_failures.value()[mid] = ccf::jsgov::Failure{reason, trace};
        }
      }

      {
        js::Runtime rt(&tx);
        js::Context js_context(rt, js::TxAccess::GOV_RO);
        rt.add_ccf_classdefs();
        js::TxContext txctx{&tx};
        js::populate_global(
          &txctx,
          nullptr,
          nullptr,
          std::nullopt,
          nullptr,
          nullptr,
          nullptr,
          nullptr,
          nullptr,
          nullptr,
          js_context);
        auto resolve_func = js_context.function(
          constitution, "resolve", "public:ccf.gov.constitution[0]");

        std::vector<js::JSWrappedValue> argv;
        argv.push_back(js_context.new_string_len(
          (const char*)proposal.data(), proposal.size()));

        argv.push_back(js_context.new_string_len(
          pi_->proposer_id.data(), pi_->proposer_id.size()));

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

        std::optional<jsgov::Failure> failure = std::nullopt;
        if (JS_IsException(val))
        {
          pi_.value().state = ProposalState::FAILED;
          auto [reason, trace] = js::js_error_message(js_context);
          if (js_context.host_time.request_timed_out)
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
            js::Runtime rt(&tx);
            js::Context js_context(rt, js::TxAccess::GOV_RW);
            rt.add_ccf_classdefs();
            js::TxContext txctx{&tx};

            auto gov_effects =
              context.get_subsystem<AbstractGovernanceEffects>();
            if (gov_effects == nullptr)
            {
              throw std::logic_error(
                "Unexpected: Could not access GovEffects subsytem");
            }

            js::populate_global(
              &txctx,
              nullptr,
              nullptr,
              std::nullopt,
              nullptr,
              gov_effects.get(),
              nullptr,
              &network,
              nullptr,
              this,
              js_context);
            auto apply_func = js_context.function(
              constitution, "apply", "public:ccf.gov.constitution[0]");

            std::vector<js::JSWrappedValue> argv = {
              js_context.new_string_len(
                (const char*)proposal.data(), proposal.size()),
              js_context.new_string_len(
                proposal_id.c_str(), proposal_id.size())};

            auto val = js_context.call(apply_func, argv);

            if (JS_IsException(val))
            {
              pi_.value().state = ProposalState::FAILED;
              auto [reason, trace] = js::js_error_message(js_context);
              if (js_context.host_time.request_timed_out)
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

#pragma clang diagnostic pop

    bool check_member_active(kv::ReadOnlyTx& tx, const MemberId& id)
    {
      return check_member_status(tx, id, {MemberStatus::ACTIVE});
    }

    bool check_member_status(
      kv::ReadOnlyTx& tx,
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
      kv::Tx& tx, const MemberId& caller_id, const SignedReq& signed_request)
    {
      auto governance_history = tx.rw(network.governance_history);
      governance_history->put(caller_id, {signed_request});
    }

    void record_cose_governance_history(
      kv::Tx& tx,
      const MemberId& caller_id,
      const std::span<const uint8_t>& cose_sign1)
    {
      auto cose_governance_history = tx.rw(network.cose_governance_history);
      cose_governance_history->put(
        caller_id, {cose_sign1.begin(), cose_sign1.end()});
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
      constexpr bool is_map = nonstd::is_specialization<T, kv::TypedMap>::value;
      constexpr bool is_value =
        nonstd::is_specialization<T, kv::TypedValue>::value;

      if constexpr (!(is_map || is_value))
      {
        static_assert(nonstd::dependent_false_v<T>, "Unsupported table type");
      }

      auto getter =
        [&, table](endpoints::ReadOnlyEndpointContext& ctx, nlohmann::json&&) {
          LOG_TRACE_FMT("Called getter for {}", table.get_name());
          auto response_body = nlohmann::json::object();

          auto handle = ctx.tx.template ro(table);
          if constexpr (is_map)
          {
            handle->foreach([&response_body](const auto& k, const auto& v) {
              if constexpr (
                std::is_same_v<typename T::Key, ccf::CodeDigest> ||
                std::is_same_v<typename T::Key, crypto::Sha256Hash>)
              {
                response_body[k.hex_str()] = v;
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

      endpoint.install();
    }

    void add_kv_wrapper_endpoints()
    {
      const auto all_gov_tables = network.get_all_builtin_governance_tables();
      nonstd::tuple_for_each(all_gov_tables, [this](const auto& table) {
        add_kv_wrapper_endpoint(table);
      });

      // add_kv_wrapper_endpoint(network.member_certs);
      // add_kv_wrapper_endpoint(network.member_encryption_public_keys);
      // add_kv_wrapper_endpoint(network.member_info);
      // add_kv_wrapper_endpoint(network.modules);
      // add_kv_wrapper_endpoint(network.modules_quickjs_bytecode);
      // add_kv_wrapper_endpoint(network.modules_quickjs_version);
      // add_kv_wrapper_endpoint(network.js_engine);
      // add_kv_wrapper_endpoint(network.node_code_ids);
      // add_kv_wrapper_endpoint(network.host_data);
      // add_kv_wrapper_endpoint(network.member_acks);
      // add_kv_wrapper_endpoint(network.governance_history);
      // add_kv_wrapper_endpoint(network.cose_governance_history);
      // add_kv_wrapper_endpoint(network.config);
      // add_kv_wrapper_endpoint(network.ca_cert_bundles);
      // add_kv_wrapper_endpoint(network.jwt_issuers);
      // add_kv_wrapper_endpoint(network.jwt_public_signing_keys);
      // add_kv_wrapper_endpoint(network.jwt_public_signing_key_issuer);
      // add_kv_wrapper_endpoint(network.user_certs);
      // add_kv_wrapper_endpoint(network.user_info);
      // add_kv_wrapper_endpoint(network.nodes);
      // add_kv_wrapper_endpoint(network.node_endorsed_certificates);
      // add_kv_wrapper_endpoint(network.acme_certificates);
      // add_kv_wrapper_endpoint(network.constitution);

      // add_kv_wrapper_endpoint(ccf::Service(ccf::Tables::SERVICE));
      // add_kv_wrapper_endpoint(
      //   ccf::jsgov::ProposalInfoMap(jsgov::Tables::PROPOSALS_INFO));
      // add_kv_wrapper_endpoint(
      //   ccf::jsgov::ProposalMap(jsgov::Tables::PROPOSALS));
    }

    NetworkState& network;
    ShareManager& share_manager;

  public:
    MemberEndpoints(
      NetworkState& network_,
      ccfapp::AbstractNodeContext& context_,
      ShareManager& share_manager_) :
      CommonEndpointRegistry(get_actor_prefix(ActorsType::members), context_),
      network(network_),
      share_manager(share_manager_)
    {
      openapi_info.title = "CCF Governance API";
      openapi_info.description =
        "This API is used to submit and query proposals which affect CCF's "
        "public governance tables.";
      openapi_info.document_version = "2.13.0";
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
        const auto* sig_ident =
          ctx.try_get_caller<ccf::MemberSignatureAuthnIdentity>())
      {
        return sig_ident->member_id;
      }
      else if (
        const auto* cert_ident =
          ctx.try_get_caller<ccf::MemberCertAuthnIdentity>())
      {
        return cert_ident->member_id;
      }

      LOG_FATAL_FMT("Request was not authenticated with a member auth policy");
      return std::nullopt;
    }

    bool authnz_active_member(
      ccf::endpoints::EndpointContext& ctx,
      std::optional<MemberId>& member_id,
      std::optional<ccf::MemberSignatureAuthnIdentity>& sig_auth_id,
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
      else if (
        const auto* sig_ident =
          ctx.try_get_caller<ccf::MemberSignatureAuthnIdentity>())
      {
        member_id = sig_ident->member_id;
        sig_auth_id = *sig_ident;
      }
      else
      {
        ctx.rpc_ctx->set_error(
          HTTP_STATUS_FORBIDDEN,
          ccf::errors::AuthorizationFailed,
          "Caller is a not a valid member id");

        return false;
      }

      if (must_be_active && !check_member_active(ctx.tx, member_id.value()))
      {
        ctx.rpc_ctx->set_error(
          HTTP_STATUS_FORBIDDEN,
          ccf::errors::AuthorizationFailed,
          fmt::format("Member {} is not active.", member_id.value()));
        return false;
      }

      return true;
    }

    void init_handlers() override
    {
      CommonEndpointRegistry::init_handlers();

      const AuthnPolicies member_sig_only = {
        member_signature_auth_policy, member_cose_sign1_auth_policy};

      const AuthnPolicies member_cert_or_sig = {
        member_cert_auth_policy,
        member_signature_auth_policy,
        member_cose_sign1_auth_policy};

      //! A member acknowledges state
      auto ack = [this](ccf::endpoints::EndpointContext& ctx) {
        std::optional<ccf::MemberSignatureAuthnIdentity> sig_auth_id =
          std::nullopt;
        std::optional<ccf::MemberCOSESign1AuthnIdentity> cose_auth_id =
          std::nullopt;
        std::optional<MemberId> member_id = std::nullopt;
        if (!authnz_active_member(
              ctx, member_id, sig_auth_id, cose_auth_id, false))
        {
          return;
        }

        if (cose_auth_id.has_value())
        {
          if (!(cose_auth_id->protected_header.gov_msg_type.has_value() &&
                cose_auth_id->protected_header.gov_msg_type.value() == "ack"))
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::InvalidResourceName,
              "Unexpected message type");
            return;
          }
        }

        auto params = nlohmann::json::parse(
          cose_auth_id.has_value() ? cose_auth_id->content :
                                     ctx.rpc_ctx->get_request_body());

        auto mas = ctx.tx.rw(this->network.member_acks);
        const auto ma = mas->get(member_id.value());
        if (!ma)
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_FORBIDDEN,
            ccf::errors::AuthorizationFailed,
            fmt::format(
              "No ACK record exists for caller {}.", member_id.value()));
          return;
        }

        const auto digest = params.get<StateDigest>();
        if (ma->state_digest != digest.state_digest)
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::StateDigestMismatch,
            "Submitted state digest is not valid.");
          return;
        }

        auto sig = ctx.tx.rw(this->network.signatures);
        const auto s = sig->get();
        if (sig_auth_id.has_value())
        {
          if (!s)
          {
            mas->put(
              member_id.value(), MemberAck({}, sig_auth_id->signed_request));
          }
          else
          {
            mas->put(
              member_id.value(),
              MemberAck(s->root, sig_auth_id->signed_request));
          }
        }

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
        GenesisGenerator g(this->network, ctx.tx);
        try
        {
          g.activate_member(member_id.value());
        }
        catch (const std::logic_error& e)
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_FORBIDDEN,
            ccf::errors::AuthorizationFailed,
            fmt::format("Error activating new member: {}", e.what()));
          return;
        }

        auto service_status = g.get_service_status();
        if (!service_status.has_value())
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            "No service currently available.");
          return;
        }

        auto members = ctx.tx.rw(this->network.member_info);
        auto member_info = members->get(member_id.value());
        if (
          service_status.value() == ServiceStatus::OPEN &&
          g.is_recovery_member(member_id.value()))
        {
          // When the service is OPEN and the new active member is a recovery
          // member, all recovery members are allocated new recovery shares
          try
          {
            share_manager.shuffle_recovery_shares(ctx.tx);
          }
          catch (const std::logic_error& e)
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              fmt::format("Error issuing new recovery shares: {}", e.what()));
            return;
          }
        }
        ctx.rpc_ctx->set_response_status(HTTP_STATUS_NO_CONTENT);
        return;
      };
      make_endpoint("/ack", HTTP_POST, ack, member_sig_only)
        .set_auto_schema<StateDigest, void>()
        .install();

      //! A member asks for a fresher state digest
      auto update_state_digest = [this](ccf::endpoints::EndpointContext& ctx) {
        const auto member_id = get_caller_member_id(ctx);
        if (!member_id.has_value())
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_FORBIDDEN,
            ccf::errors::AuthorizationFailed,
            "Caller is a not a valid member id");
          return;
        }

        if (
          const auto* cose_auth_id =
            ctx.try_get_caller<ccf::MemberCOSESign1AuthnIdentity>())
        {
          if (!(cose_auth_id->protected_header.gov_msg_type.has_value() &&
                cose_auth_id->protected_header.gov_msg_type.value() ==
                  "state_digest"))
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::InvalidResourceName,
              "Unexpected message type");
            return;
          }
        }

        auto mas = ctx.tx.rw(this->network.member_acks);
        auto sig = ctx.tx.rw(this->network.signatures);
        auto ma = mas->get(member_id.value());
        if (!ma)
        {
          ctx.rpc_ctx->set_error(
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
          http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);
        ctx.rpc_ctx->set_response_body(j.dump());
        ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        return;
      };
      make_endpoint(
        "/ack/update_state_digest",
        HTTP_POST,
        update_state_digest,
        member_cert_or_sig)
        .set_auto_schema<void, StateDigest>()
        .install();

      auto get_encrypted_recovery_share =
        [this](ccf::endpoints::EndpointContext& ctx) {
          const auto member_id = get_caller_member_id(ctx);
          if (!member_id.has_value())
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_FORBIDDEN,
              ccf::errors::AuthorizationFailed,
              "Member is unknown.");
            return;
          }
          if (!check_member_active(ctx.tx, member_id.value()))
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_FORBIDDEN,
              ccf::errors::AuthorizationFailed,
              "Only active members are given recovery shares.");
            return;
          }

          if (
            const auto* cose_auth_id =
              ctx.try_get_caller<ccf::MemberCOSESign1AuthnIdentity>())
          {
            if (!(cose_auth_id->protected_header.gov_msg_type.has_value() &&
                  cose_auth_id->protected_header.gov_msg_type.value() ==
                    "encrypted_recovery_share"))
            {
              ctx.rpc_ctx->set_error(
                HTTP_STATUS_BAD_REQUEST,
                ccf::errors::InvalidResourceName,
                "Unexpected message type");
              return;
            }
          }

          auto encrypted_share =
            share_manager.get_encrypted_share(ctx.tx, member_id.value());

          if (!encrypted_share.has_value())
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_NOT_FOUND,
              ccf::errors::ResourceNotFound,
              fmt::format(
                "Recovery share not found for member {}.", member_id->value()));
            return;
          }

          auto rec_share = GetRecoveryShare::Out{
            crypto::b64_from_raw(encrypted_share.value())};
          ctx.rpc_ctx->set_response_header(
            http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);
          ctx.rpc_ctx->set_response_body(nlohmann::json(rec_share).dump());
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          return;
        };
      make_endpoint(
        "/recovery_share",
        HTTP_GET,
        get_encrypted_recovery_share,
        member_cert_or_sig)
        .set_auto_schema<GetRecoveryShare>()
        .install();

      auto submit_recovery_share = [this](
                                     ccf::endpoints::EndpointContext& ctx) {
        // Only active members can submit their shares for recovery
        const auto member_id = get_caller_member_id(ctx);
        if (!member_id.has_value())
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_FORBIDDEN,
            ccf::errors::AuthorizationFailed,
            "Member is unknown.");
          return;
        }
        if (!check_member_active(ctx.tx, member_id.value()))
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_FORBIDDEN,
            errors::AuthorizationFailed,
            "Member is not active.");
          return;
        }

        const auto* cose_auth_id =
          ctx.try_get_caller<ccf::MemberCOSESign1AuthnIdentity>();
        if (cose_auth_id)
        {
          if (!(cose_auth_id->protected_header.gov_msg_type.has_value() &&
                cose_auth_id->protected_header.gov_msg_type.value() ==
                  "recovery_share"))
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::InvalidResourceName,
              "Unexpected message type");
            return;
          }
        }

        auto params = nlohmann::json::parse(
          cose_auth_id ? cose_auth_id->content :
                         ctx.rpc_ctx->get_request_body());

        GenesisGenerator g(this->network, ctx.tx);
        if (
          g.get_service_status() != ServiceStatus::WAITING_FOR_RECOVERY_SHARES)
        {
          ctx.rpc_ctx->set_error(
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
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_FORBIDDEN,
            errors::NodeAlreadyRecovering,
            "Node is already recovering private ledger.");
          return;
        }

        std::string share = params["share"];
        auto raw_recovery_share = crypto::raw_from_b64(share);
        OPENSSL_cleanse(const_cast<char*>(share.data()), share.size());

        size_t submitted_shares_count = 0;
        try
        {
          submitted_shares_count = share_manager.submit_recovery_share(
            ctx.tx, member_id.value(), raw_recovery_share);
        }
        catch (const std::exception& e)
        {
          constexpr auto error_msg = "Error submitting recovery shares.";
          LOG_FAIL_FMT(error_msg);
          LOG_DEBUG_FMT("Error: {}", e.what());
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            errors::InternalError,
            error_msg);
          return;
        }
        OPENSSL_cleanse(raw_recovery_share.data(), raw_recovery_share.size());

        if (submitted_shares_count < g.get_recovery_threshold())
        {
          // The number of shares required to re-assemble the secret has not yet
          // been reached
          auto recovery_share = SubmitRecoveryShare::Out{fmt::format(
            "{}/{} recovery shares successfully submitted.",
            submitted_shares_count,
            g.get_recovery_threshold())};
          ctx.rpc_ctx->set_response_header(
            http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);
          ctx.rpc_ctx->set_response_body(nlohmann::json(recovery_share).dump());
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          return;
        }

        LOG_DEBUG_FMT(
          "Reached recovery threshold {}", g.get_recovery_threshold());

        try
        {
          node_operation->initiate_private_recovery(ctx.tx);
        }
        catch (const std::exception& e)
        {
          // Clear the submitted shares if combination fails so that members can
          // start over.
          constexpr auto error_msg = "Failed to initiate private recovery.";
          LOG_FAIL_FMT(error_msg);
          LOG_DEBUG_FMT("Error: {}", e.what());
          share_manager.clear_submitted_recovery_shares(ctx.tx);
          ctx.rpc_ctx->set_apply_writes(true);
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            errors::InternalError,
            error_msg);
          return;
        }

        auto recovery_share = SubmitRecoveryShare::Out{fmt::format(
          "{}/{} recovery shares successfully submitted. End of recovery "
          "procedure initiated.",
          submitted_shares_count,
          g.get_recovery_threshold())};
        ctx.rpc_ctx->set_response_header(
          http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);
        ctx.rpc_ctx->set_response_body(nlohmann::json(recovery_share).dump());
        ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
      };
      make_endpoint(
        "/recovery_share", HTTP_POST, submit_recovery_share, member_cert_or_sig)
        .set_auto_schema<SubmitRecoveryShare>()
        .install();

      using JWTKeyMap = std::map<JwtKeyId, KeyIdInfo>;

      auto get_jwt_keys = [this](auto& ctx, nlohmann::json&& body) {
        auto keys = ctx.tx.ro(network.jwt_public_signing_keys);
        auto keys_to_issuer = ctx.tx.ro(network.jwt_public_signing_key_issuer);

        JWTKeyMap kmap;
        keys->foreach(
          [&kmap, &keys_to_issuer](const auto& kid, const auto& kpem) {
            auto issuer = keys_to_issuer->get(kid);
            if (!issuer.has_value())
            {
              throw std::logic_error(fmt::format("kid {} has no issuer", kid));
            }
            kmap.emplace(
              kid, KeyIdInfo{issuer.value(), crypto::cert_der_to_pem(kpem)});
            return true;
          });

        return make_success(kmap);
      };
      make_endpoint(
        "/jwt_keys/all", HTTP_GET, json_adapter(get_jwt_keys), no_auth_required)
        .set_auto_schema<void, JWTKeyMap>()
        .install();

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc99-extensions"

      auto post_proposals_js = [this](ccf::endpoints::EndpointContext& ctx) {
        std::optional<ccf::MemberSignatureAuthnIdentity> sig_auth_id =
          std::nullopt;
        std::optional<ccf::MemberCOSESign1AuthnIdentity> cose_auth_id =
          std::nullopt;
        std::optional<MemberId> member_id = std::nullopt;
        if (!authnz_active_member(ctx, member_id, sig_auth_id, cose_auth_id))
        {
          return;
        }

        if (!consensus)
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            "No consensus available.");
          return;
        }

        if (cose_auth_id.has_value())
        {
          if (!(cose_auth_id->protected_header.gov_msg_type.has_value() &&
                cose_auth_id->protected_header.gov_msg_type.value() ==
                  "proposal"))
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::InvalidResourceName,
              "Unexpected message type");
            return;
          }
        }

        std::vector<uint8_t> request_digest;
        if (sig_auth_id.has_value())
        {
          request_digest = sig_auth_id->request_digest;
        }
        if (cose_auth_id.has_value())
        {
          // This isn't right, instead the digest of the COSE Sign1
          // TBS should be used here.
          request_digest = crypto::sha256(
            {cose_auth_id->envelope.begin(), cose_auth_id->envelope.end()});
        }

        ProposalId proposal_id;
        if (consensus->type() == ConsensusType::CFT)
        {
          auto root_at_read = ctx.tx.get_root_at_read_version();
          if (!root_at_read.has_value())
          {
            ctx.rpc_ctx->set_error(
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
          const crypto::Sha256Hash proposal_digest(acc);
          proposal_id = proposal_digest.hex_str();
        }
        else
        {
          proposal_id = fmt::format("{:02x}", fmt::join(request_digest, ""));
        }

        auto constitution = ctx.tx.ro(network.constitution)->get();
        if (!constitution.has_value())
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            "No constitution is set - proposals cannot be evaluated");
          return;
        }

        auto validate_script = constitution.value();

        js::Runtime rt(&ctx.tx);
        js::Context context(rt, js::TxAccess::GOV_RO);
        rt.add_ccf_classdefs();
        js::TxContext txctx{&ctx.tx};
        js::populate_global(
          &txctx,
          nullptr,
          nullptr,
          std::nullopt,
          nullptr,
          nullptr,
          nullptr,
          nullptr,
          nullptr,
          nullptr,
          context);

        auto validate_func = context.function(
          validate_script, "validate", "public:ccf.gov.constitution[0]");

        const std::span<const uint8_t> proposal_body =
          cose_auth_id.has_value() ? cose_auth_id->content :
                                     ctx.rpc_ctx->get_request_body();

        auto body = reinterpret_cast<const char*>(proposal_body.data());
        auto body_len = proposal_body.size();

        auto proposal = context.new_string_len(body, body_len);
        auto val = context.call(validate_func, {proposal});

        if (JS_IsException(val))
        {
          auto [reason, trace] = js_error_message(context);
          if (context.host_time.request_timed_out)
          {
            reason = "Operation took too long to complete.";
          }
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            fmt::format(
              "Failed to execute validation: {} {}",
              reason,
              trace.value_or("")));
          return;
        }

        if (!JS_IsObject(val))
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            "Validation failed to return an object");
          return;
        }

        std::string description;
        auto desc = context(JS_GetPropertyStr(context, val, "description"));
        if (JS_IsString(desc))
        {
          description = context.to_str(desc).value_or("");
        }

        auto valid = context(JS_GetPropertyStr(context, val, "valid"));
        if (!JS_ToBool(context, valid))
        {
          ctx.rpc_ctx->set_error(
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
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            "Proposal ID collision.");
          return;
        }
        pm->put(proposal_id, {proposal_body.begin(), proposal_body.end()});

        auto pi =
          ctx.tx.rw<ccf::jsgov::ProposalInfoMap>(jsgov::Tables::PROPOSALS_INFO);
        pi->put(proposal_id, {member_id.value(), ccf::ProposalState::OPEN, {}});

        if (sig_auth_id.has_value())
        {
          record_voting_history(
            ctx.tx, member_id.value(), sig_auth_id->signed_request);
        }
        if (cose_auth_id.has_value())
        {
          record_cose_governance_history(
            ctx.tx, member_id.value(), cose_auth_id->envelope);
        }

        auto rv = resolve_proposal(
          ctx.tx,
          proposal_id,
          {proposal_body.begin(), proposal_body.end()},
          constitution.value());

        if (rv.state == ProposalState::FAILED)
        {
          // If the proposal failed to apply, we want to discard the tx and not
          // apply its side-effects to the KV state.
          ctx.rpc_ctx->set_error(
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
            http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);
          ctx.rpc_ctx->set_response_body(nlohmann::json(rv).dump());
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          return;
        }
      };

      make_endpoint("/proposals", HTTP_POST, post_proposals_js, member_sig_only)
        .set_auto_schema<jsgov::Proposal, jsgov::ProposalInfoSummary>()
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
        .install();

      auto withdraw_js = [this](ccf::endpoints::EndpointContext& ctx) {
        std::optional<ccf::MemberSignatureAuthnIdentity> sig_auth_id =
          std::nullopt;
        std::optional<ccf::MemberCOSESign1AuthnIdentity> cose_auth_id =
          std::nullopt;
        std::optional<MemberId> member_id = std::nullopt;
        if (!authnz_active_member(ctx, member_id, sig_auth_id, cose_auth_id))
        {
          return;
        }

        ProposalId proposal_id;
        std::string error;
        if (!get_proposal_id_from_path(
              ctx.rpc_ctx->get_request_path_params(), proposal_id, error))
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidResourceName,
            std::move(error));
          return;
        }

        if (cose_auth_id.has_value())
        {
          if (!(cose_auth_id->protected_header.gov_msg_type.has_value() &&
                cose_auth_id->protected_header.gov_msg_type.value() ==
                  "withdrawal"))
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::InvalidResourceName,
              "Unexpected message type");
            return;
          }
          if (!(cose_auth_id->protected_header.gov_msg_proposal_id
                  .has_value() &&
                cose_auth_id->protected_header.gov_msg_proposal_id.value() ==
                  proposal_id))
          {
            ctx.rpc_ctx->set_error(
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
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::ProposalNotFound,
            fmt::format("Proposal {} does not exist.", proposal_id));
          return;
        }

        if (member_id.value() != pi_->proposer_id)
        {
          ctx.rpc_ctx->set_error(
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
          ctx.rpc_ctx->set_error(
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
        if (sig_auth_id.has_value())
        {
          record_voting_history(
            ctx.tx, member_id.value(), sig_auth_id->signed_request);
        }
        if (cose_auth_id.has_value())
        {
          record_cose_governance_history(
            ctx.tx, member_id.value(), cose_auth_id->envelope);
        }

        ctx.rpc_ctx->set_response_header(
          http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);
        ctx.rpc_ctx->set_response_body(nlohmann::json(pi_.value()).dump());
        ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
      };

      make_endpoint(
        "/proposals/{proposal_id}/withdraw",
        HTTP_POST,
        withdraw_js,
        member_sig_only)
        .set_auto_schema<void, jsgov::ProposalInfo>()
        .install();

      auto get_proposal_actions_js =
        [this](ccf::endpoints::ReadOnlyEndpointContext& ctx) {
          ProposalId proposal_id;
          std::string error;
          if (!get_proposal_id_from_path(
                ctx.rpc_ctx->get_request_path_params(), proposal_id, error))
          {
            ctx.rpc_ctx->set_error(
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
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_NOT_FOUND,
              ccf::errors::ProposalNotFound,
              fmt::format("Proposal {} does not exist.", proposal_id));
            return;
          }

          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          ctx.rpc_ctx->set_response_header(
            http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);
          ctx.rpc_ctx->set_response_body(std::move(p.value()));
        };

      make_read_only_endpoint(
        "/proposals/{proposal_id}/actions",
        HTTP_GET,
        get_proposal_actions_js,
        ccf::no_auth_required)
        .set_auto_schema<void, jsgov::Proposal>()
        .install();

      auto vote_js = [this](ccf::endpoints::EndpointContext& ctx) {
        std::optional<ccf::MemberSignatureAuthnIdentity> sig_auth_id =
          std::nullopt;
        std::optional<ccf::MemberCOSESign1AuthnIdentity> cose_auth_id =
          std::nullopt;
        std::optional<MemberId> member_id = std::nullopt;
        if (!authnz_active_member(ctx, member_id, sig_auth_id, cose_auth_id))
        {
          return;
        }

        ProposalId proposal_id;
        std::string error;
        if (!get_proposal_id_from_path(
              ctx.rpc_ctx->get_request_path_params(), proposal_id, error))
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InvalidResourceName,
            std::move(error));
          return;
        }
        if (cose_auth_id.has_value())
        {
          if (!(cose_auth_id->protected_header.gov_msg_type.has_value() &&
                cose_auth_id->protected_header.gov_msg_type.value() ==
                  "ballot"))
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::InvalidResourceName,
              "Unexpected message type");
            return;
          }
          if (!(cose_auth_id->protected_header.gov_msg_proposal_id
                  .has_value() &&
                cose_auth_id->protected_header.gov_msg_proposal_id.value() ==
                  proposal_id))
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::InvalidResourceName,
              "Authenticated proposal id does not match URL");
            return;
          }
        }

        auto constitution = ctx.tx.ro(network.constitution)->get();
        if (!constitution.has_value())
        {
          ctx.rpc_ctx->set_error(
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
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_NOT_FOUND,
            ccf::errors::ProposalNotFound,
            fmt::format("Could not find proposal {}.", proposal_id));
          return;
        }

        if (pi_.value().state != ProposalState::OPEN)
        {
          ctx.rpc_ctx->set_error(
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
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_NOT_FOUND,
            ccf::errors::ProposalNotFound,
            fmt::format("Proposal {} does not exist.", proposal_id));
          return;
        }

        if (pi_->ballots.find(member_id.value()) != pi_->ballots.end())
        {
          ctx.rpc_ctx->set_error(
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
          js::Runtime rt(&ctx.tx);
          js::Context context(rt, js::TxAccess::GOV_RO);
          auto ballot_func =
            context.function(params["ballot"], "vote", "body[\"ballot\"]");
        }

        pi_->ballots[member_id.value()] = params["ballot"];
        pi->put(proposal_id, pi_.value());

        if (sig_auth_id.has_value())
        {
          record_voting_history(
            ctx.tx, member_id.value(), sig_auth_id->signed_request);
        }
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
          ctx.rpc_ctx->set_error(
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
            http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);
          ctx.rpc_ctx->set_response_body(nlohmann::json(rv).dump());
          ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          return;
        }
      };
      make_endpoint(
        "/proposals/{proposal_id}/ballots", HTTP_POST, vote_js, member_sig_only)
        .set_auto_schema<jsgov::Ballot, jsgov::ProposalInfoSummary>()
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
        .install();

#pragma clang diagnostic pop

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
        .install();

      add_kv_wrapper_endpoints();
    }
  };

  class MemberRpcFrontend : public RpcFrontend
  {
  protected:
    MemberEndpoints member_endpoints;

  public:
    MemberRpcFrontend(
      NetworkState& network,
      ccfapp::AbstractNodeContext& context,
      ShareManager& share_manager) :
      RpcFrontend(*network.tables, member_endpoints, context),
      member_endpoints(network, context, share_manager)
    {}
  };
} // namespace ccf
