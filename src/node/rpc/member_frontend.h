// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "ccf/common_auth_policies.h"
#include "ccf/common_endpoint_registry.h"
#include "ccf/json_handler.h"
#include "crypto/key_pair.h"
#include "ds/nonstd.h"
#include "frontend.h"
#include "js/wrap.h"
#include "node/config_id.h"
#include "node/genesis_gen.h"
#include "node/gov.h"
#include "node/jwt.h"
#include "node/members.h"
#include "node/nodes.h"
#include "node/quote.h"
#include "node/secret_share.h"
#include "node/share_manager.h"
#include "node_interface.h"
#include "tls/base64.h"

#include <charconv>
#include <exception>
#include <initializer_list>
#include <map>
#include <memory>
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

  struct SetJwtPublicSigningKeys
  {
    std::string issuer;
    JsonWebKeySet jwks;
  };
  DECLARE_JSON_TYPE(SetJwtPublicSigningKeys)
  DECLARE_JSON_REQUIRED_FIELDS(SetJwtPublicSigningKeys, issuer, jwks)

  class MemberEndpoints : public CommonEndpointRegistry
  {
  private:
    bool set_js_app(kv::Tx& tx, const JsBundle& bundle)
    {
      std::string module_prefix = "/";
      remove_modules(tx, module_prefix);
      set_modules(tx, module_prefix, bundle.modules);

      remove_endpoints(tx);

      auto endpoints =
        tx.rw<ccf::endpoints::EndpointsMap>(ccf::Tables::ENDPOINTS);

      for (auto& [url, endpoint] : bundle.metadata.endpoints)
      {
        for (auto& [method, info] : endpoint)
        {
          const std::string& js_module = info.js_module;
          if (std::none_of(
                bundle.modules.cbegin(),
                bundle.modules.cend(),
                [&js_module](const SetModule& item) {
                  return item.name == js_module;
                }))
          {
            LOG_FAIL_FMT(
              "{} {}: module '{}' not found in bundle",
              method,
              url,
              info.js_module);
            return false;
          }
          auto info_ = info;
          info_.js_module = module_prefix + info_.js_module;
          auto verb = nlohmann::json(method).get<RESTVerb>();
          endpoints->put(ccf::endpoints::EndpointKey{url, verb}, info_);
        }
      }

      return true;
    }

    bool remove_js_app(kv::Tx& tx)
    {
      remove_modules(tx, "/");
      remove_endpoints(tx);
      return true;
    }

    void set_modules(
      kv::Tx& tx, std::string prefix, const std::vector<SetModule>& modules)
    {
      for (auto& set_module_ : modules)
      {
        std::string full_name = prefix + set_module_.name;
        if (!set_module(tx, full_name, set_module_.module))
        {
          throw std::logic_error(
            fmt::format("Unexpected error while setting module {}", full_name));
        }
      }
    }

    bool set_module(kv::Tx& tx, std::string name, Module module)
    {
      if (name.empty() || name[0] != '/')
      {
        LOG_FAIL_FMT("module names must start with /");
        return false;
      }
      auto tx_modules = tx.rw(network.modules);
      tx_modules->put(name, module);
      return true;
    }

    void remove_modules(kv::Tx& tx, std::string prefix)
    {
      auto tx_modules = tx.rw(network.modules);
      tx_modules->foreach(
        [&tx_modules, &prefix](const std::string& name, const Module&) {
          if (nonstd::starts_with(name, prefix))
          {
            if (!tx_modules->remove(name))
            {
              throw std::logic_error(
                fmt::format("Unexpected error while removing module {}", name));
            }
          }
          return true;
        });
    }

    bool remove_module(kv::Tx& tx, std::string name)
    {
      auto tx_modules = tx.rw(network.modules);
      return tx_modules->remove(name);
    }

    void remove_endpoints(kv::Tx& tx)
    {
      auto endpoints =
        tx.rw<ccf::endpoints::EndpointsMap>(ccf::Tables::ENDPOINTS);
      endpoints->clear();
    }

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc99-extensions"

    void remove_all_other_non_open_proposals(
      kv::Tx& tx, const ProposalId& proposal_id)
    {
      auto p = tx.rw<ccf::jsgov::ProposalMap>(Tables::PROPOSALS);
      auto pi = tx.rw<ccf::jsgov::ProposalInfoMap>(Tables::PROPOSALS_INFO);
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
      auto pi = tx.rw<ccf::jsgov::ProposalInfoMap>(Tables::PROPOSALS_INFO);
      auto pi_ = pi->get(proposal_id);

      std::vector<std::pair<MemberId, bool>> votes;
      std::optional<ccf::jsgov::Votes> final_votes = std::nullopt;
      std::optional<ccf::jsgov::VoteFailures> vote_failures = std::nullopt;
      for (const auto& [mid, mb] : pi_->ballots)
      {
        js::Runtime rt;
        js::Context context(rt);
        rt.add_ccf_classdefs();
        js::TxContext txctx{&tx, js::TxAccess::GOV_RO};
        js::populate_global_console(context);
        js::populate_global_ccf(
          &txctx,
          nullptr,
          std::nullopt,
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

        JSValue argv[2];
        auto prop = JS_NewStringLen(
          context, (const char*)proposal.data(), proposal.size());
        argv[0] = prop;
        auto pid = JS_NewStringLen(
          context, pi_->proposer_id.data(), pi_->proposer_id.size());
        argv[1] = pid;

        auto val =
          context(JS_Call(context, ballot_func, JS_UNDEFINED, 2, argv));
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
          vote_failures.value()[mid] = ccf::jsgov::Failure{reason, trace};
        }
        JS_FreeValue(context, ballot_func);
        JS_FreeValue(context, prop);
        JS_FreeValue(context, pid);
      }

      {
        js::Runtime rt;
        js::Context js_context(rt);
        js::populate_global_console(js_context);
        rt.add_ccf_classdefs();
        js::TxContext txctx{&tx, js::TxAccess::GOV_RO};
        js::populate_global_ccf(
          &txctx,
          nullptr,
          std::nullopt,
          nullptr,
          nullptr,
          nullptr,
          nullptr,
          js_context);
        auto resolve_func = js_context.function(
          constitution, "resolve", "public:ccf.gov.constitution[0]");
        JSValue argv[3];
        auto prop = JS_NewStringLen(
          js_context, (const char*)proposal.data(), proposal.size());
        argv[0] = prop;

        auto prop_id = JS_NewStringLen(
          js_context, pi_->proposer_id.data(), pi_->proposer_id.size());
        argv[1] = prop_id;

        auto vs = JS_NewArray(js_context);
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
        argv[2] = vs;

        auto val =
          js_context(JS_Call(js_context, resolve_func, JS_UNDEFINED, 3, argv));

        JS_FreeValue(js_context, resolve_func);
        JS_FreeValue(js_context, prop);
        JS_FreeValue(js_context, prop_id);
        JS_FreeValue(js_context, vs);

        std::optional<jsgov::Failure> failure = std::nullopt;
        if (JS_IsException(val))
        {
          pi_.value().state = ProposalState::FAILED;
          auto [reason, trace] = js::js_error_message(js_context);
          failure = ccf::jsgov::Failure{
            fmt::format("Failed to resolve(): {}", reason), trace};
        }
        else if (JS_IsString(val))
        {
          auto s = JS_ToCString(js_context, val);
          std::string status(s);
          JS_FreeCString(js_context, s);
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
            js::Runtime rt;
            js::Context js_context(rt);
            js::populate_global_console(js_context);
            rt.add_ccf_classdefs();
            js::TxContext txctx{&tx, js::TxAccess::GOV_RW};
            js::populate_global_ccf(
              &txctx,
              nullptr,
              std::nullopt,
              nullptr,
              &context.get_node_state(),
              nullptr,
              &network,
              js_context);
            auto apply_func = js_context.function(
              constitution, "apply", "public:ccf.gov.constitution[0]");

            JSValue argv[2];
            auto prop = JS_NewStringLen(
              js_context, (const char*)proposal.data(), proposal.size());
            argv[0] = prop;

            auto prop_id = JS_NewStringLen(
              js_context, proposal_id.c_str(), proposal_id.size());
            argv[1] = prop_id;

            auto val = js_context(
              JS_Call(js_context, apply_func, JS_UNDEFINED, 2, argv));

            JS_FreeValue(js_context, apply_func);
            JS_FreeValue(js_context, prop);
            JS_FreeValue(js_context, prop_id);

            if (JS_IsException(val))
            {
              pi_.value().state = ProposalState::FAILED;
              auto [reason, trace] = js::js_error_message(js_context);
              failure = ccf::jsgov::Failure{
                fmt::format("Failed to apply(): {}", reason), trace};
            }
          }
        }

        return jsgov::ProposalInfoSummary{proposal_id,
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

    bool get_proposal_id_from_path(
      const enclave::PathParams& params,
      ProposalId& proposal_id,
      std::string& error)
    {
      return get_path_param(params, "proposal_id", proposal_id, error);
    }

    bool get_member_id_from_path(
      const enclave::PathParams& params,
      MemberId& member_id,
      std::string& error)
    {
      return get_path_param(params, "member_id", member_id.value(), error);
    }

    NetworkState& network;
    ShareManager& share_manager;

  public:
    MemberEndpoints(
      NetworkState& network,
      ccfapp::AbstractNodeContext& context_,
      ShareManager& share_manager) :
      CommonEndpointRegistry(get_actor_prefix(ActorsType::members), context_),
      network(network),
      share_manager(share_manager)
    {
      openapi_info.title = "CCF Governance API";
      openapi_info.description =
        "This API is used to submit and query proposals which affect CCF's "
        "public governance tables.";
      openapi_info.document_version = "1.1.0";
    }

    static std::optional<MemberId> get_caller_member_id(
      endpoints::CommandEndpointContext& ctx)
    {
      if (
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

    void init_handlers() override
    {
      CommonEndpointRegistry::init_handlers();

      const AuthnPolicies member_sig_only = {member_signature_auth_policy};

      const AuthnPolicies member_cert_or_sig = {member_cert_auth_policy,
                                                member_signature_auth_policy};

      //! A member acknowledges state
      auto ack = [this](auto& ctx, nlohmann::json&& params) {
        const auto& caller_identity =
          ctx.template get_caller<ccf::MemberSignatureAuthnIdentity>();
        const auto& signed_request = caller_identity.signed_request;

        auto mas = ctx.tx.rw(this->network.member_acks);
        const auto ma = mas->get(caller_identity.member_id);
        if (!ma)
        {
          return make_error(
            HTTP_STATUS_FORBIDDEN,
            ccf::errors::AuthorizationFailed,
            fmt::format(
              "No ACK record exists for caller {}.",
              caller_identity.member_id));
        }

        const auto digest = params.get<StateDigest>();
        if (ma->state_digest != digest.state_digest)
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::StateDigestMismatch,
            "Submitted state digest is not valid.");
        }

        auto sig = ctx.tx.rw(this->network.signatures);
        const auto s = sig->get();
        if (!s)
        {
          mas->put(caller_identity.member_id, MemberAck({}, signed_request));
        }
        else
        {
          mas->put(
            caller_identity.member_id, MemberAck(s->root, signed_request));
        }

        // update member status to ACTIVE
        GenesisGenerator g(this->network, ctx.tx);
        try
        {
          g.activate_member(caller_identity.member_id);
        }
        catch (const std::logic_error& e)
        {
          return make_error(
            HTTP_STATUS_FORBIDDEN,
            ccf::errors::AuthorizationFailed,
            fmt::format("Error activating new member: {}", e.what()));
        }

        auto service_status = g.get_service_status();
        if (!service_status.has_value())
        {
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            "No service currently available.");
        }

        auto members = ctx.tx.rw(this->network.member_info);
        auto member_info = members->get(caller_identity.member_id);
        if (
          service_status.value() == ServiceStatus::OPEN &&
          g.is_recovery_member(caller_identity.member_id))
        {
          // When the service is OPEN and the new active member is a recovery
          // member, all recovery members are allocated new recovery shares
          try
          {
            share_manager.shuffle_recovery_shares(ctx.tx);
          }
          catch (const std::logic_error& e)
          {
            return make_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              fmt::format("Error issuing new recovery shares: {}", e.what()));
          }
        }
        return make_success();
      };
      make_endpoint("ack", HTTP_POST, json_adapter(ack), member_sig_only)
        .set_auto_schema<StateDigest, void>()
        .install();

      //! A member asks for a fresher state digest
      auto update_state_digest = [this](auto& ctx, nlohmann::json&&) {
        const auto member_id = get_caller_member_id(ctx);
        if (!member_id.has_value())
        {
          return make_error(
            HTTP_STATUS_FORBIDDEN,
            ccf::errors::AuthorizationFailed,
            "Caller is a not a valid member id");
        }

        auto mas = ctx.tx.rw(this->network.member_acks);
        auto sig = ctx.tx.rw(this->network.signatures);
        auto ma = mas->get(member_id.value());
        if (!ma)
        {
          return make_error(
            HTTP_STATUS_FORBIDDEN,
            ccf::errors::AuthorizationFailed,
            fmt::format(
              "No ACK record exists for caller {}.", member_id.value()));
        }

        auto s = sig->get();
        if (s)
        {
          ma->state_digest = s->root.hex_str();
          mas->put(member_id.value(), ma.value());
        }
        nlohmann::json j;
        j["state_digest"] = ma->state_digest;

        return make_success(j);
      };
      make_endpoint(
        "ack/update_state_digest",
        HTTP_POST,
        json_adapter(update_state_digest),
        member_cert_or_sig)
        .set_auto_schema<void, StateDigest>()
        .install();

      auto get_encrypted_recovery_share = [this](auto& ctx, nlohmann::json&&) {
        const auto member_id = get_caller_member_id(ctx);
        if (!member_id.has_value())
        {
          return make_error(
            HTTP_STATUS_FORBIDDEN,
            ccf::errors::AuthorizationFailed,
            "Member is unknown.");
        }
        if (!check_member_active(ctx.tx, member_id.value()))
        {
          return make_error(
            HTTP_STATUS_FORBIDDEN,
            ccf::errors::AuthorizationFailed,
            "Only active members are given recovery shares.");
        }

        auto encrypted_share =
          share_manager.get_encrypted_share(ctx.tx, member_id.value());

        if (!encrypted_share.has_value())
        {
          return make_error(
            HTTP_STATUS_NOT_FOUND,
            ccf::errors::ResourceNotFound,
            fmt::format(
              "Recovery share not found for member {}.", member_id->value()));
        }

        return make_success(
          GetRecoveryShare::Out{tls::b64_from_raw(encrypted_share.value())});
      };
      make_endpoint(
        "recovery_share",
        HTTP_GET,
        json_adapter(get_encrypted_recovery_share),
        member_cert_or_sig)
        .set_auto_schema<GetRecoveryShare>()
        .install();

      auto submit_recovery_share = [this](auto& ctx, nlohmann::json&& params) {
        // Only active members can submit their shares for recovery
        const auto member_id = get_caller_member_id(ctx);
        if (!member_id.has_value())
        {
          return make_error(
            HTTP_STATUS_FORBIDDEN,
            ccf::errors::AuthorizationFailed,
            "Member is unknown.");
        }
        if (!check_member_active(ctx.tx, member_id.value()))
        {
          return make_error(
            HTTP_STATUS_FORBIDDEN,
            errors::AuthorizationFailed,
            "Member is not active");
        }

        GenesisGenerator g(this->network, ctx.tx);
        if (
          g.get_service_status() != ServiceStatus::WAITING_FOR_RECOVERY_SHARES)
        {
          return make_error(
            HTTP_STATUS_FORBIDDEN,
            errors::ServiceNotWaitingForRecoveryShares,
            "Service is not waiting for recovery shares");
        }

        if (context.get_node_state().is_reading_private_ledger())
        {
          return make_error(
            HTTP_STATUS_FORBIDDEN,
            errors::NodeAlreadyRecovering,
            "Node is already recovering private ledger");
        }

        const auto in = params.get<SubmitRecoveryShare::In>();
        auto raw_recovery_share = tls::raw_from_b64(in.share);

        size_t submitted_shares_count = 0;
        try
        {
          submitted_shares_count = share_manager.submit_recovery_share(
            ctx.tx, member_id.value(), raw_recovery_share);
        }
        catch (const std::exception& e)
        {
          constexpr auto error_msg = "Error submitting recovery shares";
          LOG_FAIL_FMT(error_msg);
          LOG_DEBUG_FMT("Error: {}", e.what());
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            errors::InternalError,
            error_msg);
        }

        if (submitted_shares_count < g.get_recovery_threshold())
        {
          // The number of shares required to re-assemble the secret has not yet
          // been reached
          return make_success(SubmitRecoveryShare::Out{fmt::format(
            "{}/{} recovery shares successfully submitted.",
            submitted_shares_count,
            g.get_recovery_threshold())});
        }

        LOG_DEBUG_FMT(
          "Reached recovery threshold {}", g.get_recovery_threshold());

        try
        {
          context.get_node_state().initiate_private_recovery(ctx.tx);
        }
        catch (const std::exception& e)
        {
          // Clear the submitted shares if combination fails so that members can
          // start over.
          constexpr auto error_msg = "Failed to initiate private recovery";
          LOG_FAIL_FMT(error_msg);
          LOG_DEBUG_FMT("Error: {}", e.what());
          share_manager.clear_submitted_recovery_shares(ctx.tx);
          ctx.rpc_ctx->set_apply_writes(true);
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            errors::InternalError,
            error_msg);
        }

        share_manager.clear_submitted_recovery_shares(ctx.tx);

        return make_success(SubmitRecoveryShare::Out{fmt::format(
          "{}/{} recovery shares successfully submitted. End of recovery "
          "procedure initiated.",
          submitted_shares_count,
          g.get_recovery_threshold())});
      };
      make_endpoint(
        "recovery_share",
        HTTP_POST,
        json_adapter(submit_recovery_share),
        member_cert_or_sig)
        .set_auto_schema<SubmitRecoveryShare>()
        .install();

      auto create = [this](auto& ctx, nlohmann::json&& params) {
        LOG_DEBUG_FMT("Processing create RPC");
        const auto in = params.get<CreateNetworkNodeToNode::In>();

        GenesisGenerator g(this->network, ctx.tx);

        // This endpoint can only be called once, directly from the starting
        // node for the genesis transaction to initialise the service
        if (g.is_service_created())
        {
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            "Service is already created.");
        }

        g.init_values();
        g.create_service(in.network_cert);

        for (const auto& info : in.members_info)
        {
          g.add_member(info);
        }

        // Note that it is acceptable to start a network without any member
        // having a recovery share. The service will check that at least one
        // recovery member is added before the service is opened.
        g.init_configuration(in.configuration);

        g.add_node(
          in.node_id,
          {in.node_info_network,
           in.node_cert,
           {in.quote_info},
           in.public_encryption_key,
           NodeStatus::TRUSTED,
           get_fresh_config_id(network, ctx.tx)});

#ifdef GET_QUOTE
        g.trust_node_code_id(in.code_digest);
#endif

        g.set_constitution(in.constitution);

        LOG_INFO_FMT("Created service");
        return make_success(true);
      };
      make_endpoint("create", HTTP_POST, json_adapter(create), no_auth_required)
        .set_openapi_hidden(true)
        .install();

      // Only called from node. See node_state.h.
      auto refresh_jwt_keys = [this](auto& ctx, nlohmann::json&& body) {
        // All errors are server errors since the client is the server.

        if (!consensus)
        {
          LOG_FAIL_FMT("JWT key auto-refresh: no consensus available");
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            "No consensus available.");
        }

        auto primary_id = consensus->primary();
        if (!primary_id.has_value())
        {
          LOG_FAIL_FMT("JWT key auto-refresh: primary unknown");
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            "Primary is unknown");
        }

        const auto& cert_auth_ident =
          ctx.template get_caller<ccf::NodeCertAuthnIdentity>();
        if (primary_id.value() != cert_auth_ident.node_id)
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
        catch (const JsonParseError& e)
        {
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            "Unable to parse body.");
        }

        auto issuers = ctx.tx.rw(this->network.jwt_issuers);
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
        "jwt_keys/refresh",
        HTTP_POST,
        json_adapter(refresh_jwt_keys),
        {std::make_shared<NodeCertAuthnPolicy>()})
        .set_openapi_hidden(true)
        .install();

      using JWTKeyMap = std::map<JwtKeyId, crypto::Pem>;

      auto get_jwt_keys = [this](auto& ctx, nlohmann::json&& body) {
        auto keys = ctx.tx.template ro<JwtPublicSigningKeys>(
          ccf::Tables::JWT_PUBLIC_SIGNING_KEYS);
        JWTKeyMap kmap;
        keys->foreach([&kmap](const auto& kid, const auto& kpem) {
          kmap[kid] = crypto::cert_der_to_pem(kpem);
          return false;
        });

        return make_success(kmap);
      };
      make_endpoint(
        "jwt_keys/all", HTTP_GET, json_adapter(get_jwt_keys), no_auth_required)
        .set_auto_schema<void, JWTKeyMap>()
        .install();

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc99-extensions"

      auto post_proposals_js = [this](ccf::endpoints::EndpointContext& ctx) {
        const auto& caller_identity =
          ctx.get_caller<ccf::MemberSignatureAuthnIdentity>();
        if (!check_member_active(ctx.tx, caller_identity.member_id))
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_FORBIDDEN,
            ccf::errors::AuthorizationFailed,
            "Member is not active.");
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
          acc.insert(
            acc.end(),
            caller_identity.request_digest.begin(),
            caller_identity.request_digest.end());
          const crypto::Sha256Hash proposal_digest(acc);
          proposal_id = proposal_digest.hex_str();
        }
        else
        {
          proposal_id = fmt::format(
            "{:02x}", fmt::join(caller_identity.request_digest, ""));
        }

        auto constitution = ctx.tx.ro(network.constitution)->get(0);
        if (!constitution.has_value())
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            "No constitution is set - proposals cannot be evaluated");
          return;
        }

        auto validate_script = constitution.value();

        js::Runtime rt;
        js::Context context(rt);
        rt.add_ccf_classdefs();
        js::populate_global_ccf(
          nullptr,
          nullptr,
          std::nullopt,
          nullptr,
          nullptr,
          nullptr,
          nullptr,
          context);

        auto validate_func = context.function(
          validate_script, "validate", "public:ccf.gov.constitution[0]");

        auto body =
          reinterpret_cast<const char*>(ctx.rpc_ctx->get_request_body().data());
        auto body_len = ctx.rpc_ctx->get_request_body().size();

        auto proposal = JS_NewStringLen(context, body, body_len);
        JSValueConst* argv = (JSValueConst*)&proposal;

        auto val =
          context(JS_Call(context, validate_func, JS_UNDEFINED, 1, argv));

        JS_FreeValue(context, proposal);
        JS_FreeValue(context, validate_func);

        if (JS_IsException(val))
        {
          js::js_dump_error(context);
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            "Failed to execute validation");
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
          auto cstr = JS_ToCString(context, desc);
          description = std::string(cstr);
          JS_FreeCString(context, cstr);
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

        auto pm = ctx.tx.rw<ccf::jsgov::ProposalMap>(Tables::PROPOSALS);
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
        pm->put(proposal_id, ctx.rpc_ctx->get_request_body());

        auto pi =
          ctx.tx.rw<ccf::jsgov::ProposalInfoMap>(Tables::PROPOSALS_INFO);
        pi->put(
          proposal_id,
          {caller_identity.member_id, ccf::ProposalState::OPEN, {}});

        record_voting_history(
          ctx.tx, caller_identity.member_id, caller_identity.signed_request);

        auto rv = resolve_proposal(
          ctx.tx,
          proposal_id,
          ctx.rpc_ctx->get_request_body(),
          constitution.value());
        pi->put(
          proposal_id,
          {caller_identity.member_id,
           rv.state,
           {},
           {},
           std::nullopt,
           rv.failure});

        ctx.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        ctx.rpc_ctx->set_response_header(
          http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);
        ctx.rpc_ctx->set_response_body(nlohmann::json(rv).dump());
      };

      make_endpoint("proposals", HTTP_POST, post_proposals_js, member_sig_only)
        .set_auto_schema<jsgov::Proposal, jsgov::ProposalInfoSummary>()
        .install();

      auto get_proposal_js =
        [this](endpoints::ReadOnlyEndpointContext& ctx, nlohmann::json&&) {
          const auto member_id = get_caller_member_id(ctx);
          if (!member_id.has_value())
          {
            return make_error(
              HTTP_STATUS_FORBIDDEN,
              ccf::errors::AuthorizationFailed,
              "Member is unknown.");
          }
          if (!check_member_active(ctx.tx, member_id.value()))
          {
            return make_error(
              HTTP_STATUS_FORBIDDEN,
              ccf::errors::AuthorizationFailed,
              "Member is not active.");
          }

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

          auto pm = ctx.tx.ro<ccf::jsgov::ProposalMap>(Tables::PROPOSALS);
          auto p = pm->get(proposal_id);

          if (!p)
          {
            return make_error(
              HTTP_STATUS_NOT_FOUND,
              ccf::errors::ProposalNotFound,
              fmt::format("Proposal {} does not exist.", proposal_id));
          }

          auto pi =
            ctx.tx.ro<ccf::jsgov::ProposalInfoMap>(Tables::PROPOSALS_INFO);
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
        "proposals/{proposal_id}",
        HTTP_GET,
        json_read_only_adapter(get_proposal_js),
        member_cert_or_sig)
        .set_auto_schema<void, jsgov::ProposalInfo>()
        .install();

      auto withdraw_js = [this](
                           endpoints::EndpointContext& ctx, nlohmann::json&&) {
        const auto& caller_identity =
          ctx.template get_caller<ccf::MemberSignatureAuthnIdentity>();
        if (!check_member_active(ctx.tx, caller_identity.member_id))
        {
          return make_error(
            HTTP_STATUS_FORBIDDEN,
            ccf::errors::AuthorizationFailed,
            "Member is not active.");
        }

        ProposalId proposal_id;
        std::string error;
        if (!get_proposal_id_from_path(
              ctx.rpc_ctx->get_request_path_params(), proposal_id, error))
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST, ccf::errors::InvalidResourceName, error);
        }

        auto pi =
          ctx.tx.rw<ccf::jsgov::ProposalInfoMap>(Tables::PROPOSALS_INFO);
        auto pi_ = pi->get(proposal_id);

        if (!pi_)
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::ProposalNotFound,
            fmt::format("Proposal {} does not exist.", proposal_id));
        }

        if (caller_identity.member_id != pi_->proposer_id)
        {
          return make_error(
            HTTP_STATUS_FORBIDDEN,
            ccf::errors::AuthorizationFailed,
            fmt::format(
              "Proposal {} can only be withdrawn by proposer {}, not caller "
              "{}.",
              proposal_id,
              pi_->proposer_id,
              caller_identity.member_id));
        }

        if (pi_->state != ProposalState::OPEN)
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::ProposalNotOpen,
            fmt::format(
              "Proposal {} is currently in state {} - only {} proposals can be "
              "withdrawn.",
              proposal_id,
              pi_->state,
              ProposalState::OPEN));
        }

        pi_->state = ProposalState::WITHDRAWN;
        pi->put(proposal_id, pi_.value());

        remove_all_other_non_open_proposals(ctx.tx, proposal_id);
        record_voting_history(
          ctx.tx, caller_identity.member_id, caller_identity.signed_request);

        return make_success(pi_.value());
      };

      make_endpoint(
        "proposals/{proposal_id}/withdraw",
        HTTP_POST,
        json_adapter(withdraw_js),
        member_sig_only)
        .set_auto_schema<void, jsgov::ProposalInfo>()
        .install();

      auto get_proposal_actions_js =
        [this](ccf::endpoints::ReadOnlyEndpointContext& ctx) {
          const auto& caller_identity =
            ctx.get_caller<ccf::MemberSignatureAuthnIdentity>();
          if (!check_member_active(ctx.tx, caller_identity.member_id))
          {
            ctx.rpc_ctx->set_error(
              HTTP_STATUS_FORBIDDEN,
              ccf::errors::AuthorizationFailed,
              "Member is not active.");
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

          auto pm = ctx.tx.ro<ccf::jsgov::ProposalMap>(Tables::PROPOSALS);
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
        "proposals/{proposal_id}/actions",
        HTTP_GET,
        get_proposal_actions_js,
        member_cert_or_sig)
        .set_auto_schema<void, jsgov::Proposal>()
        .install();

      auto vote_js = [this](
                       endpoints::EndpointContext& ctx,
                       nlohmann::json&& params) {
        const auto& caller_identity =
          ctx.get_caller<ccf::MemberSignatureAuthnIdentity>();
        if (!check_member_active(ctx.tx, caller_identity.member_id))
        {
          return make_error(
            HTTP_STATUS_FORBIDDEN,
            ccf::errors::AuthorizationFailed,
            "Member is not active.");
        }

        ProposalId proposal_id;
        std::string error;
        if (!get_proposal_id_from_path(
              ctx.rpc_ctx->get_request_path_params(), proposal_id, error))
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST, ccf::errors::InvalidResourceName, error);
        }

        auto constitution = ctx.tx.ro(network.constitution)->get(0);
        if (!constitution.has_value())
        {
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            "No constitution is set - proposals cannot be evaluated");
        }

        auto pi =
          ctx.tx.rw<ccf::jsgov::ProposalInfoMap>(Tables::PROPOSALS_INFO);
        auto pi_ = pi->get(proposal_id);
        if (!pi_)
        {
          return make_error(
            HTTP_STATUS_NOT_FOUND,
            ccf::errors::ProposalNotFound,
            fmt::format("Could not find proposal {}.", proposal_id));
        }

        if (pi_.value().state != ProposalState::OPEN)
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::ProposalNotOpen,
            fmt::format(
              "Proposal {} is currently in state {} - only {} proposals can "
              "receive votes.",
              proposal_id,
              pi_.value().state,
              ProposalState::OPEN));
        }

        auto pm = ctx.tx.ro<ccf::jsgov::ProposalMap>(Tables::PROPOSALS);
        auto p = pm->get(proposal_id);

        if (!p)
        {
          return make_error(
            HTTP_STATUS_NOT_FOUND,
            ccf::errors::ProposalNotFound,
            fmt::format("Proposal {} does not exist.", proposal_id));
        }

        if (pi_->ballots.find(caller_identity.member_id) != pi_->ballots.end())
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::VoteAlreadyExists,
            "Vote already submitted.");
        }
        // Validate vote

        {
          js::Runtime rt;
          js::Context context(rt);
          auto ballot_func =
            context.function(params["ballot"], "vote", "body[\"ballot\"]");
          JS_FreeValue(context, ballot_func);
        }

        pi_->ballots[caller_identity.member_id] = params["ballot"];
        pi->put(proposal_id, pi_.value());

        // Do we still need to do this?
        record_voting_history(
          ctx.tx, caller_identity.member_id, caller_identity.signed_request);

        auto rv = resolve_proposal(
          ctx.tx, proposal_id, p.value(), constitution.value());
        pi_.value().state = rv.state;
        pi_.value().final_votes = rv.votes;
        pi_.value().vote_failures = rv.vote_failures;
        pi_.value().failure = rv.failure;
        pi->put(proposal_id, pi_.value());
        return make_success(rv);
      };
      make_endpoint(
        "proposals/{proposal_id}/ballots",
        HTTP_POST,
        json_adapter(vote_js),
        member_sig_only)
        .set_auto_schema<jsgov::Ballot, jsgov::ProposalInfoSummary>()
        .install();

      auto get_vote_js =
        [this](endpoints::ReadOnlyEndpointContext& ctx, nlohmann::json&&) {
          const auto member_id = get_caller_member_id(ctx);
          if (!member_id.has_value())
          {
            return make_error(
              HTTP_STATUS_FORBIDDEN,
              ccf::errors::AuthorizationFailed,
              "Member is unknown.");
          }
          if (!check_member_active(ctx.tx, member_id.value()))
          {
            return make_error(
              HTTP_STATUS_FORBIDDEN,
              ccf::errors::AuthorizationFailed,
              "Member is not active.");
          }

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

          auto pi =
            ctx.tx.ro<ccf::jsgov::ProposalInfoMap>(Tables::PROPOSALS_INFO);
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
        "proposals/{proposal_id}/ballots/{member_id}",
        HTTP_GET,
        json_read_only_adapter(get_vote_js),
        member_cert_or_sig)
        .set_auto_schema<void, jsgov::Ballot>()
        .install();

#pragma clang diagnostic pop
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
      RpcFrontend(*network.tables, member_endpoints),
      member_endpoints(network, context, share_manager)
    {}
  };
} // namespace ccf
