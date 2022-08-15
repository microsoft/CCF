// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "ccf/common_auth_policies.h"
#include "ccf/common_endpoint_registry.h"
#include "ccf/crypto/base64.h"
#include "ccf/crypto/key_pair.h"
#include "ccf/ds/nonstd.h"
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
    bool set_js_app(kv::Tx& tx, const JsBundle& bundle)
    {
      std::string module_prefix = "/";
      remove_modules(tx, module_prefix);
      set_modules(tx, module_prefix, bundle.modules);

      remove_endpoints(tx);

      auto endpoints =
        tx.rw<ccf::endpoints::EndpointsMap>(ccf::endpoints::Tables::ENDPOINTS);

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
          endpoints->put(
            ccf::endpoints::EndpointKey{
              nonstd::starts_with(url, "/") ? url : fmt::format("/{}", url),
              verb},
            info_);
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

    void remove_endpoints(kv::Tx& tx) {}

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
        js::Runtime rt;
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
          vote_failures.value()[mid] = ccf::jsgov::Failure{reason, trace};
        }
      }

      {
        js::Runtime rt;
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
            js::Runtime rt;
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
      openapi_info.document_version = "2.7.3";
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

      const AuthnPolicies member_cert_or_sig = {
        member_cert_auth_policy, member_signature_auth_policy};

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
      make_endpoint("/ack", HTTP_POST, json_adapter(ack), member_sig_only)
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
        "/ack/update_state_digest",
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
          GetRecoveryShare::Out{crypto::b64_from_raw(encrypted_share.value())});
      };
      make_endpoint(
        "/recovery_share",
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
            "Member is not active.");
        }

        GenesisGenerator g(this->network, ctx.tx);
        if (
          g.get_service_status() != ServiceStatus::WAITING_FOR_RECOVERY_SHARES)
        {
          return make_error(
            HTTP_STATUS_FORBIDDEN,
            errors::ServiceNotWaitingForRecoveryShares,
            "Service is not waiting for recovery shares.");
        }

        auto node_operation = context.get_subsystem<AbstractNodeOperation>();
        if (node_operation == nullptr)
        {
          throw std::logic_error(
            "Unexpected: Could not access NodeOperation subsystem");
        }

        if (node_operation->is_reading_private_ledger())
        {
          return make_error(
            HTTP_STATUS_FORBIDDEN,
            errors::NodeAlreadyRecovering,
            "Node is already recovering private ledger.");
        }

        const auto in = params.get<SubmitRecoveryShare::In>();
        auto raw_recovery_share = crypto::raw_from_b64(in.share);
        OPENSSL_cleanse(const_cast<char*>(in.share.data()), in.share.size());

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
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            errors::InternalError,
            error_msg);
        }
        OPENSSL_cleanse(raw_recovery_share.data(), raw_recovery_share.size());

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
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            errors::InternalError,
            error_msg);
        }

        return make_success(SubmitRecoveryShare::Out{fmt::format(
          "{}/{} recovery shares successfully submitted. End of recovery "
          "procedure initiated.",
          submitted_shares_count,
          g.get_recovery_threshold())});
      };
      make_endpoint(
        "/recovery_share",
        HTTP_POST,
        json_adapter(submit_recovery_share),
        member_cert_or_sig)
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

        js::Runtime rt;
        js::Context context(rt, js::TxAccess::GOV_RO);
        rt.add_ccf_classdefs();
        js::populate_global(
          nullptr,
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

        auto body =
          reinterpret_cast<const char*>(ctx.rpc_ctx->get_request_body().data());
        auto body_len = ctx.rpc_ctx->get_request_body().size();

        auto proposal = context.new_string_len(body, body_len);
        auto val = context.call(validate_func, {proposal});

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
        pm->put(proposal_id, ctx.rpc_ctx->get_request_body());

        auto pi =
          ctx.tx.rw<ccf::jsgov::ProposalInfoMap>(jsgov::Tables::PROPOSALS_INFO);
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
            {caller_identity.member_id,
             rv.state,
             {},
             {},
             std::nullopt,
             rv.failure});
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

      auto get_proposal_js = [this](
                               endpoints::ReadOnlyEndpointContext& ctx,
                               nlohmann::json&&) {
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
          ctx.tx.rw<ccf::jsgov::ProposalInfoMap>(jsgov::Tables::PROPOSALS_INFO);
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
        "/proposals/{proposal_id}/withdraw",
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
        member_cert_or_sig)
        .set_auto_schema<void, jsgov::Proposal>()
        .install();

      auto vote_js = [this](ccf::endpoints::EndpointContext& ctx) {
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

        if (pi_->ballots.find(caller_identity.member_id) != pi_->ballots.end())
        {
          ctx.rpc_ctx->set_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::VoteAlreadyExists,
            "Vote already submitted.");
          return;
        }
        // Validate vote

        auto params = nlohmann::json::parse(ctx.rpc_ctx->get_request_body());

        {
          js::Runtime rt;
          js::Context context(rt, js::TxAccess::GOV_RO);
          auto ballot_func =
            context.function(params["ballot"], "vote", "body[\"ballot\"]");
        }

        pi_->ballots[caller_identity.member_id] = params["ballot"];
        pi->put(proposal_id, pi_.value());

        // Do we still need to do this?
        record_voting_history(
          ctx.tx, caller_identity.member_id, caller_identity.signed_request);

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
        member_cert_or_sig)
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
