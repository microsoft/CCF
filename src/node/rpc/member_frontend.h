// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "ds/nonstd.h"
#include "frontend.h"
#include "lua_interp/lua_json.h"
#include "lua_interp/tx_script_runner.h"
#include "node/genesis_gen.h"
#include "node/members.h"
#include "node/nodes.h"
#include "node/quote.h"
#include "node/secret_share.h"
#include "node/share_manager.h"
#include "node_interface.h"
#include "tls/base64.h"
#include "tls/key_pair.h"

#include <charconv>
#include <exception>
#include <initializer_list>
#include <map>
#include <memory>
#include <openenclave/attestation/verifier.h>
#include <set>
#include <sstream>
#if defined(INSIDE_ENCLAVE) && !defined(VIRTUAL_ENCLAVE)
#  include <openenclave/enclave.h>
#else
#  include <openenclave/host_verify.h>
#endif

namespace ccf
{
  class MemberTsr : public lua::TxScriptRunner
  {
    void setup_environment(
      lua::Interpreter& li,
      const std::optional<Script>& env_script) const override
    {
      auto l = li.get_state();
      lua_register(l, "pem_to_der", lua_pem_to_der);
      lua_register(
        l, "verify_cert_and_get_claims", lua_verify_cert_and_get_claims);

      TxScriptRunner::setup_environment(li, env_script);
    }

    static int lua_pem_to_der(lua_State* l)
    {
      std::string pem = get_var_string_from_args(l);
      std::vector<uint8_t> der = tls::make_verifier(pem)->der_cert_data();
      nlohmann::json json = der;
      lua::push_raw(l, json);
      return 1;
    }

    static oe_result_t oe_verify_attestation_certificate_with_evidence_cb(
      oe_claim_t* claims, size_t claims_length, void* arg)
    {
      auto claims_map = (std::map<std::string, std::vector<uint8_t>>*)arg;
      for (size_t i = 0; i < claims_length; i++)
      {
        std::string claim_name(claims[i].name);
        std::vector<uint8_t> claim_value(
          claims[i].value, claims[i].value + claims[i].value_size);
        claims_map->emplace(std::move(claim_name), std::move(claim_value));
      }
      return OE_OK;
    }

    static int lua_verify_cert_and_get_claims(lua_State* l)
    {
      LOG_INFO_FMT("lua_verify_cert_and_get_claims");
      nlohmann::json json = lua::check_get<nlohmann::json>(l, -1);
      std::vector<uint8_t> cert_der = json;

      std::map<std::string, std::vector<uint8_t>> claims;

      oe_verifier_initialize();
      oe_result_t res = oe_verify_attestation_certificate_with_evidence(
        cert_der.data(),
        cert_der.size(),
        oe_verify_attestation_certificate_with_evidence_cb,
        &claims);

      if (res != OE_OK)
      {
        // Validation should happen before the proposal is registered.
        // See https://github.com/microsoft/CCF/issues/1458.
        throw std::runtime_error(fmt::format(
          "Invalid certificate, "
          "oe_verify_attestation_certificate_with_evidence() returned {}",
          res));
      }

      lua_newtable(l);
      const int table_idx = -2;

      for (auto const& item : claims)
      {
        std::string val_hex = fmt::format("{:02x}", fmt::join(item.second, ""));
        LOG_INFO_FMT("claim[{}] = {}", item.first, val_hex);
        lua::push_raw(l, val_hex);
        lua_setfield(l, table_idx, item.first.c_str());
      }

      return 1;
    }

  public:
    MemberTsr(NetworkTables& network) : TxScriptRunner(network) {}
  };

  struct SetMemberData
  {
    MemberId member_id;
    nlohmann::json member_data = nullptr;
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(SetMemberData)
  DECLARE_JSON_REQUIRED_FIELDS(SetMemberData, member_id)
  DECLARE_JSON_OPTIONAL_FIELDS(SetMemberData, member_data)

  struct SetUserData
  {
    UserId user_id;
    nlohmann::json user_data = nullptr;
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(SetUserData)
  DECLARE_JSON_REQUIRED_FIELDS(SetUserData, user_id)
  DECLARE_JSON_OPTIONAL_FIELDS(SetUserData, user_data)

  struct GetEncryptedRecoveryShare
  {
    std::string encrypted_recovery_share;
    std::string nonce;

    GetEncryptedRecoveryShare() = default;

    GetEncryptedRecoveryShare(const EncryptedShare& encrypted_share_raw) :
      encrypted_recovery_share(
        tls::b64_from_raw(encrypted_share_raw.encrypted_share)),
      nonce(tls::b64_from_raw(encrypted_share_raw.nonce))
    {}
  };
  DECLARE_JSON_TYPE(GetEncryptedRecoveryShare)
  DECLARE_JSON_REQUIRED_FIELDS(
    GetEncryptedRecoveryShare, encrypted_recovery_share, nonce)

  struct SetModule
  {
    std::string name;
    Module module;
  };
  DECLARE_JSON_TYPE(SetModule)
  DECLARE_JSON_REQUIRED_FIELDS(SetModule, name, module)

  struct JsBundleEndpointMethod : public ccf::endpoints::EndpointProperties
  {
    std::string js_module;
    std::string js_function;
  };
  DECLARE_JSON_TYPE_WITH_BASE(
    JsBundleEndpointMethod, ccf::endpoints::EndpointProperties)
  DECLARE_JSON_REQUIRED_FIELDS(JsBundleEndpointMethod, js_module, js_function)

  using JsBundleEndpoint = std::map<std::string, JsBundleEndpointMethod>;

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

  struct DeployJsApp
  {
    JsBundle bundle;
  };
  DECLARE_JSON_TYPE(DeployJsApp)
  DECLARE_JSON_REQUIRED_FIELDS(DeployJsApp, bundle)

  class MemberEndpoints : public CommonEndpointRegistry
  {
  private:
    Script get_script(kv::Tx& tx, std::string name)
    {
      const auto s = tx.get_view(network.gov_scripts)->get(name);
      if (!s)
      {
        throw std::logic_error(
          fmt::format("Could not find gov script: {}", name));
      }
      return *s;
    }

    void set_app_scripts(kv::Tx& tx, std::map<std::string, std::string> scripts)
    {
      auto tx_scripts = tx.get_view(network.app_scripts);

      // First, remove all existing handlers
      tx_scripts->foreach(
        [&tx_scripts](const std::string& name, const Script&) {
          tx_scripts->remove(name);
          return true;
        });

      for (auto& rs : scripts)
      {
        tx_scripts->put(rs.first, lua::compile(rs.second));
      }
    }

    void set_js_scripts(kv::Tx& tx, std::map<std::string, std::string> scripts)
    {
      auto tx_scripts = tx.get_view(network.app_scripts);

      // First, remove all existing handlers
      tx_scripts->foreach(
        [&tx_scripts](const std::string& name, const Script&) {
          tx_scripts->remove(name);
          return true;
        });

      for (auto& rs : scripts)
      {
        tx_scripts->put(rs.first, {rs.second});
      }
    }

    bool deploy_js_app(kv::Tx& tx, const JsBundle& bundle)
    {
      std::string module_prefix = "/";
      remove_modules(tx, module_prefix);
      set_modules(tx, module_prefix, bundle.modules);

      auto endpoints_view =
        tx.get_view<ccf::endpoints::EndpointsMap>(ccf::Tables::ENDPOINTS);

      std::map<std::string, std::string> scripts;
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

          auto verb = nlohmann::json(method).get<RESTVerb>();
          endpoints_view->put(ccf::endpoints::EndpointKey{url, verb}, info);

          // CCF currently requires each endpoint to have an inline JS module.
          std::string method_uppercase = method;
          nonstd::to_upper(method_uppercase);
          std::string url_without_leading_slash = url.substr(1);
          std::string key =
            fmt::format("{} {}", method_uppercase, url_without_leading_slash);
          std::string script = fmt::format(
            "import {{ {} as f }} from '.{}{}'; export default (r) => f(r);",
            info.js_function,
            module_prefix,
            info.js_module);
          scripts.emplace(key, script);
        }
      }

      set_js_scripts(tx, scripts);

      return true;
    }

    bool remove_js_app(kv::Tx& tx)
    {
      remove_modules(tx, "/");
      set_js_scripts(tx, {});

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
      auto tx_modules = tx.get_view(network.modules);
      tx_modules->put(name, module);
      return true;
    }

    void remove_modules(kv::Tx& tx, std::string prefix)
    {
      auto tx_modules = tx.get_view(network.modules);
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
      auto tx_modules = tx.get_view(network.modules);
      return tx_modules->remove(name);
    }

    bool add_new_code_id(
      kv::Tx& tx,
      const CodeDigest& new_code_id,
      CodeIDs& code_id_table,
      ObjectId proposal_id)
    {
      auto code_ids = tx.get_view(code_id_table);
      auto existing_code_id = code_ids->get(new_code_id);
      if (existing_code_id)
      {
        LOG_FAIL_FMT(
          "Proposal {}: Code signature already exists with digest: {:02x}",
          proposal_id,
          fmt::join(new_code_id, ""));
        return false;
      }
      code_ids->put(new_code_id, CodeStatus::ACCEPTED);
      return true;
    }

    bool retire_code_id(
      kv::Tx& tx,
      const CodeDigest& code_id,
      CodeIDs& code_id_table,
      ObjectId proposal_id)
    {
      auto code_ids = tx.get_view(code_id_table);
      auto existing_code_id = code_ids->get(code_id);
      if (!existing_code_id)
      {
        LOG_FAIL_FMT(
          "Proposal {}: No such code id in table: {:02x}",
          proposal_id,
          fmt::join(code_id, ""));
        return false;
      }
      code_ids->put(code_id, CodeStatus::RETIRED);
      return true;
    }

    //! Table of functions that proposal scripts can propose to invoke
    const std::unordered_map<
      std::string,
      std::function<bool(ObjectId, kv::Tx&, const nlohmann::json&)>>
      hardcoded_funcs = {
        // set the lua application script
        {"set_lua_app",
         [this](ObjectId, kv::Tx& tx, const nlohmann::json& args) {
           const std::string app = args;
           set_app_scripts(tx, lua::Interpreter().invoke<nlohmann::json>(app));

           return true;
         }},
        // set the js application script
        {"set_js_app",
         [this](ObjectId, kv::Tx& tx, const nlohmann::json& args) {
           const std::string app = args;
           set_js_scripts(tx, lua::Interpreter().invoke<nlohmann::json>(app));
           return true;
         }},
        // deploy the js application bundle
        {"deploy_js_app",
         [this](ObjectId, kv::Tx& tx, const nlohmann::json& args) {
           const auto parsed = args.get<DeployJsApp>();
           return deploy_js_app(tx, parsed.bundle);
         }},
        // undeploy/remove the js application
        {"remove_js_app",
         [this](ObjectId, kv::Tx& tx, const nlohmann::json&) {
           return remove_js_app(tx);
         }},
        // add/update a module
        {"set_module",
         [this](ObjectId, kv::Tx& tx, const nlohmann::json& args) {
           const auto parsed = args.get<SetModule>();
           return set_module(tx, parsed.name, parsed.module);
         }},
        // remove a module
        {"remove_module",
         [this](ObjectId, kv::Tx& tx, const nlohmann::json& args) {
           const auto name = args.get<std::string>();
           return remove_module(tx, name);
         }},
        // add a new member
        {"new_member",
         [this](ObjectId, kv::Tx& tx, const nlohmann::json& args) {
           const auto parsed = args.get<MemberPubInfo>();
           GenesisGenerator g(this->network, tx);
           g.add_member(parsed);

           return true;
         }},
        // retire an existing member
        {"retire_member",
         [this](ObjectId, kv::Tx& tx, const nlohmann::json& args) {
           const auto member_id = args.get<MemberId>();

           GenesisGenerator g(this->network, tx);

           auto member_info = g.get_member_info(member_id);
           if (!member_info.has_value())
           {
             return false;
           }

           if (!g.retire_member(member_id))
           {
             LOG_FAIL_FMT("Failed to retire member {}", member_id);
             return false;
           }

           if (member_info->status == MemberStatus::ACTIVE)
           {
             // A retired member should not have access to the private ledger
             // going forward. New recovery shares are also issued to remaining
             // active members.
             if (!node.rekey_ledger(tx))
             {
               return false;
             }
           }

           return true;
         }},
        {"set_member_data",
         [this](ObjectId proposal_id, kv::Tx& tx, const nlohmann::json& args) {
           const auto parsed = args.get<SetMemberData>();
           auto members_view = tx.get_view(this->network.members);
           auto member_info = members_view->get(parsed.member_id);
           if (!member_info.has_value())
           {
             LOG_FAIL_FMT(
               "Proposal {}: {} is not a valid member ID",
               proposal_id,
               parsed.member_id);
             return false;
           }

           member_info->member_data = parsed.member_data;
           members_view->put(parsed.member_id, member_info.value());
           return true;
         }},
        {"new_user",
         [this](ObjectId, kv::Tx& tx, const nlohmann::json& args) {
           const auto user_info = args.get<ccf::UserInfo>();

           GenesisGenerator g(this->network, tx);
           g.add_user(user_info);

           return true;
         }},
        {"remove_user",
         [this](ObjectId proposal_id, kv::Tx& tx, const nlohmann::json& args) {
           const UserId user_id = args;

           GenesisGenerator g(this->network, tx);
           auto r = g.remove_user(user_id);
           if (!r)
           {
             LOG_FAIL_FMT(
               "Proposal {}: {} is not a valid user ID", proposal_id, user_id);
           }

           return r;
         }},
        {"set_user_data",
         [this](ObjectId proposal_id, kv::Tx& tx, const nlohmann::json& args) {
           const auto parsed = args.get<SetUserData>();
           auto users_view = tx.get_view(this->network.users);
           auto user_info = users_view->get(parsed.user_id);
           if (!user_info.has_value())
           {
             LOG_FAIL_FMT(
               "Proposal {}: {} is not a valid user ID",
               proposal_id,
               parsed.user_id);
             return false;
           }

           user_info->user_data = parsed.user_data;
           users_view->put(parsed.user_id, user_info.value());
           return true;
         }},
        // accept a node
        {"trust_node",
         [this](ObjectId proposal_id, kv::Tx& tx, const nlohmann::json& args) {
           const auto id = args.get<NodeId>();
           auto nodes = tx.get_view(this->network.nodes);
           auto node_info = nodes->get(id);
           if (!node_info.has_value())
           {
             LOG_FAIL_FMT(
               "Proposal {}: Node {} does not exist", proposal_id, id);
             return false;
           }
           if (node_info->status == NodeStatus::RETIRED)
           {
             LOG_FAIL_FMT(
               "Proposal {}: Node {} is already retired", proposal_id, id);
             return false;
           }
           node_info->status = NodeStatus::TRUSTED;
           nodes->put(id, node_info.value());
           LOG_INFO_FMT("Node {} is now {}", id, node_info->status);
           return true;
         }},
        // retire a node
        {"retire_node",
         [this](ObjectId proposal_id, kv::Tx& tx, const nlohmann::json& args) {
           const auto id = args.get<NodeId>();
           auto nodes = tx.get_view(this->network.nodes);
           auto node_info = nodes->get(id);
           if (!node_info.has_value())
           {
             LOG_FAIL_FMT(
               "Proposal {}: Node {} does not exist", proposal_id, id);
             return false;
           }
           if (node_info->status == NodeStatus::RETIRED)
           {
             LOG_FAIL_FMT(
               "Proposal {}: Node {} is already retired", proposal_id, id);
             return false;
           }
           node_info->status = NodeStatus::RETIRED;
           nodes->put(id, node_info.value());
           LOG_INFO_FMT("Node {} is now {}", id, node_info->status);
           return true;
         }},
        // accept new node code ID
        {"new_node_code",
         [this](ObjectId proposal_id, kv::Tx& tx, const nlohmann::json& args) {
           return this->add_new_code_id(
             tx,
             args.get<CodeDigest>(),
             this->network.node_code_ids,
             proposal_id);
         }},
        // retire node code ID
        {"retire_node_code",
         [this](ObjectId proposal_id, kv::Tx& tx, const nlohmann::json& args) {
           return this->retire_code_id(
             tx,
             args.get<CodeDigest>(),
             this->network.node_code_ids,
             proposal_id);
         }},
        // For now, members can propose to accept a recovery with shares. In
        // that case, members will have to submit their shares after this
        // proposal is accepted.
        {"accept_recovery",
         [this](ObjectId proposal_id, kv::Tx& tx, const nlohmann::json&) {
           if (node.is_part_of_public_network())
           {
             const auto accept_recovery = node.accept_recovery(tx);
             if (!accept_recovery)
             {
               LOG_FAIL_FMT("Proposal {}: Accept recovery failed", proposal_id);
             }
             return accept_recovery;
           }
           else
           {
             LOG_FAIL_FMT(
               "Proposal {}: Node is not part of public network", proposal_id);
             return false;
           }
         }},
        {"open_network",
         [this](ObjectId proposal_id, kv::Tx& tx, const nlohmann::json&) {
           // On network open, the service checks that a sufficient number of
           // members have become active. If so, recovery shares are allocated
           // to each active member.
           try
           {
             share_manager.issue_shares(tx);
           }
           catch (const std::logic_error& e)
           {
             LOG_FAIL_FMT(
               "Proposal {}: Issuing recovery shares failed when opening the "
               "network: {}",
               proposal_id,
               e.what());
             return false;
           }

           GenesisGenerator g(this->network, tx);
           const auto network_opened = g.open_service();
           if (!network_opened)
           {
             LOG_FAIL_FMT("Proposal {}: Open network failed", proposal_id);
           }
           return network_opened;
         }},
        {"rekey_ledger",
         [this](ObjectId proposal_id, kv::Tx& tx, const nlohmann::json&) {
           const auto ledger_rekeyed = node.rekey_ledger(tx);
           if (!ledger_rekeyed)
           {
             LOG_FAIL_FMT("Proposal {}: Ledger rekey failed", proposal_id);
           }
           return ledger_rekeyed;
         }},
        {"update_recovery_shares",
         [this](ObjectId proposal_id, kv::Tx& tx, const nlohmann::json&) {
           try
           {
             share_manager.issue_shares(tx);
           }
           catch (const std::logic_error& e)
           {
             LOG_FAIL_FMT(
               "Proposal {}: Updating recovery shares failed: {}",
               proposal_id,
               e.what());
             return false;
           }
           return true;
         }},
        {"set_recovery_threshold",
         [this](ObjectId proposal_id, kv::Tx& tx, const nlohmann::json& args) {
           const auto new_recovery_threshold = args.get<size_t>();

           GenesisGenerator g(this->network, tx);

           if (new_recovery_threshold == g.get_recovery_threshold())
           {
             // If the recovery threshold is the same as before, return with no
             // effect
             return true;
           }

           if (!g.set_recovery_threshold(new_recovery_threshold))
           {
             return false;
           }

           // Update recovery shares (same number of shares)
           try
           {
             share_manager.issue_shares(tx);
           }
           catch (const std::logic_error& e)
           {
             LOG_FAIL_FMT(
               "Proposal {}: Setting recovery threshold failed: {}",
               proposal_id,
               e.what());
             return false;
           }
           return true;
         }},
      };

    ProposalInfo complete_proposal(
      kv::Tx& tx, const ObjectId proposal_id, Proposal& proposal)
    {
      if (proposal.state != ProposalState::OPEN)
      {
        throw std::logic_error(fmt::format(
          "Cannot complete non-open proposal - current state is {}",
          proposal.state));
      }

      auto proposals = tx.get_view(this->network.proposals);

      // run proposal script
      const auto proposed_calls = tsr.run<nlohmann::json>(
        tx,
        {proposal.script,
         {}, // can't write
         WlIds::MEMBER_CAN_READ,
         get_script(tx, GovScriptIds::ENV_PROPOSAL)},
        // vvv arguments to script vvv
        proposal.parameter);

      nlohmann::json votes;
      // Collect all member votes
      for (const auto& vote : proposal.votes)
      {
        // valid voter
        if (!check_member_active(tx, vote.first))
        {
          continue;
        }

        // does the voter agree?
        votes[std::to_string(vote.first)] = tsr.run<bool>(
          tx,
          {vote.second,
           {}, // can't write
           WlIds::MEMBER_CAN_READ,
           {}},
          proposed_calls);
      }

      const auto pass = tsr.run<int>(
        tx,
        {get_script(tx, GovScriptIds::PASS),
         {}, // can't write
         WlIds::MEMBER_CAN_READ,
         {}},
        // vvv arguments to script vvv
        proposed_calls,
        votes);

      switch (pass)
      {
        case CompletionResult::PASSED:
        {
          // vote passed, go on to update the state
          break;
        }
        case CompletionResult::PENDING:
        {
          // vote is pending, return false but do not update state
          return get_proposal_info(proposal_id, proposal);
        }
        case CompletionResult::REJECTED:
        {
          // vote unsuccessful, update the proposal's state
          proposal.state = ProposalState::REJECTED;
          proposals->put(proposal_id, proposal);
          return get_proposal_info(proposal_id, proposal);
        }
        default:
        {
          throw std::logic_error(fmt::format(
            "Invalid completion result ({}) for proposal {}",
            pass,
            proposal_id));
        }
      };

      // execute proposed calls
      ProposedCalls pc = proposed_calls;
      for (const auto& call : pc)
      {
        // proposing a hardcoded C++ function?
        const auto f = hardcoded_funcs.find(call.func);
        if (f != hardcoded_funcs.end())
        {
          if (!f->second(proposal_id, tx, call.args))
          {
            proposal.state = ProposalState::FAILED;
            proposals->put(proposal_id, proposal);
            return get_proposal_info(proposal_id, proposal);
          }
          continue;
        }

        // proposing a script function?
        const auto s = tx.get_view(network.gov_scripts)->get(call.func);
        if (!s.has_value())
        {
          continue;
        }
        tsr.run<void>(
          tx,
          {s.value(),
           WlIds::MEMBER_CAN_PROPOSE, // can write!
           {},
           {}},
          call.args);
      }

      // if the vote was successful, update the proposal's state
      proposal.state = ProposalState::ACCEPTED;
      proposals->put(proposal_id, proposal);

      return get_proposal_info(proposal_id, proposal);
    }

    bool check_member_active(kv::ReadOnlyTx& tx, MemberId id)
    {
      return check_member_status(tx, id, {MemberStatus::ACTIVE});
    }

    bool check_member_accepted(kv::ReadOnlyTx& tx, MemberId id)
    {
      return check_member_status(
        tx, id, {MemberStatus::ACTIVE, MemberStatus::ACCEPTED});
    }

    bool check_member_status(
      kv::ReadOnlyTx& tx,
      MemberId id,
      std::initializer_list<MemberStatus> allowed)
    {
      auto member = tx.get_read_only_view(this->network.members)->get(id);
      if (!member)
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
      kv::Tx& tx, CallerId caller_id, const SignedReq& signed_request)
    {
      auto governance_history = tx.get_view(network.governance_history);
      governance_history->put(caller_id, {signed_request});
    }

    static ProposalInfo get_proposal_info(
      ObjectId proposal_id, const Proposal& proposal)
    {
      return ProposalInfo{proposal_id, proposal.proposer, proposal.state};
    }

    template <typename T>
    bool get_path_param(
      const enclave::PathParams& params,
      const std::string& param_name,
      T& value,
      std::string& error)
    {
      const auto it = params.find(param_name);
      if (it == params.end())
      {
        error = fmt::format("No parameter named '{}' in path", param_name);
        return false;
      }

      const auto param_s = it->second;
      const auto [p, ec] =
        std::from_chars(param_s.data(), param_s.data() + param_s.size(), value);
      if (ec != std::errc())
      {
        error = fmt::format(
          "Unable to parse path parameter '{}' as a {}", param_s, param_name);
        return false;
      }

      return true;
    }

    bool get_proposal_id_from_path(
      const enclave::PathParams& params,
      ObjectId& proposal_id,
      std::string& error)
    {
      return get_path_param(params, "proposal_id", proposal_id, error);
    }

    bool get_member_id_from_path(
      const enclave::PathParams& params,
      MemberId& member_id,
      std::string& error)
    {
      return get_path_param(params, "member_id", member_id, error);
    }

    NetworkTables& network;
    AbstractNodeState& node;
    ShareManager& share_manager;
    const MemberTsr tsr;

  public:
    MemberEndpoints(
      NetworkTables& network,
      AbstractNodeState& node,
      ShareManager& share_manager) :
      CommonEndpointRegistry(
        get_actor_prefix(ActorsType::members),
        *network.tables,
        Tables::MEMBER_CERT_DERS),
      network(network),
      node(node),
      share_manager(share_manager),
      tsr(network)
    {
      openapi_info.title = "CCF Governance API";
      openapi_info.description =
        "This API is used to submit and query proposals which affect CCF's "
        "public governance tables.";
    }

    void init_handlers(kv::Store& tables_) override
    {
      CommonEndpointRegistry::init_handlers(tables_);

      auto read = [this](
                    kv::Tx& tx, CallerId caller_id, nlohmann::json&& params) {
        if (!check_member_status(
              tx, caller_id, {MemberStatus::ACTIVE, MemberStatus::ACCEPTED}))
        {
          return make_error(
            HTTP_STATUS_FORBIDDEN, "Member is not active or accepted");
        }

        const auto in = params.get<KVRead::In>();

        const ccf::Script read_script(R"xxx(
        local tables, table_name, key = ...
        return tables[table_name]:get(key) or {}
        )xxx");

        auto value = tsr.run<nlohmann::json>(
          tx, {read_script, {}, WlIds::MEMBER_CAN_READ, {}}, in.table, in.key);
        if (value.empty())
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST,
            fmt::format(
              "Key {} does not exist in table {}", in.key.dump(), in.table));
        }

        return make_success(value);
      };
      make_endpoint("read", HTTP_POST, json_adapter(read))
        // This can be executed locally, but can't currently take ReadOnlyTx due
        // to restrictions in our lua wrappers
        .set_forwarding_required(ForwardingRequired::Sometimes)
        .set_auto_schema<KVRead>()
        .install();

      auto query =
        [this](kv::Tx& tx, CallerId caller_id, nlohmann::json&& params) {
          if (!check_member_accepted(tx, caller_id))
          {
            return make_error(HTTP_STATUS_FORBIDDEN, "Member is not accepted");
          }

          const auto script = params.get<ccf::Script>();
          return make_success(tsr.run<nlohmann::json>(
            tx, {script, {}, WlIds::MEMBER_CAN_READ, {}}));
        };
      make_endpoint("query", HTTP_POST, json_adapter(query))
        // This can be executed locally, but can't currently take ReadOnlyTx due
        // to restristions in our lua wrappers
        .set_forwarding_required(ForwardingRequired::Sometimes)
        .set_auto_schema<Script, nlohmann::json>()
        .install();

      auto propose = [this](EndpointContext& args, nlohmann::json&& params) {
        if (!check_member_active(args.tx, args.caller_id))
        {
          return make_error(HTTP_STATUS_FORBIDDEN, "Member is not active");
        }

        const auto in = params.get<Propose::In>();
        const auto proposal_id = get_next_id(
          args.tx.get_view(this->network.values), ValueIds::NEXT_PROPOSAL_ID);
        Proposal proposal(in.script, in.parameter, args.caller_id);

        auto proposals = args.tx.get_view(this->network.proposals);
        proposal.votes[args.caller_id] = in.ballot;
        proposals->put(proposal_id, proposal);

        record_voting_history(
          args.tx, args.caller_id, args.rpc_ctx->get_signed_request().value());

        return make_success(
          Propose::Out{complete_proposal(args.tx, proposal_id, proposal)});
      };
      make_endpoint("proposals", HTTP_POST, json_adapter(propose))
        .set_auto_schema<Propose>()
        .set_require_client_signature(true)
        .install();

      auto get_proposal =
        [this](ReadOnlyEndpointContext& args, nlohmann::json&&) {
          if (!check_member_active(args.tx, args.caller_id))
          {
            return make_error(HTTP_STATUS_FORBIDDEN, "Member is not active");
          }

          ObjectId proposal_id;
          std::string error;
          if (!get_proposal_id_from_path(
                args.rpc_ctx->get_request_path_params(), proposal_id, error))
          {
            return make_error(HTTP_STATUS_BAD_REQUEST, error);
          }

          auto proposals = args.tx.get_read_only_view(this->network.proposals);
          auto proposal = proposals->get(proposal_id);

          if (!proposal)
          {
            return make_error(
              HTTP_STATUS_BAD_REQUEST,
              fmt::format("Proposal {} does not exist", proposal_id));
          }

          return make_success(proposal.value());
        };
      make_read_only_endpoint(
        "proposals/{proposal_id}",
        HTTP_GET,
        json_read_only_adapter(get_proposal))
        .set_auto_schema<void, Proposal>()
        .install();

      auto withdraw = [this](EndpointContext& args, nlohmann::json&&) {
        if (!check_member_active(args.tx, args.caller_id))
        {
          return make_error(HTTP_STATUS_FORBIDDEN, "Member is not active");
        }

        ObjectId proposal_id;
        std::string error;
        if (!get_proposal_id_from_path(
              args.rpc_ctx->get_request_path_params(), proposal_id, error))
        {
          return make_error(HTTP_STATUS_BAD_REQUEST, error);
        }

        auto proposals = args.tx.get_view(this->network.proposals);
        auto proposal = proposals->get(proposal_id);

        if (!proposal)
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST,
            fmt::format("Proposal {} does not exist", proposal_id));
        }

        if (proposal->proposer != args.caller_id)
        {
          return make_error(
            HTTP_STATUS_FORBIDDEN,
            fmt::format(
              "Proposal {} can only be withdrawn by proposer {}, not caller {}",
              proposal_id,
              proposal->proposer,
              args.caller_id));
        }

        if (proposal->state != ProposalState::OPEN)
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST,
            fmt::format(
              "Proposal {} is currently in state {} - only {} proposals can be "
              "withdrawn",
              proposal_id,
              proposal->state,
              ProposalState::OPEN));
        }

        proposal->state = ProposalState::WITHDRAWN;
        proposals->put(proposal_id, proposal.value());
        record_voting_history(
          args.tx, args.caller_id, args.rpc_ctx->get_signed_request().value());

        return make_success(get_proposal_info(proposal_id, proposal.value()));
      };
      make_endpoint(
        "proposals/{proposal_id}/withdraw", HTTP_POST, json_adapter(withdraw))
        .set_auto_schema<void, ProposalInfo>()
        .set_require_client_signature(true)
        .install();

      auto vote = [this](EndpointContext& args, nlohmann::json&& params) {
        if (!check_member_active(args.tx, args.caller_id))
        {
          return make_error(HTTP_STATUS_FORBIDDEN, "Member is not active");
        }

        const auto signed_request = args.rpc_ctx->get_signed_request();
        if (!signed_request.has_value())
        {
          return make_error(HTTP_STATUS_BAD_REQUEST, "Votes must be signed");
        }

        ObjectId proposal_id;
        std::string error;
        if (!get_proposal_id_from_path(
              args.rpc_ctx->get_request_path_params(), proposal_id, error))
        {
          return make_error(HTTP_STATUS_BAD_REQUEST, error);
        }

        auto proposals = args.tx.get_view(this->network.proposals);
        auto proposal = proposals->get(proposal_id);
        if (!proposal)
        {
          return make_error(
            HTTP_STATUS_NOT_FOUND,
            fmt::format("Proposal {} does not exist", proposal_id));
        }

        if (proposal->state != ProposalState::OPEN)
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST,
            fmt::format(
              "Proposal {} is currently in state {} - only {} proposals can "
              "receive votes",
              proposal_id,
              proposal->state,
              ProposalState::OPEN));
        }

        const auto vote = params.get<Vote>();
        proposal->votes[args.caller_id] = vote.ballot;
        proposals->put(proposal_id, proposal.value());

        record_voting_history(
          args.tx, args.caller_id, args.rpc_ctx->get_signed_request().value());

        return make_success(
          complete_proposal(args.tx, proposal_id, proposal.value()));
      };
      make_endpoint(
        "proposals/{proposal_id}/votes", HTTP_POST, json_adapter(vote))
        .set_auto_schema<Vote, ProposalInfo>()
        .set_require_client_signature(true)
        .install();

      auto get_vote = [this](ReadOnlyEndpointContext& args, nlohmann::json&&) {
        if (!check_member_active(args.tx, args.caller_id))
        {
          return make_error(HTTP_STATUS_FORBIDDEN, "Member is not active");
        }

        std::string error;
        ObjectId proposal_id;
        if (!get_proposal_id_from_path(
              args.rpc_ctx->get_request_path_params(), proposal_id, error))
        {
          return make_error(HTTP_STATUS_BAD_REQUEST, error);
        }

        MemberId member_id;
        if (!get_member_id_from_path(
              args.rpc_ctx->get_request_path_params(), member_id, error))
        {
          return make_error(HTTP_STATUS_BAD_REQUEST, error);
        }

        auto proposals = args.tx.get_read_only_view(this->network.proposals);
        auto proposal = proposals->get(proposal_id);
        if (!proposal)
        {
          return make_error(
            HTTP_STATUS_NOT_FOUND,
            fmt::format("Proposal {} does not exist", proposal_id));
        }

        const auto vote_it = proposal->votes.find(member_id);
        if (vote_it == proposal->votes.end())
        {
          return make_error(
            HTTP_STATUS_NOT_FOUND,
            fmt::format(
              "Member {} has not voted for proposal {}",
              member_id,
              proposal_id));
        }

        return make_success(vote_it->second);
      };
      make_read_only_endpoint(
        "proposals/{proposal_id}/votes/{member_id}",
        HTTP_GET,
        json_read_only_adapter(get_vote))
        .set_auto_schema<void, Vote>()
        .install();

      auto complete = [this](EndpointContext& ctx, nlohmann::json&&) {
        if (!check_member_active(ctx.tx, ctx.caller_id))
        {
          return make_error(HTTP_STATUS_FORBIDDEN, "Member is not active");
        }

        ObjectId proposal_id;
        std::string error;
        if (!get_proposal_id_from_path(
              ctx.rpc_ctx->get_request_path_params(), proposal_id, error))
        {
          return make_error(HTTP_STATUS_BAD_REQUEST, error);
        }

        auto proposals = ctx.tx.get_view(this->network.proposals);
        auto proposal = proposals->get(proposal_id);
        if (!proposal.has_value())
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST,
            fmt::format("No such proposal: {}", proposal_id));
        }

        return make_success(
          complete_proposal(ctx.tx, proposal_id, proposal.value()));
      };
      make_endpoint(
        "proposals/{proposal_id}/complete", HTTP_POST, json_adapter(complete))
        .set_auto_schema<void, ProposalInfo>()
        .set_require_client_signature(true)
        .install();

      //! A member acknowledges state
      auto ack = [this](EndpointContext& args, nlohmann::json&& params) {
        const auto signed_request = args.rpc_ctx->get_signed_request();

        auto [ma_view, sig_view] =
          args.tx.get_view(this->network.member_acks, this->network.signatures);
        const auto ma = ma_view->get(args.caller_id);
        if (!ma)
        {
          return make_error(
            HTTP_STATUS_FORBIDDEN,
            fmt::format("No ACK record exists for caller {}", args.caller_id));
        }

        const auto digest = params.get<StateDigest>();
        if (ma->state_digest != digest.state_digest)
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST, "Submitted state digest is not valid");
        }

        const auto s = sig_view->get(0);
        if (!s)
        {
          ma_view->put(args.caller_id, MemberAck({}, signed_request.value()));
        }
        else
        {
          ma_view->put(
            args.caller_id, MemberAck(s->root, signed_request.value()));
        }

        // update member status to ACTIVE
        GenesisGenerator g(this->network, args.tx);
        g.activate_member(args.caller_id);

        auto service_status = g.get_service_status();
        if (!service_status.has_value())
        {
          throw std::logic_error("No service currently available");
        }

        if (service_status.value() == ServiceStatus::OPEN)
        {
          // When the service is OPEN, new active members are allocated new
          // recovery shares
          try
          {
            share_manager.issue_shares(args.tx);
          }
          catch (const std::logic_error& e)
          {
            return make_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              fmt::format("Error issuing new recovery shares: {}", e.what()));
          }
        }
        return make_success(true);
      };
      make_endpoint("ack", HTTP_POST, json_adapter(ack))
        .set_auto_schema<StateDigest, bool>()
        .set_require_client_signature(true)
        .install();

      //! A member asks for a fresher state digest
      auto update_state_digest =
        [this](kv::Tx& tx, CallerId caller_id, nlohmann::json&&) {
          auto [ma_view, sig_view] =
            tx.get_view(this->network.member_acks, this->network.signatures);
          auto ma = ma_view->get(caller_id);
          if (!ma)
          {
            return make_error(
              HTTP_STATUS_FORBIDDEN,
              fmt::format("No ACK record exists for caller {}", caller_id));
          }

          auto s = sig_view->get(0);
          if (s)
          {
            ma->state_digest =
              std::vector<uint8_t>(s->root.h.begin(), s->root.h.end());

            ma_view->put(caller_id, ma.value());
          }

          return make_success(ma.value());
        };
      make_endpoint(
        "ack/update_state_digest", HTTP_POST, json_adapter(update_state_digest))
        .set_auto_schema<void, MemberAck>()
        .install();

      auto get_encrypted_recovery_share = [this](
                                            EndpointContext& args,
                                            nlohmann::json&&) {
        if (!check_member_active(args.tx, args.caller_id))
        {
          return make_error(
            HTTP_STATUS_FORBIDDEN,
            "Only active members are given recovery shares");
        }

        auto encrypted_share =
          share_manager.get_encrypted_share(args.tx, args.caller_id);

        if (!encrypted_share.has_value())
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST,
            fmt::format(
              "Recovery share not found for member {}", args.caller_id));
        }

        return make_success(GetEncryptedRecoveryShare(encrypted_share.value()));
      };
      make_endpoint(
        "recovery_share", HTTP_GET, json_adapter(get_encrypted_recovery_share))
        .set_auto_schema<void, GetEncryptedRecoveryShare>()
        .install();

      auto submit_recovery_share = [this](EndpointContext& args) {
        // Only active members can submit their shares for recovery
        if (!check_member_active(args.tx, args.caller_id))
        {
          args.rpc_ctx->set_response_status(HTTP_STATUS_FORBIDDEN);
          args.rpc_ctx->set_response_body("Member is not active");
          return;
        }

        GenesisGenerator g(this->network, args.tx);
        if (
          g.get_service_status() != ServiceStatus::WAITING_FOR_RECOVERY_SHARES)
        {
          args.rpc_ctx->set_response_status(HTTP_STATUS_FORBIDDEN);
          args.rpc_ctx->set_response_body(
            "Service is not waiting for recovery shares");
          return;
        }

        if (node.is_reading_private_ledger())
        {
          args.rpc_ctx->set_response_status(HTTP_STATUS_FORBIDDEN);
          args.rpc_ctx->set_response_body(
            "Node is already recovering private ledger");
          return;
        }

        const auto& in = args.rpc_ctx->get_request_body();
        const auto s = std::string(in.begin(), in.end());
        auto raw_recovery_share = tls::raw_from_b64(s);

        size_t submitted_shares_count = 0;
        try
        {
          submitted_shares_count = share_manager.submit_recovery_share(
            args.tx, args.caller_id, raw_recovery_share);
        }
        catch (const std::exception& e)
        {
          auto error_msg = "Error submitting recovery shares";
          LOG_FAIL_FMT(error_msg);
          LOG_DEBUG_FMT("Error: {}", e.what());
          args.rpc_ctx->set_response_status(HTTP_STATUS_INTERNAL_SERVER_ERROR);
          args.rpc_ctx->set_response_body(std::move(error_msg));
          return;
        }

        if (submitted_shares_count < g.get_recovery_threshold())
        {
          // The number of shares required to re-assemble the secret has not yet
          // been reached
          args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          args.rpc_ctx->set_response_body(fmt::format(
            "{}/{} recovery shares successfully submitted.",
            submitted_shares_count,
            g.get_recovery_threshold()));
          return;
        }

        LOG_DEBUG_FMT(
          "Reached secret sharing threshold {}", g.get_recovery_threshold());

        try
        {
          node.initiate_private_recovery(args.tx);
        }
        catch (const std::exception& e)
        {
          // Clear the submitted shares if combination fails so that members can
          // start over.
          auto error_msg = "Failed to initiate private recovery";
          LOG_FAIL_FMT(error_msg);
          LOG_DEBUG_FMT("Error: {}", e.what());
          share_manager.clear_submitted_recovery_shares(args.tx);
          args.rpc_ctx->set_response_status(HTTP_STATUS_INTERNAL_SERVER_ERROR);
          args.rpc_ctx->set_response_body(std::move(error_msg));
          return;
        }

        share_manager.clear_submitted_recovery_shares(args.tx);

        args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        args.rpc_ctx->set_response_body(fmt::format(
          "{}/{} recovery shares successfully submitted. End of recovery "
          "procedure initiated.",
          submitted_shares_count,
          g.get_recovery_threshold()));
      };
      make_endpoint("recovery_share", HTTP_POST, submit_recovery_share)
        .set_auto_schema<std::string, std::string>()
        .install();

      auto create = [this](kv::Tx& tx, nlohmann::json&& params) {
        LOG_DEBUG_FMT("Processing create RPC");
        const auto in = params.get<CreateNetworkNodeToNode::In>();

        GenesisGenerator g(this->network, tx);

        // This endpoint can only be called once, directly from the starting
        // node for the genesis transaction to initialise the service
        if (g.is_service_created())
        {
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR, "Service is already created");
        }

        g.init_values();
        g.create_service(in.network_cert);

        for (const auto& info : in.members_info)
        {
          g.add_member(info);
        }

        g.set_recovery_threshold(in.recovery_threshold);

        g.add_consensus(in.consensus_type);

        size_t self = g.add_node({in.node_info_network,
                                  in.node_cert,
                                  in.quote,
                                  in.public_encryption_key,
                                  NodeStatus::TRUSTED});

        LOG_INFO_FMT("Create node id: {}", self);
        if (self != 0)
        {
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR, "Starting node ID is not 0");
        }

#ifdef GET_QUOTE
        if (in.consensus_type != ConsensusType::BFT)
        {
          CodeDigest node_code_id;
          std::copy_n(
            std::begin(in.code_digest),
            CODE_DIGEST_BYTES,
            std::begin(node_code_id));
          g.trust_node_code_id(node_code_id);
        }
#endif

        for (const auto& wl : default_whitelists)
        {
          g.set_whitelist(wl.first, wl.second);
        }

        g.set_gov_scripts(
          lua::Interpreter().invoke<nlohmann::json>(in.gov_script));

        LOG_INFO_FMT("Created service");
        return make_success(true);
      };
      make_endpoint("create", HTTP_POST, json_adapter(create))
        .set_require_client_identity(false)
        .install();
    }
  };

  class MemberRpcFrontend : public RpcFrontend
  {
  protected:
    std::string invalid_caller_error_message() const override
    {
      return "Could not find matching member certificate";
    }

    MemberEndpoints member_endpoints;
    Members* members;

  public:
    MemberRpcFrontend(
      NetworkTables& network,
      AbstractNodeState& node,
      ShareManager& share_manager) :
      RpcFrontend(
        *network.tables, member_endpoints, &network.member_client_signatures),
      member_endpoints(network, node, share_manager),
      members(&network.members)
    {}

    bool lookup_forwarded_caller_cert(
      std::shared_ptr<enclave::RpcContext> ctx, kv::Tx& tx) override
    {
      // Lookup the caller member's certificate from the forwarded caller id
      auto members_view = tx.get_view(*members);
      auto caller = members_view->get(ctx->session->original_caller->caller_id);
      if (!caller.has_value())
      {
        return false;
      }

      ctx->session->caller_cert = caller.value().cert.raw();
      return true;
    }

    virtual bool is_members_frontend() override
    {
      return true;
    }
  };
} // namespace ccf
