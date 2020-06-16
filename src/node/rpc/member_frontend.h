// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "frontend.h"
#include "lua_interp/tx_script_runner.h"
#include "node/genesis_gen.h"
#include "node/members.h"
#include "node/nodes.h"
#include "node/quote.h"
#include "node/secret_share.h"
#include "node/share_manager.h"
#include "node_interface.h"
#include "tls/key_pair.h"

#include <exception>
#include <initializer_list>
#include <map>
#include <memory>
#include <set>
#include <sstream>

namespace ccf
{
  struct SetUserData
  {
    UserId user_id;
    nlohmann::json user_data = nullptr;
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(SetUserData)
  DECLARE_JSON_REQUIRED_FIELDS(SetUserData, user_id)
  DECLARE_JSON_OPTIONAL_FIELDS(SetUserData, user_data)

  struct SubmitRecoveryShare
  {
    std::vector<uint8_t> recovery_share;
  };
  DECLARE_JSON_TYPE(SubmitRecoveryShare)
  DECLARE_JSON_REQUIRED_FIELDS(SubmitRecoveryShare, recovery_share)

  class MemberHandlers : public CommonHandlerRegistry
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
        [&tx_scripts](const std::string& name, const Script& script) {
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
        [&tx_scripts](const std::string& name, const Script& script) {
          tx_scripts->remove(name);
          return true;
        });

      for (auto& rs : scripts)
      {
        tx_scripts->put(rs.first, {rs.second});
      }
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

    //! Table of functions that proposal scripts can propose to invoke
    const std::unordered_map<
      std::string,
      std::function<bool(ObjectId, kv::Tx&, const nlohmann::json&)>>
      hardcoded_funcs = {
        // set the lua application script
        {"set_lua_app",
         [this](ObjectId proposal_id, kv::Tx& tx, const nlohmann::json& args) {
           const std::string app = args;
           set_app_scripts(tx, lua::Interpreter().invoke<nlohmann::json>(app));

           return true;
         }},
        // set the js application script
        {"set_js_app",
         [this](ObjectId proposal_id, kv::Tx& tx, const nlohmann::json& args) {
           const std::string app = args;
           set_js_scripts(tx, lua::Interpreter().invoke<nlohmann::json>(app));
           return true;
         }},
        // add a new member
        {"new_member",
         [this](ObjectId proposal_id, kv::Tx& tx, const nlohmann::json& args) {
           const auto parsed = args.get<MemberPubInfo>();
           GenesisGenerator g(this->network, tx);
           auto new_member_id = g.add_member(parsed.cert, parsed.keyshare);

           return true;
         }},
        // retire an existing member
        {"retire_member",
         [this](ObjectId proposal_id, kv::Tx& tx, const nlohmann::json& args) {
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
        // add a new user
        {"new_user",
         [this](ObjectId proposal_id, kv::Tx& tx, const nlohmann::json& args) {
           const Cert pem_cert = args;

           GenesisGenerator g(this->network, tx);
           g.add_user(pem_cert);

           return true;
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
           const auto id = args.get<CodeDigest>();
           return this->add_new_code_id(
             tx,
             args.get<CodeDigest>(),
             this->network.node_code_ids,
             proposal_id);
         }},
        // accept new user code ID
        {"new_user_code",
         [this](ObjectId proposal_id, kv::Tx& tx, const nlohmann::json& args) {
           const auto id = args.get<CodeDigest>();
           return this->add_new_code_id(
             tx,
             args.get<CodeDigest>(),
             this->network.user_code_ids,
             proposal_id);
         }},
        // For now, members can propose to accept a recovery with shares. In
        // that case, members will have to submit their shares after this
        // proposal is accepted.
        {"accept_recovery",
         [this](ObjectId proposal_id, kv::Tx& tx, const nlohmann::json& args) {
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
         [this](ObjectId proposal_id, kv::Tx& tx, const nlohmann::json& args) {
           const auto network_opened = node.open_network(tx);
           if (!network_opened)
           {
             LOG_FAIL_FMT("Proposal {}: Open network failed", proposal_id);
           }
           return network_opened;
         }},
        {"rekey_ledger",
         [this](ObjectId proposal_id, kv::Tx& tx, const nlohmann::json& args) {
           const auto ledger_rekeyed = node.rekey_ledger(tx);
           if (!ledger_rekeyed)
           {
             LOG_FAIL_FMT("Proposal {}: Ledger rekey failed", proposal_id);
           }
           return ledger_rekeyed;
         }},
        {"update_recovery_shares",
         [this](ObjectId proposal_id, kv::Tx& tx, const nlohmann::json& args) {
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
               "Proposal {}: Setting recovery threshold failed: {}", e.what());
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

    bool check_member_active(kv::Tx& tx, MemberId id)
    {
      return check_member_status(tx, id, {MemberStatus::ACTIVE});
    }

    bool check_member_accepted(kv::Tx& tx, MemberId id)
    {
      return check_member_status(
        tx, id, {MemberStatus::ACTIVE, MemberStatus::ACCEPTED});
    }

    bool check_member_status(
      kv::Tx& tx, MemberId id, std::initializer_list<MemberStatus> allowed)
    {
      auto member = tx.get_view(this->network.members)->get(id);
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

    NetworkTables& network;
    AbstractNodeState& node;
    ShareManager& share_manager;
    const lua::TxScriptRunner tsr;

  public:
    MemberHandlers(
      NetworkTables& network,
      AbstractNodeState& node,
      ShareManager& share_manager) :
      CommonHandlerRegistry(*network.tables, Tables::MEMBER_CERTS),
      network(network),
      node(node),
      share_manager(share_manager),
      tsr(network)
    {}

    void init_handlers(kv::Store& tables_) override
    {
      CommonHandlerRegistry::init_handlers(tables_);

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
      make_handler(MemberProcs::READ, HTTP_POST, json_adapter(read))
        .set_read_write(ReadWrite::Read)
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
      make_handler(MemberProcs::QUERY, HTTP_POST, json_adapter(query))
        .set_read_write(ReadWrite::Read)
        .set_auto_schema<Script, nlohmann::json>()
        .install();

      auto propose = [this](RequestArgs& args, nlohmann::json&& params) {
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
      make_handler(MemberProcs::PROPOSE, HTTP_POST, json_adapter(propose))
        .set_auto_schema<Propose>()
        .install();

      auto withdraw = [this](RequestArgs& args, nlohmann::json&& params) {
        if (!check_member_active(args.tx, args.caller_id))
        {
          return make_error(HTTP_STATUS_FORBIDDEN, "Member is not active");
        }

        const auto proposal_action = params.get<ProposalAction>();
        const auto proposal_id = proposal_action.id;
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
      make_handler(MemberProcs::WITHDRAW, HTTP_POST, json_adapter(withdraw))
        .set_auto_schema<ProposalAction, ProposalInfo>()
        .set_require_client_signature(true)
        .install();

      auto vote = [this](RequestArgs& args, nlohmann::json&& params) {
        if (!check_member_active(args.tx, args.caller_id))
        {
          return make_error(HTTP_STATUS_FORBIDDEN, "Member is not active");
        }

        const auto signed_request = args.rpc_ctx->get_signed_request();
        if (!signed_request.has_value())
        {
          return make_error(HTTP_STATUS_BAD_REQUEST, "Votes must be signed");
        }

        const auto vote = params.get<Vote>();
        auto proposals = args.tx.get_view(this->network.proposals);
        auto proposal = proposals->get(vote.id);
        if (!proposal)
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST,
            fmt::format("Proposal {} does not exist", vote.id));
        }

        if (proposal->state != ProposalState::OPEN)
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST,
            fmt::format(
              "Proposal {} is currently in state {} - only {} proposals can "
              "receive votes",
              vote.id,
              proposal->state,
              ProposalState::OPEN));
        }

        proposal->votes[args.caller_id] = vote.ballot;
        proposals->put(vote.id, proposal.value());

        record_voting_history(
          args.tx, args.caller_id, args.rpc_ctx->get_signed_request().value());

        return make_success(
          complete_proposal(args.tx, vote.id, proposal.value()));
      };
      make_handler(MemberProcs::VOTE, HTTP_POST, json_adapter(vote))
        .set_auto_schema<Vote, ProposalInfo>()
        .set_require_client_signature(true)
        .install();

      auto complete =
        [this](kv::Tx& tx, CallerId caller_id, nlohmann::json&& params) {
          if (!check_member_active(tx, caller_id))
          {
            return make_error(HTTP_STATUS_FORBIDDEN, "Member is not active");
          }

          const auto proposal_action = params.get<ProposalAction>();
          const auto proposal_id = proposal_action.id;

          auto proposals = tx.get_view(this->network.proposals);
          auto proposal = proposals->get(proposal_id);
          if (!proposal.has_value())
          {
            return make_error(
              HTTP_STATUS_BAD_REQUEST,
              fmt::format("No such proposal: {}", proposal_id));
          }

          return make_success(
            complete_proposal(tx, proposal_id, proposal.value()));
        };
      make_handler(MemberProcs::COMPLETE, HTTP_POST, json_adapter(complete))
        .set_auto_schema<ProposalAction, ProposalInfo>()
        .set_require_client_signature(true)
        .install();

      //! A member acknowledges state
      auto ack = [this](RequestArgs& args, nlohmann::json&& params) {
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
        auto members = args.tx.get_view(this->network.members);
        auto member = members->get(args.caller_id);
        if (member->status == MemberStatus::ACCEPTED)
        {
          member->status = MemberStatus::ACTIVE;

          GenesisGenerator g(this->network, args.tx);
          if (g.get_active_members_count() >= max_active_members_count)
          {
            return make_error(
              HTTP_STATUS_FORBIDDEN,
              fmt::format(
                "No more than {} active members are allowed",
                max_active_members_count));
          }
          members->put(args.caller_id, *member);

          // New active members are allocated a new recovery share
          try
          {
            share_manager.issue_shares(args.tx);
          }
          catch (const std::logic_error& e)
          {
            return make_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              fmt::format("Error issuing new recovery shares {}: ", e.what()));
          }
        }
        return make_success(true);
      };
      make_handler(MemberProcs::ACK, HTTP_POST, json_adapter(ack))
        .set_auto_schema<StateDigest, bool>()
        .set_require_client_signature(true)
        .install();

      //! A member asks for a fresher state digest
      auto update_state_digest =
        [this](kv::Tx& tx, CallerId caller_id, nlohmann::json&& params) {
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
      make_handler(
        MemberProcs::UPDATE_ACK_STATE_DIGEST,
        HTTP_POST,
        json_adapter(update_state_digest))
        .set_auto_schema<void, StateDigest>()
        .install();

      auto get_encrypted_recovery_share =
        [this](RequestArgs& args, nlohmann::json&& params) {
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

          return make_success(encrypted_share.value());
        };
      make_handler(
        MemberProcs::GET_ENCRYPTED_RECOVERY_SHARE,
        HTTP_GET,
        json_adapter(get_encrypted_recovery_share))
        .set_auto_schema<void, EncryptedShare>()
        .install();

      auto submit_recovery_share = [this](
                                     RequestArgs& args,
                                     nlohmann::json&& params) {
        // Only active members can submit their shares for recovery
        if (!check_member_active(args.tx, args.caller_id))
        {
          return make_error(HTTP_STATUS_FORBIDDEN, "Member is not active");
        }

        GenesisGenerator g(this->network, args.tx);
        if (
          g.get_service_status() != ServiceStatus::WAITING_FOR_RECOVERY_SHARES)
        {
          return make_error(
            HTTP_STATUS_FORBIDDEN,
            "Service is not waiting for recovery shares");
        }

        if (node.is_reading_private_ledger())
        {
          return make_error(
            HTTP_STATUS_FORBIDDEN, "Node is already recovering private ledger");
        }

        const auto in = params.get<SubmitRecoveryShare>();
        size_t submitted_shares_count = 0;
        try
        {
          submitted_shares_count = share_manager.submit_recovery_share(
            args.tx, args.caller_id, in.recovery_share);
        }
        catch (const std::logic_error& e)
        {
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            fmt::format("Could not submit recovery share: {}", e.what()));
        }

        if (submitted_shares_count < g.get_recovery_threshold())
        {
          // The number of shares required to re-assemble the secret has not yet
          // been reached
          return make_success(false);
        }

        LOG_DEBUG_FMT(
          "Reached secret sharing threshold {}", g.get_recovery_threshold());

        try
        {
          node.initiate_private_recovery(args.tx);
        }
        catch (const std::logic_error& e)
        {
          // For now, clear the submitted shares if combination fails.
          share_manager.clear_submitted_recovery_shares(args.tx);
          return make_error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            fmt::format("Failed to initiate private recovery: {}", e.what()));
        }

        share_manager.clear_submitted_recovery_shares(args.tx);
        return make_success(true);
      };
      make_handler(
        MemberProcs::SUBMIT_RECOVERY_SHARE,
        HTTP_POST,
        json_adapter(submit_recovery_share))
        .set_auto_schema<SubmitRecoveryShare, bool>()
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

        for (auto& [cert, k_encryption_key] : in.members_info)
        {
          g.add_member(cert, k_encryption_key);
        }

        g.set_recovery_threshold(in.recovery_threshold);

        g.add_consensus(in.consensus_type);

        share_manager.issue_shares(tx);

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
        if (in.consensus_type != ConsensusType::PBFT)
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
      make_handler(MemberProcs::CREATE, HTTP_POST, json_adapter(create))
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

    MemberHandlers member_handlers;
    Members* members;

  public:
    MemberRpcFrontend(
      NetworkTables& network,
      AbstractNodeState& node,
      ShareManager& share_manager) :
      RpcFrontend(
        *network.tables, member_handlers, &network.member_client_signatures),
      member_handlers(network, node, share_manager),
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

      ctx->session->caller_cert = caller.value().cert;
      return true;
    }

    virtual bool is_members_frontend() override
    {
      return true;
    }
  };
} // namespace ccf
