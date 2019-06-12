// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "frontend.h"
#include "luainterp/txscriptrunner.h"
#include "tls/entropy.h"
#include "tls/keypair.h"

#include <exception>
#include <initializer_list>
#include <map>
#include <memory>
#include <set>
#include <sstream>

namespace ccf
{
  class MemberCallRpcFrontend : public RpcFrontend
  {
  private:
    Script get_script(Store::Tx& tx, std::string name)
    {
      const auto s = tx.get_view(network.gov_scripts)->get(name);
      if (!s)
        throw std::logic_error(
          std::string("Could not find gov script: ") + name);
      return *s;
    }

    //! Table of functions that proposal scripts can propose to invoke
    const std::unordered_map<
      std::string,
      std::function<bool(Store::Tx&, const nlohmann::json&)>>
      hardcoded_funcs = {
        // add a new member
        {"new_member",
         [this](Store::Tx& tx, const nlohmann::json& args) {
           const Cert cert = args;
           auto mc = tx.get_view(this->network.member_certs);
           // the cert needs to be unique
           if (mc->get(cert))
             throw std::logic_error("Certificate already exists");

           const auto id = get_next_id(
             tx.get_view(this->network.values), ValueIds::NEXT_MEMBER_ID);
           // store cert
           mc->put(cert, id);
           // set state to ACCEPTED
           tx.get_view(this->network.members)
             ->put(id, {MemberStatus::ACCEPTED});
           // create nonce for ACK
           tx.get_view(this->network.member_acks)
             ->put(id, {rng.random(SIZE_NONCE)});
           return true;
         }},
        // accept a node
        {"accept_node",
         [this](Store::Tx& tx, const nlohmann::json& args) {
           const auto id = args;
           auto nodes = tx.get_view(this->network.nodes);
           auto info = nodes->get(id);
           if (!info)
             throw std::logic_error("Node does not exist.");
           info->status = NodeStatus::TRUSTED;
           nodes->put(id, *info);
           return true;
         }},
        // initiate end of recovery
        // TODO(#important): for now, recovery assumes that no leader
        // change can happen between the time the public CFTR is established and
        // this function is called.
        {"accept_recovery", [this](Store::Tx& tx, const nlohmann::json& args) {
           if (node.is_part_of_public_network())
             return node.finish_recovery(tx, args);
           else
             return false;
         }}};

    bool complete_proposal(Store::Tx& tx, const ObjectId id)
    {
      auto proposals = tx.get_view(this->network.proposals);
      const auto proposal = proposals->get(id);
      if (!proposal)
        throw std::logic_error("No proposal");

      // run proposal script
      const auto proposed_calls = tsr.run<nlohmann::json>(
        tx,
        {proposal->script,
         {}, // can't write
         WlIds::MEMBER_CAN_READ,
         get_script(tx, GovScriptIds::ENV_PROPOSAL)},
        // vvv arguments to script vvv
        proposal->parameter);

      // pass the effects to the quorum script
      const auto quorum = tsr.run<int>(
        tx,
        {get_script(tx, GovScriptIds::QUORUM),
         {}, // can't write
         WlIds::MEMBER_CAN_READ,
         {}},
        // vvv arguments to script vvv
        proposed_calls);

      /* count the votes
       * if the proposer hasn't explicitly voted and is still active,
       * an implicit pro vote is assumed.
       */
      bool explicit_proposer_vote = false;
      uint64_t pro = 0, con = 0;
      const uint64_t total = proposal->votes.size();
      for (const auto& vote : proposal->votes)
      {
        // can the proposal still succeed? If we haven't seen the proposer's
        // vote yet, assume it to be pro.
        if (total - con + (explicit_proposer_vote ? 0 : 1) < quorum)
          return false;

        // is this an explicit proposer vote?
        if (vote.first == proposal->proposer)
          explicit_proposer_vote = true;

        // valid voter
        if (!check_member_active(tx, vote.first))
          continue;

        // does the voter agree?
        if (tsr.run<bool>(
              tx,
              {vote.second,
               {}, // can't write
               WlIds::MEMBER_CAN_READ,
               {}},
              proposed_calls))
          pro++;
        else
          con++;
      }
      if (
        !explicit_proposer_vote && check_member_active(tx, proposal->proposer))
        pro++;

      if (pro < quorum)
        return false;

      // execute proposed calls
      ProposedCalls pc = proposed_calls;
      for (const auto& call : pc)
      {
        // proposing a hardcoded C++ function?
        const auto f = hardcoded_funcs.find(call.func);
        if (f != hardcoded_funcs.end())
        {
          if (!f->second(tx, call.args))
            return false;
          continue;
        }

        // proposing a script function?
        const auto s = tx.get_view(network.gov_scripts)->get(call.func);
        if (!s)
          continue;
        tsr.run<void>(
          tx,
          {*s,
           WlIds::MEMBER_CAN_PROPOSE, // can write!
           {},
           {}},
          call.args);
      }

      // if the vote was successful, remove the proposal
      proposals->remove(id);
      return true;
    }

    bool check_member_active(Store::Tx& tx, MemberId id)
    {
      return check_member_status(tx, id, {MemberStatus::ACTIVE});
    }

    bool check_member_accepted(Store::Tx& tx, MemberId id)
    {
      return check_member_status(
        tx, id, {MemberStatus::ACTIVE, MemberStatus::ACCEPTED});
    }

    bool check_member_status(
      Store::Tx& tx, MemberId id, std::initializer_list<MemberStatus> allowed)
    {
      auto member = tx.get_view(this->network.members)->get(id);
      if (!member)
        return false;
      for (const auto s : allowed)
        if (member->status == s)
          return true;
      return false;
    }

    NetworkTables& network;
    AbstractNodeState& node;
    const lua::TxScriptRunner tsr;

    tls::Entropy rng;
    static constexpr auto SIZE_NONCE = 16;

  public:
    MemberCallRpcFrontend(NetworkTables& network, AbstractNodeState& node) :
      RpcFrontend(
        *network.tables,
        &network.member_client_signatures,
        &network.member_certs),
      network(network),
      node(node),
      tsr(network)
    {
      using jerr = jsonrpc::ErrorCodes;
      auto read = [this](RequestArgs& args) {
        if (!check_member_status(
              args.tx,
              args.caller_id,
              {MemberStatus::ACTIVE, MemberStatus::ACCEPTED}))
          return jsonrpc::error(jerr::INSUFFICIENT_RIGHTS);

        const auto in = args.params.get<KVRead::In>();

        const ccf::Script read_script(R"xxx(
        local tables, table_name, key = ...
        return tables[table_name]:get(key) or {}
        )xxx");

        const auto value = tsr.run<nlohmann::json>(
          args.tx,
          {read_script, {}, WlIds::MEMBER_CAN_READ, {}},
          in.table,
          in.key);
        if (value.empty())
          return jsonrpc::error(jerr::INVALID_PARAMS, "key does not exist");
        return jsonrpc::success(value);
      };
      install_with_auto_schema<KVRead>(MemberProcs::READ, read, Read);

      auto query = [this](RequestArgs& args) {
        if (!check_member_accepted(args.tx, args.caller_id))
          return jsonrpc::error(jerr::INSUFFICIENT_RIGHTS);

        const auto script = args.params.get<ccf::Script>();
        return jsonrpc::success(tsr.run<nlohmann::json>(
          args.tx, {script, {}, WlIds::MEMBER_CAN_READ, {}}));
      };
      install_with_auto_schema<Script, nlohmann::json>(
        MemberProcs::QUERY, query, Read);

      auto propose = [this](RequestArgs& args) {
        if (!check_member_active(args.tx, args.caller_id))
          return jsonrpc::error(jerr::INSUFFICIENT_RIGHTS);

        const auto in = args.params.get<Proposal::In>();
        const auto proposal_id = get_next_id(
          args.tx.get_view(this->network.values), ValueIds::NEXT_PROPOSAL_ID);
        args.tx.get_view(this->network.proposals)
          ->put(proposal_id, {args.caller_id, in});
        const bool completed = complete_proposal(args.tx, proposal_id);
        return jsonrpc::success<Proposal::Out>({proposal_id, completed});
      };
      install_with_auto_schema<Proposal>(MemberProcs::PROPOSE, propose, Write);

      auto removal = [this](RequestArgs& args) {
        if (!check_member_status(
              args.tx, args.caller_id, {MemberStatus::ACTIVE}))
          return jsonrpc::error(jerr::INSUFFICIENT_RIGHTS);

        const auto proposal_action = args.params.get<ProposalAction>();
        const auto proposal_id = proposal_action.id;
        auto proposals = args.tx.get_view(this->network.proposals);
        const auto proposal = proposals->get(proposal_id);

        if (!proposal)
          return jsonrpc::error(
            jerr::INVALID_PARAMS, "Proposal does not exist");

        if (proposal->proposer != args.caller_id)
          return jsonrpc::error(
            jerr::INVALID_REQUEST,
            "Proposals can only be removed by proposer.");

        proposals->remove(proposal_id);
        return jsonrpc::success(true);
      };
      install_with_auto_schema<ProposalAction, bool>(
        MemberProcs::REMOVAL, removal, Write);

      auto vote = [this](RequestArgs& args) {
        if (!check_member_active(args.tx, args.caller_id))
          return jsonrpc::error(jerr::INSUFFICIENT_RIGHTS);

        if (args.signed_request.sig.empty())
          return jsonrpc::error(jerr::RPC_NOT_SIGNED);

        const auto vote = args.params.get<Vote>();
        auto proposals = args.tx.get_view(this->network.proposals);
        auto proposal = proposals->get(vote.id);
        if (!proposal)
          return jsonrpc::error(
            jerr::INVALID_PARAMS, "Proposal does not exist");

        // record vote
        proposal->votes[args.caller_id] = vote.ballot;
        proposals->put(vote.id, *proposal);

        auto voting_history = args.tx.get_view(this->network.voting_history);
        voting_history->put(args.caller_id, {args.signed_request});

        return jsonrpc::success(complete_proposal(args.tx, vote.id));
      };
      install_with_auto_schema<Vote, bool>(MemberProcs::VOTE, vote, Write);

      auto complete = [this](RequestArgs& args) {
        if (!check_member_active(args.tx, args.caller_id))
          return jsonrpc::error(jerr::INSUFFICIENT_RIGHTS);

        const auto proposal_action = args.params.get<ProposalAction>();
        const auto proposal_id = proposal_action.id;
        if (!complete_proposal(args.tx, proposal_id))
          return jsonrpc::error(jerr::DENIED);
        return jsonrpc::success(true);
      };
      install_with_auto_schema<ProposalAction, bool>(
        MemberProcs::COMPLETE, complete, Write);

      //! A member acknowledges state
      auto ack = [this](RequestArgs& args) {
        // TODO(#feature): sign and verify Merkle tree roots instead of
        // nonce as is done in the paper.
        auto mas = args.tx.get_view(this->network.member_acks);
        const auto last_ma = mas->get(args.caller_id);
        if (!last_ma)
          return jsonrpc::error(
            jsonrpc::ErrorCodes::INVALID_PARAMS, "No ACK record exists (1)");

        tls::Verifier v((std::vector<uint8_t>(args.rpc_ctx.caller_cert)));
        const auto rs = args.params.get<RawSignature>();
        if (!v.verify_hash(crypto::Sha256Hash{last_ma->next_nonce}, rs.sig))
          return jsonrpc::error(jerr::INVALID_PARAMS, "Signature is not valid");

        MemberAck next_ma{rs.sig, rng.random(SIZE_NONCE)};
        mas->put(args.caller_id, next_ma);

        // update member status to ACTIVE
        auto members = args.tx.get_view(this->network.members);
        auto member = members->get(args.caller_id);
        if (member->status == MemberStatus::ACCEPTED)
          member->status = MemberStatus::ACTIVE;
        members->put(args.caller_id, *member);
        return jsonrpc::success(true);
      };
      // ACK method cannot be forwarded and should be run on leader as it makes
      // explicit use of caller certificate
      install_with_auto_schema<RawSignature, bool>(
        MemberProcs::ACK, ack, Write, Forwardable::DoNotForward);

      //! A member asks for a fresher nonce
      auto update_ack_nonce = [this](RequestArgs& args) {
        auto mas = args.tx.get_view(this->network.member_acks);
        auto ma = mas->get(args.caller_id);
        if (!ma)
          return jsonrpc::error(
            jsonrpc::ErrorCodes::INVALID_PARAMS, "No ACK record exists (2)");
        ma->next_nonce = rng.random(SIZE_NONCE);
        mas->put(args.caller_id, *ma);
        return jsonrpc::success(true);
      };
      install_with_auto_schema<void, bool>(
        MemberProcs::UPDATE_ACK_NONCE, update_ack_nonce, Write);
    }
  };
} // namespace ccf
