// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT
#include "doctest/doctest.h"
#include "ds/files.h"
#include "ds/logger.h"
#include "enclave/appinterface.h"
#include "genesisgen/genesisgen.h"
#include "node/clientsignatures.h"
#include "node/rpc/jsonrpc.h"
#include "node/rpc/memberfrontend.h"
#include "node/rpc/userfrontend.h"
#include "node_stub.h"
#include "runtime_config/default_whitelists.h"

#include <iostream>
#include <string>

extern "C"
{
#include <evercrypt/EverCrypt_AutoConfig2.h>
}

using namespace ccfapp;
using namespace ccf;
using namespace std;
using namespace jsonrpc;
using namespace nlohmann;

// used throughout
auto kp = tls::make_key_pair();
auto ca_mem = kp -> self_sign("CN=name_member");
auto verifier_mem = tls::make_verifier(ca_mem);
auto member_caller = verifier_mem -> raw_cert_data();

string get_script_path(string name)
{
  auto default_dir = "../src/runtime_config";
  auto dir = getenv("RUNTIME_CONFIG_DIR");
  stringstream ss;
  ss << (dir ? dir : default_dir) << "/" << name;
  return ss.str();
}
const auto gov_script_file = files::slurp_string(get_script_path("gov.lua"));

template <typename T>
auto mpack(T&& a)
{
  return pack(forward<T>(a), Pack::MsgPack);
}

template <typename T>
auto munpack(T&& a)
{
  return unpack(forward<T>(a), Pack::MsgPack);
}

void check_error(const nlohmann::json& j, const int expected)
{
  CHECK(j[ERR][CODE] == expected);
}

void check_success(const Response<bool> r, const bool expected = true)
{
  CHECK(r.result == expected);
}

void set_whitelists(GenesisGenerator& network)
{
  for (const auto& wl : default_whitelists)
    network.set_whitelist(wl.first, wl.second);
}

std::vector<uint8_t> sign_json(nlohmann::json j, tls::KeyPairPtr& kp_)
{
  auto contents = nlohmann::json::to_msgpack(j);
  return kp_->sign(contents);
}

json create_json_req(const json& params, const string& method_name)
{
  json j;
  j[JSON_RPC] = RPC_VERSION;
  j[ID] = 1;
  j[METHOD] = method_name;
  if (!params.is_null())
    j[PARAMS] = params;
  return j;
}

json create_json_req_signed(
  const json& params, const string& method_name, tls::KeyPairPtr& kp_)
{
  auto j = create_json_req(params, method_name);
  nlohmann::json sj;
  sj["req"] = j;
  auto sig = sign_json(j, kp_);
  sj["sig"] = sig;
  return sj;
}

template <typename T>
auto query_params(T script, bool compile)
{
  json params;
  if (compile)
    params["bytecode"] = lua::compile(script);
  else
    params["text"] = script;
  return params;
}

template <typename T>
auto read_params(const T& key, const string& table_name)
{
  json params;
  params["key"] = key;
  params["table"] = table_name;
  return params;
}

std::vector<uint8_t> get_cert_data(uint64_t member_id, tls::KeyPairPtr& kp_mem)
{
  std::vector<uint8_t> ca_mem =
    kp_mem->self_sign("CN=new member" + to_string(member_id));
  auto v_mem = tls::make_verifier(ca_mem);
  std::vector<uint8_t> cert_data = v_mem->raw_cert_data();
  return cert_data;
}

auto init_frontend(
  GenesisGenerator& network, StubNodeState& node, const int n_members)
{
  // create members with fake certs (no crypto here)
  for (uint8_t i = 0; i < n_members; i++)
    network.add_member({i}, MemberStatus::ACTIVE);

  set_whitelists(network);
  network.set_gov_scripts(lua::Interpreter().invoke<json>(gov_script_file));
  network.finalize_raw();
  return MemberCallRpcFrontend(network, node);
}

TEST_CASE("Member query/read")
{
  // initialize the network state
  const Cert mcert = {0};
  GenesisGenerator network;
  StubNodeState node;
  MemberCallRpcFrontend frontend(network, node);
  const auto mid = network.add_member(mcert, MemberStatus::ACCEPTED);
  network.finalize_raw();
  enclave::RPCContext rpc_ctx(0, nullb);

  // put value to read
  constexpr auto key = 123;
  constexpr auto value = 456;
  Store::Tx tx;
  tx.get_view(network.values)->put(key, value);
  CHECK(tx.commit() == kv::CommitSuccess::OK);

  static constexpr auto query = R"xxx(
  local tables = ...
  return tables["values"]:get(123)
  )xxx";

  SUBCASE("Query: bytecode/script allowed access")
  {
    // set member ACL so that the VALUES table is accessible
    Store::Tx tx;
    tx.get_view(network.whitelists)
      ->put(WlIds::MEMBER_CAN_READ, {Tables::VALUES});
    CHECK(tx.commit() == kv::CommitSuccess::OK);

    bool compile = true;
    do
    {
      Store::Tx tx;
      auto req = create_json_req(query_params(query, compile), "query");
      ccf::SignedReq sr(req);

      auto rep = frontend.process_json(rpc_ctx, tx, mid, req, sr);
      CHECK(rep.has_value());
      const Response<int> r = rep.value();
      CHECK(r.result == value);
      compile = !compile;
    } while (!compile);
  }

  SUBCASE("Query: table not in ACL")
  {
    // set member ACL so that no table is accessible
    Store::Tx tx;
    tx.get_view(network.whitelists)->put(WlIds::MEMBER_CAN_READ, {});
    CHECK(tx.commit() == kv::CommitSuccess::OK);

    Store::Tx tx1;
    auto req = create_json_req(query_params(query, true), "query");
    ccf::SignedReq sr(req);

    check_error(
      frontend.process_json(rpc_ctx, tx1, 0, req, sr).value(),
      ErrorCodes::SCRIPT_ERROR);
  }

  SUBCASE("Read: allowed access, key exists")
  {
    Store::Tx tx;
    tx.get_view(network.whitelists)
      ->put(WlIds::MEMBER_CAN_READ, {Tables::VALUES});
    CHECK(tx.commit() == kv::CommitSuccess::OK);

    Store::Tx tx1;
    auto read_call_j =
      create_json_req(read_params<int>(key, Tables::VALUES), "read");
    ccf::SignedReq sr(read_call_j);

    auto response = frontend.process_json(rpc_ctx, tx1, mid, read_call_j, sr);
    Response<int> r = response.value();
    CHECK(r.result == value);
  }

  SUBCASE("Read: allowed access, key doesn't exist")
  {
    constexpr auto wrong_key = 321;
    Store::Tx tx;
    tx.get_view(network.whitelists)
      ->put(WlIds::MEMBER_CAN_READ, {Tables::VALUES});
    CHECK(tx.commit() == kv::CommitSuccess::OK);

    Store::Tx tx1;
    auto read_call_j =
      create_json_req(read_params<int>(wrong_key, Tables::VALUES), "read");
    ccf::SignedReq sr(read_call_j);

    check_error(
      frontend.process_json(rpc_ctx, tx1, mid, read_call_j, sr).value(),
      ErrorCodes::INVALID_PARAMS);
  }

  SUBCASE("Read: access not allowed")
  {
    Store::Tx tx;
    tx.get_view(network.whitelists)->put(WlIds::MEMBER_CAN_READ, {});
    CHECK(tx.commit() == kv::CommitSuccess::OK);

    Store::Tx tx1;
    auto read_call_j =
      create_json_req(read_params<int>(key, Tables::VALUES), "read");
    ccf::SignedReq sr(read_call_j);

    check_error(
      frontend.process_json(rpc_ctx, tx1, 0, read_call_j, sr).value(),
      ErrorCodes::SCRIPT_ERROR);
  }
}

struct NewMember
{
  MemberId id;
  tls::KeyPairPtr kp = tls::make_key_pair();
  Cert cert;
};

TEST_CASE("Add new members until there are 7, then reject")
{
  constexpr auto initial_members = 3;
  constexpr auto n_new_members = 7;
  constexpr auto max_members = 8;
  GenesisGenerator network;
  StubNodeState node;
  // add three active members
  // the proposer
  network.add_member(vector<uint8_t>(member_caller), MemberStatus::ACTIVE);
  // the voter
  vector<uint8_t> voter = get_cert_data(1, kp);
  network.add_member(voter, MemberStatus::ACTIVE);
  network.add_member(get_cert_data(2, kp), MemberStatus::ACTIVE);

  set_whitelists(network);
  network.set_gov_scripts(lua::Interpreter().invoke<json>(gov_script_file));
  network.finalize_raw();
  MemberCallRpcFrontend frontend(network, node);

  vector<NewMember> new_members(n_new_members);

  auto i = 0ul;
  for (auto& new_member : new_members)
  {
    const auto proposal_id = i;
    new_member.id = initial_members + i++;
    // new member certificate
    auto v = tls::make_verifier(
      new_member.kp->self_sign(fmt::format("CN=new member{}", new_member.id)));
    const auto _cert = v->raw();
    new_member.cert = {_cert->raw.p, _cert->raw.p + _cert->raw.len};

    // check new_member id does not work before member is added
    enclave::RPCContext rpc_ctx(0, new_member.cert);
    const auto read_next_member_id = mpack(create_json_req(
      read_params<int>(ValueIds::NEXT_MEMBER_ID, Tables::VALUES), "read"));
    check_error(
      munpack(frontend.process(rpc_ctx, read_next_member_id)),
      ErrorCodes::INVALID_CALLER_ID);

    Script proposal(R"xxx(
      local tables, member_cert = ...
      return Calls:call("new_member", member_cert)
    )xxx");

    const auto proposej =
      create_json_req(Proposal::In{proposal, new_member.cert}, "propose");

    {
      Store::Tx tx;
      ccf::SignedReq sr(proposej);
      Response<Proposal::Out> r =
        frontend.process_json(rpc_ctx, tx, 0, proposej, sr).value();
      // the proposal should be accepted, but not succeed immediately
      CHECK(r.result.id == proposal_id);
      CHECK(r.result.completed == false);
    }

    Script vote_ballot(R"xxx(
        local tables, calls = ...
        local n = 0
        tables["members"]:foreach( function(k, v) n = n + 1 end )
        if n < 8 then
          return true
        else
          return false
        end
        )xxx");

    json votej =
      create_json_req_signed(Vote{proposal_id, vote_ballot}, "vote", kp);

    // vote from second member
    Store::Tx tx;
    enclave::RPCContext mem_rpc_ctx(0, member_caller);
    ccf::SignedReq sr(votej);
    Response<bool> r =
      frontend.process_json(mem_rpc_ctx, tx, 1, votej["req"], sr).value();
    if (new_member.id < max_members)
    {
      // vote should succeed
      CHECK(r.result);
      // check that member with the new new_member cert can make rpc's now
      CHECK(
        Response<int>(munpack(frontend.process(rpc_ctx, read_next_member_id)))
          .result == new_member.id + 1);
    }
    else
    {
      // vote should not succeed
      CHECK(!r.result);
      // check that member with the new new_member cert can make rpc's now
      check_error(
        munpack(frontend.process(rpc_ctx, read_next_member_id)),
        ErrorCodes::INVALID_CALLER_ID);
    }
  }

  SUBCASE("ACK from newly added members")
  {
    // iterate over all new_members, except for the last one
    for (auto new_member = new_members.cbegin(); new_member !=
         new_members.cend() - (initial_members + n_new_members - max_members);
         new_member++)
    {
      enclave::RPCContext rpc_ctx(0, new_member->cert);

      // (1) read ack entry
      const auto read_nonce = mpack(create_json_req(
        read_params(new_member->id, Tables::MEMBER_ACKS), "read"));
      const Response<MemberAck> ack0 =
        munpack(frontend.process(rpc_ctx, read_nonce));
      // (2) ask for a fresher nonce
      const auto freshen_nonce =
        mpack(create_json_req(nullptr, "updateAckNonce"));
      check_success(munpack(frontend.process(rpc_ctx, freshen_nonce)));
      // (3) read ack entry again and check that the nonce has changed
      const Response<MemberAck> ack1 =
        munpack(frontend.process(rpc_ctx, read_nonce));
      CHECK(ack0.result.next_nonce != ack1.result.next_nonce);
      // (4) sign old nonce and send it
      const auto bad_sig =
        RawSignature{new_member->kp->sign(ack0.result.next_nonce)};
      const auto send_bad_sig = mpack(create_json_req(bad_sig, "ack"));
      check_error(
        munpack(frontend.process(rpc_ctx, send_bad_sig)),
        jsonrpc::INVALID_PARAMS);
      // (5) sign new nonce and send it
      const auto good_sig =
        RawSignature{new_member->kp->sign(ack1.result.next_nonce)};
      const auto send_good_sig = mpack(create_json_req(good_sig, "ack"));
      check_success(munpack(frontend.process(rpc_ctx, send_good_sig)));
      // (6) read ack entry again and check that the signature matches
      const Response<MemberAck> ack2 =
        munpack(frontend.process(rpc_ctx, read_nonce));
      CHECK(ack2.result.sig == good_sig.sig);
      // (7) read own member status
      const auto read_status = mpack(
        create_json_req(read_params(new_member->id, Tables::MEMBERS), "read"));
      const Response<MemberInfo> mi =
        munpack(frontend.process(rpc_ctx, read_status));
      CHECK(mi.result.status == MemberStatus::ACTIVE);
    }
  }
}

TEST_CASE("Accept node")
{
  GenesisGenerator network;
  StubNodeState node;
  auto new_kp = tls::make_key_pair();

  const Cert mcert0 = get_cert_data(0, new_kp), mcert1 = get_cert_data(1, kp);
  const auto mid0 = network.add_member(mcert0, MemberStatus::ACTIVE);
  const auto mid1 = network.add_member(mcert1, MemberStatus::ACTIVE);
  enclave::RPCContext rpc_ctx(0, mcert1);

  // node to be tested
  // new node certificate
  auto new_ca = new_kp->self_sign("CN=new node");
  NodeInfo ni = {"", "", "", "", new_ca, {}};
  network.add_node(ni);
  set_whitelists(network);
  network.set_gov_scripts(lua::Interpreter().invoke<json>(gov_script_file));
  network.finalize_raw();
  MemberCallRpcFrontend frontend(network, node);
  auto node_id = 0;
  // check node exists with status pending
  {
    Store::Tx tx;
    auto read_values_j =
      create_json_req(read_params<int>(node_id, Tables::NODES), "read");
    ccf::SignedReq sr(read_values_j);

    Response<NodeInfo> r =
      frontend.process_json(rpc_ctx, tx, mid0, read_values_j, sr).value();
    CHECK(r.result.status == NodeStatus::PENDING);
  }
  // m0 proposes adding new node
  {
    Script proposal(R"xxx(
      local tables, node_id = ...
      return Calls:call("accept_node", node_id)
    )xxx");

    json proposej = create_json_req(Proposal::In{proposal, node_id}, "propose");
    ccf::SignedReq sr(proposej);

    Store::Tx tx;
    Response<Proposal::Out> r =
      frontend.process_json(rpc_ctx, tx, mid0, proposej, sr).value();
    CHECK(!r.result.completed);
    CHECK(r.result.id == 0);
  }
  // m1 votes for accepting a single new node
  {
    Script vote_ballot(R"xxx(
        local tables, calls = ...
        return #calls == 1 and calls[1].func == "accept_node"
       )xxx");

    json votej = create_json_req_signed(Vote{0, vote_ballot}, "vote", kp);
    ccf::SignedReq sr(votej);

    Store::Tx tx;
    check_success(
      frontend.process_json(rpc_ctx, tx, mid1, votej["req"], sr).value());
  }
  // check node exists with status pending
  {
    Store::Tx tx;
    auto read_values_j =
      create_json_req(read_params<int>(node_id, Tables::NODES), "read");
    ccf::SignedReq sr(read_values_j);

    Response<NodeInfo> r =
      frontend.process_json(rpc_ctx, tx, mid0, read_values_j, sr).value();
    CHECK(r.result.status == NodeStatus::TRUSTED);
  }
}

bool test_raw_writes(
  GenesisGenerator& network,
  StubNodeState& node,
  Proposal::In proposal,
  const int n_members = 1,
  const int pro_votes = 1,
  bool explicit_proposer_vote = false)
{
  enclave::RPCContext rpc_ctx(0, nullb);
  auto frontend = init_frontend(network, node, n_members);
  // check values before
  {
    Store::Tx tx;
    auto next_member_id_r =
      tx.get_view(network.values)->get(ValueIds::NEXT_MEMBER_ID);
    CHECK(next_member_id_r);
    CHECK(*next_member_id_r == n_members);
  }
  // propose
  const auto proposal_id = 0ul;
  {
    const uint8_t proposer_id = 0;
    json proposej = create_json_req(proposal, "propose");
    ccf::SignedReq sr(proposej);

    Store::Tx tx;
    Response<Proposal::Out> r =
      frontend.process_json(rpc_ctx, tx, proposer_id, proposej, sr).value();
    CHECK(r.result.completed == (n_members == 1));
    CHECK(r.result.id == proposal_id);
    if (r.result.completed)
      return true;
  }
  // con votes
  for (int i = n_members - 1; i >= pro_votes; i--)
  {
    auto mem_cert = get_cert_data(i, kp);
    enclave::RPCContext mem_rpc_ctx(0, mem_cert);
    const Script vote("return false");
    json votej = create_json_req_signed(Vote{proposal_id, vote}, "vote", kp);
    ccf::SignedReq sr(votej);

    Store::Tx tx;
    check_success(
      frontend.process_json(mem_rpc_ctx, tx, i, votej["req"], sr).value(),
      false);
  }
  // pro votes (proposer also votes)
  bool completed = false;
  for (uint8_t i = explicit_proposer_vote ? 0 : 1; i < pro_votes; i++)
  {
    const Script vote("return true");
    json votej = create_json_req_signed(Vote{proposal_id, vote}, "vote", kp);
    ccf::SignedReq sr(votej);

    Store::Tx tx;
    auto mem_cert = get_cert_data(i, kp);
    enclave::RPCContext mem_rpc_ctx(0, mem_cert);
    if (!completed)
    {
      completed =
        Response<bool>(
          frontend.process_json(mem_rpc_ctx, tx, i, votej["req"], sr).value())
          .result;
    }
    else
    {
      // proposal does not exist anymore, because it completed -> invalid params
      check_error(
        frontend.process_json(mem_rpc_ctx, tx, i, votej["req"], sr).value(),
        ErrorCodes::INVALID_PARAMS);
    }
  }
  return completed;
}

TEST_CASE("Propose raw writes")
{
  SUBCASE("insensitive tables")
  {
    const auto n_members = 10;
    for (int pro_votes = 0; pro_votes <= n_members; pro_votes++)
    {
      const bool should_succeed = pro_votes > n_members / 2;
      GenesisGenerator network;
      StubNodeState node;
      // manually add a member in state active (not recommended)
      const Cert mcert = {1, 2, 3};
      CHECK(
        test_raw_writes(
          network,
          node,
          {R"xxx(
        local tables, cert = ...
        local STATE_ACTIVE = 1
        local NEXT_MEMBER_ID_VALUE = 0
        local p = Puts:new()
        -- get id
        local member_id = tables["values"]:get(NEXT_MEMBER_ID_VALUE)
        -- increment id
        p:put("values", NEXT_MEMBER_ID_VALUE, member_id + 1)
        -- write member cert and status
        p:put("members", member_id, {status = STATE_ACTIVE})
        p:put("membercerts", cert, member_id)
        return Calls:call("raw_puts", p)
      )xxx"s,
           mcert},
          n_members,
          pro_votes) == should_succeed);
      if (!should_succeed)
        continue;

      // check results
      Store::Tx tx;
      const auto next_mid =
        tx.get_view(network.values)->get(ValueIds::NEXT_MEMBER_ID);
      CHECK(next_mid);
      CHECK(*next_mid == n_members + 1);
      const auto m = tx.get_view(network.members)->get(n_members);
      CHECK(m);
      CHECK(m->status == MemberStatus::ACTIVE);
      const auto mid = tx.get_view(network.member_certs)->get(mcert);
      CHECK(mid);
      CHECK(*mid == n_members);
    }
  }

  SUBCASE("sensitive tables")
  {
    // propose changes to sensitive tables; changes must only be accepted
    // unanimously create new network for each case
    const auto sensitive_tables = {Tables::WHITELISTS, Tables::GOV_SCRIPTS};
    const auto n_members = 10;
    // let proposer vote/not vote
    for (const auto proposer_vote : {true, false})
    {
      for (int pro_votes = 0; pro_votes < n_members; pro_votes++)
      {
        for (const auto& sensitive_table : sensitive_tables)
        {
          GenesisGenerator network;
          StubNodeState node;

          const auto sensitive_put =
            "return Calls:call('raw_puts', Puts:put('"s + sensitive_table +
            "', 9, {'aaa'}))"s;
          CHECK(
            test_raw_writes(
              network,
              node,
              {sensitive_put},
              n_members,
              pro_votes,
              proposer_vote) == (n_members == pro_votes));
        }
      }
    }
  }
}

TEST_CASE("Remove proposal")
{
  NewMember caller;
  auto v = tls::make_verifier(caller.kp->self_sign("CN=new member"));
  caller.cert = v->raw_cert_data();

  GenesisGenerator network;
  StubNodeState node;
  enclave::RPCContext rpc_ctx(0, nullb);
  network.add_member(member_caller, MemberStatus::ACTIVE);
  network.add_member(caller.cert, MemberStatus::ACTIVE);
  set_whitelists(network);
  network.set_gov_scripts(lua::Interpreter().invoke<json>(gov_script_file));
  network.finalize_raw();
  MemberCallRpcFrontend frontend(network, node);
  auto proposal_id = 0;
  auto wrong_proposal_id = 1;
  ccf::Script proposal_script(R"xxx(
      local tables, param = ...
      return {}
    )xxx");

  // check that the proposal doesn't exist
  {
    Store::Tx tx;
    auto proposal = tx.get_view(network.proposals)->get(proposal_id);
    CHECK(!proposal);
  }

  {
    json proposej =
      create_json_req(Proposal::In{proposal_script, 0}, "propose");
    ccf::SignedReq sr(proposej);

    Store::Tx tx;
    Response<Proposal::Out> r =
      frontend.process_json(rpc_ctx, tx, 0, proposej, sr).value();
    CHECK(r.result.id == proposal_id);
    CHECK(!r.result.completed);
  }
  // check that the proposal is there
  {
    Store::Tx tx;
    auto proposal = tx.get_view(network.proposals)->get(proposal_id);
    REQUIRE(proposal);
    CHECK(proposal->script.text.value() == proposal_script.text.value());
  }
  SUBCASE("Attempt remove proposal with non existing id")
  {
    Store::Tx tx;
    json param;
    param["id"] = wrong_proposal_id;
    json removalj = create_json_req(param, "removal");
    ccf::SignedReq sr(removalj);

    check_error(
      frontend.process_json(rpc_ctx, tx, 0, removalj, sr).value(),
      ErrorCodes::INVALID_PARAMS);
  }
  SUBCASE("Attempt remove proposal that you didn't propose")
  {
    Store::Tx tx;
    json param;
    param["id"] = proposal_id;
    json removalj = create_json_req(param, "removal");
    ccf::SignedReq sr(removalj);

    check_error(
      frontend.process_json(rpc_ctx, tx, 1, removalj, sr).value(),
      ErrorCodes::INVALID_REQUEST);
  }
  SUBCASE("Successfully remove proposal")
  {
    Store::Tx tx;
    json param;
    param["id"] = proposal_id;
    json removalj = create_json_req(param, "removal");
    ccf::SignedReq sr(removalj);

    check_success(frontend.process_json(rpc_ctx, tx, 0, removalj, sr).value());
    // check that the proposal doesn't exist anymore
    {
      Store::Tx tx;
      auto proposal = tx.get_view(network.proposals)->get(proposal_id);
      CHECK(!proposal);
    }
  }
}

TEST_CASE("Complete proposal after initial rejection")
{
  GenesisGenerator network;
  StubNodeState node;
  auto frontend = init_frontend(network, node, 3);
  const Cert m0 = {0}, m1 = get_cert_data(1, kp);
  enclave::RPCContext rpc_ctx(0, m1);
  // propose
  {
    const auto proposal =
      "return Calls:call('raw_puts', Puts:put('values', 999, 999))"s;
    const auto proposej = create_json_req(Proposal::In{proposal}, "propose");
    ccf::SignedReq sr(proposej);

    Store::Tx tx;
    Response<Proposal::Out> r =
      frontend.process_json(rpc_ctx, tx, 0, proposej, sr).value();
    CHECK(r.result.completed == false);
  }
  // vote that rejects initially
  {
    const Script vote(R"xxx(
    local tables = ...
    return tables["values"]:get(123) == 123
    )xxx");
    const auto votej = create_json_req_signed(Vote{0, vote}, "vote", kp);
    ccf::SignedReq sr(votej);

    Store::Tx tx;
    check_success(
      frontend.process_json(rpc_ctx, tx, 1, votej["req"], sr).value(), false);
  }
  // try to complete
  {
    const auto completej = create_json_req(ProposalAction{0}, "complete");
    ccf::SignedReq sr(completej);

    Store::Tx tx;
    check_error(
      frontend.process_json(rpc_ctx, tx, 1, completej, sr).value(),
      ErrorCodes::DENIED);
  }
  // put value that makes vote agree
  {
    Store::Tx tx;
    tx.get_view(network.values)->put(123, 123);
    CHECK(tx.commit() == kv::CommitSuccess::OK);
  }
  // try again to complete
  {
    const auto completej = create_json_req(ProposalAction{0}, "complete");
    ccf::SignedReq sr(completej);

    Store::Tx tx;
    check_success(frontend.process_json(rpc_ctx, tx, 1, completej, sr).value());
  }
}

TEST_CASE("Add user via proposed call")
{
  GenesisGenerator network;
  StubNodeState node;
  enclave::RPCContext rpc_ctx(0, nullb);
  network.add_member(Cert{0}, MemberStatus::ACTIVE);
  set_whitelists(network);
  network.set_gov_scripts(lua::Interpreter().invoke<json>(gov_script_file));
  network.finalize_raw();
  MemberCallRpcFrontend frontend(network, node);

  Script proposal(R"xxx(
    tables, user_cert = ...
      return Calls:call("new_user", user_cert)
    )xxx");

  const vector<uint8_t> user_cert = {1, 2, 3};
  json proposej = create_json_req(Proposal::In{proposal, user_cert}, "propose");
  ccf::SignedReq sr(proposej);

  Store::Tx tx;
  Response<Proposal::Out> r =
    frontend.process_json(rpc_ctx, tx, 0, proposej, sr).value();
  CHECK(r.result.completed);
  CHECK(r.result.id == 0);

  Store::Tx tx1;
  const auto uid = tx1.get_view(network.values)->get(ValueIds::NEXT_USER_ID);
  REQUIRE(uid);
  CHECK(*uid == 1);
  const auto uid1 = tx1.get_view(network.user_certs)->get(user_cert);
  REQUIRE(uid1);
  CHECK(*uid1 == 0);
}

// We need an explicit main to initialize kremlib and EverCrypt
int main(int argc, char** argv)
{
  doctest::Context context;
  context.applyCommandLine(argc, argv);
  ::EverCrypt_AutoConfig2_init();
  int res = context.run();
  if (context.shouldExit())
    return res;
  return res;
}