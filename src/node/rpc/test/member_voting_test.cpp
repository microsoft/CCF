// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT
#define DOCTEST_CONFIG_NO_SHORT_MACRO_NAMES
#include "ds/files.h"
#include "ds/logger.h"
#include "enclave/app_interface.h"
#include "node/client_signatures.h"
#include "node/encryptor.h"
#include "node/genesis_gen.h"
#include "node/rpc/json_rpc.h"
#include "node/rpc/member_frontend.h"
#include "node/rpc/user_frontend.h"
#include "node_stub.h"
#include "runtime_config/default_whitelists.h"

#include <doctest/doctest.h>
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

using TResponse = http::SimpleResponseProcessor::Response;

// used throughout
auto kp = tls::make_key_pair();
auto member_cert = kp -> self_sign("CN=name_member");
auto verifier_mem = tls::make_verifier(member_cert);
auto member_caller = verifier_mem -> der_cert_data();
auto user_cert = kp -> self_sign("CN=name_user");
std::vector<uint8_t> dummy_key_share = {1, 2, 3};

auto encryptor = std::make_shared<ccf::NullTxEncryptor>();

constexpr auto default_pack = jsonrpc::Pack::Text;

string get_script_path(string name)
{
  auto default_dir = "../src/runtime_config";
  auto dir = getenv("RUNTIME_CONFIG_DIR");
  stringstream ss;
  ss << (dir ? dir : default_dir) << "/" << name;
  return ss.str();
}
const auto gov_script_file = files::slurp_string(get_script_path("gov.lua"));
const auto gov_veto_script_file =
  files::slurp_string(get_script_path("gov_veto.lua"));
const auto operator_gov_script_file =
  files::slurp_string(get_script_path("operator_gov.lua"));

template <typename T>
T parse_response_body(const TResponse& r)
{
  const auto body_j = jsonrpc::unpack(r.body, jsonrpc::Pack::Text);
  return body_j.get<T>();
}

void check_error(const TResponse& r, http_status expected)
{
  DOCTEST_CHECK(r.status == expected);
}

void check_result_state(const TResponse& r, ProposalState expected)
{
  DOCTEST_CHECK(r.status == HTTP_STATUS_OK);
  const auto result = parse_response_body<ProposalInfo>(r);
  DOCTEST_CHECK(result.state == expected);
}

void set_whitelists(GenesisGenerator& gen)
{
  for (const auto& wl : default_whitelists)
    gen.set_whitelist(wl.first, wl.second);
}

std::vector<uint8_t> sign_json(nlohmann::json j, tls::KeyPairPtr& kp_)
{
  auto contents = nlohmann::json::to_msgpack(j);
  return kp_->sign(contents);
}

std::vector<uint8_t> create_request(
  const json& params, const string& method_name)
{
  http::Request r(method_name);
  const auto body = params.is_null() ? std::vector<uint8_t>() :
                                       jsonrpc::pack(params, default_pack);
  r.set_body(&body);
  return r.build_request();
}

std::vector<uint8_t> create_signed_request(
  const json& params, const string& method_name, const tls::KeyPairPtr& kp_)
{
  http::Request r(method_name);

  const auto body = params.is_null() ? std::vector<uint8_t>() :
                                       jsonrpc::pack(params, default_pack);

  r.set_body(&body);
  http::sign_request(r, kp_);

  return r.build_request();
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

auto frontend_process(
  MemberRpcFrontend& frontend,
  const std::vector<uint8_t>& serialized_request,
  const Cert& caller)
{
  auto session = std::make_shared<enclave::SessionContext>(
    0, tls::make_verifier(caller)->der_cert_data());
  auto rpc_ctx = enclave::make_rpc_context(session, serialized_request);
  auto serialized_response = frontend.process(rpc_ctx);

  DOCTEST_CHECK(serialized_response.has_value());

  http::SimpleResponseProcessor processor;
  http::ResponseParser parser(processor);

  const auto parsed_count =
    parser.execute(serialized_response->data(), serialized_response->size());
  DOCTEST_REQUIRE(parsed_count == serialized_response->size());
  DOCTEST_REQUIRE(processor.received.size() == 1);

  return processor.received.front();
}

auto get_proposal(
  MemberRpcFrontend& frontend, size_t proposal_id, const Cert& caller)
{
  Script read_proposal(fmt::format(
    R"xxx(
      tables = ...
      return tables["ccf.proposals"]:get({})
    )xxx",
    proposal_id));

  const auto read = create_request(read_proposal, "query");

  return parse_response_body<Proposal>(
    frontend_process(frontend, read, caller));
}

std::vector<uint8_t> get_cert_data(uint64_t member_id, tls::KeyPairPtr& kp_mem)
{
  return kp_mem->self_sign("CN=new member" + to_string(member_id));
}

auto init_frontend(
  NetworkTables& network,
  GenesisGenerator& gen,
  StubNodeState& node,
  const int n_members,
  std::vector<std::vector<uint8_t>>& member_certs)
{
  // create members
  for (uint8_t i = 0; i < n_members; i++)
  {
    member_certs.push_back(get_cert_data(i, kp));
    gen.add_member(member_certs.back(), {}, MemberStatus::ACTIVE);
  }

  set_whitelists(gen);
  gen.set_gov_scripts(lua::Interpreter().invoke<json>(gov_script_file));
  gen.finalize();

  return MemberRpcFrontend(network, node);
}

DOCTEST_TEST_CASE("Member query/read")
{
  // initialize the network state
  NetworkTables network;
  Store::Tx gen_tx;
  GenesisGenerator gen(network, gen_tx);
  gen.init_values();
  StubNodeState node;
  MemberRpcFrontend frontend(network, node);
  frontend.open();
  const auto member_id =
    gen.add_member(member_cert, {}, MemberStatus::ACCEPTED);
  gen.finalize();

  const enclave::SessionContext member_session(
    enclave::InvalidSessionId, member_cert);

  // put value to read
  constexpr auto key = 123;
  constexpr auto value = 456;
  Store::Tx tx;
  tx.get_view(network.values)->put(key, value);
  DOCTEST_CHECK(tx.commit() == kv::CommitSuccess::OK);

  static constexpr auto query = R"xxx(
  local tables = ...
  return tables["ccf.values"]:get(123)
  )xxx";

  DOCTEST_SUBCASE("Query: bytecode/script allowed access")
  {
    // set member ACL so that the VALUES table is accessible
    Store::Tx tx;
    tx.get_view(network.whitelists)
      ->put(WlIds::MEMBER_CAN_READ, {Tables::VALUES});
    DOCTEST_CHECK(tx.commit() == kv::CommitSuccess::OK);

    bool compile = true;
    do
    {
      const auto req = create_request(query_params(query, compile), "query");
      const auto r = frontend_process(frontend, req, member_cert);
      const auto result = parse_response_body<int>(r);
      DOCTEST_CHECK(result == value);
      compile = !compile;
    } while (!compile);
  }

  DOCTEST_SUBCASE("Query: table not in ACL")
  {
    // set member ACL so that no table is accessible
    Store::Tx tx;
    tx.get_view(network.whitelists)->put(WlIds::MEMBER_CAN_READ, {});
    DOCTEST_CHECK(tx.commit() == kv::CommitSuccess::OK);

    auto req = create_request(query_params(query, true), "query");
    const auto response = frontend_process(frontend, req, member_cert);

    check_error(response, HTTP_STATUS_INTERNAL_SERVER_ERROR);
  }

  DOCTEST_SUBCASE("Read: allowed access, key exists")
  {
    Store::Tx tx;
    tx.get_view(network.whitelists)
      ->put(WlIds::MEMBER_CAN_READ, {Tables::VALUES});
    DOCTEST_CHECK(tx.commit() == kv::CommitSuccess::OK);

    auto read_call =
      create_request(read_params<int>(key, Tables::VALUES), "read");
    const auto r = frontend_process(frontend, read_call, member_cert);
    const auto result = parse_response_body<int>(r);
    DOCTEST_CHECK(result == value);
  }

  DOCTEST_SUBCASE("Read: allowed access, key doesn't exist")
  {
    constexpr auto wrong_key = 321;
    Store::Tx tx;
    tx.get_view(network.whitelists)
      ->put(WlIds::MEMBER_CAN_READ, {Tables::VALUES});
    DOCTEST_CHECK(tx.commit() == kv::CommitSuccess::OK);

    auto read_call =
      create_request(read_params<int>(wrong_key, Tables::VALUES), "read");
    const auto response = frontend_process(frontend, read_call, member_cert);

    check_error(response, HTTP_STATUS_BAD_REQUEST);
  }

  DOCTEST_SUBCASE("Read: access not allowed")
  {
    Store::Tx tx;
    tx.get_view(network.whitelists)->put(WlIds::MEMBER_CAN_READ, {});
    DOCTEST_CHECK(tx.commit() == kv::CommitSuccess::OK);

    auto read_call =
      create_request(read_params<int>(key, Tables::VALUES), "read");
    const auto response = frontend_process(frontend, read_call, member_cert);

    check_error(response, HTTP_STATUS_INTERNAL_SERVER_ERROR);
  }
}

DOCTEST_TEST_CASE("Proposer ballot")
{
  NetworkTables network;
  network.tables->set_encryptor(encryptor);
  Store::Tx gen_tx;
  GenesisGenerator gen(network, gen_tx);
  gen.init_values();

  const auto proposer_cert = get_cert_data(0, kp);
  const auto proposer_id =
    gen.add_member(proposer_cert, {}, MemberStatus::ACTIVE);
  const auto voter_cert = get_cert_data(1, kp);
  const auto voter_id = gen.add_member(voter_cert, {}, MemberStatus::ACTIVE);

  set_whitelists(gen);
  gen.set_gov_scripts(lua::Interpreter().invoke<json>(gov_script_file));
  gen.finalize();

  StubNodeState node;
  MemberRpcFrontend frontend(network, node);
  frontend.open();

  size_t proposal_id;

  const ccf::Script vote_for("return true");
  const ccf::Script vote_against("return false");
  {
    DOCTEST_INFO("Propose, initially voting against");

    const auto proposed_member = get_cert_data(2, kp);

    Propose::In proposal;
    proposal.script = std::string(R"xxx(
      tables, member_info = ...
      return Calls:call("new_member", member_info)
    )xxx");
    proposal.parameter["cert"] = proposed_member;
    proposal.parameter["keyshare"] = dummy_key_share;
    proposal.ballot = vote_against;
    const auto propose = create_signed_request(proposal, "propose", kp);
    const auto r = frontend_process(frontend, propose, proposer_cert);

    // the proposal should be accepted, but not succeed immediately
    const auto result = parse_response_body<Propose::Out>(r);
    DOCTEST_CHECK(result.state == ProposalState::OPEN);

    proposal_id = result.proposal_id;
  }

  {
    DOCTEST_INFO("Second member votes for proposal");

    const auto vote =
      create_signed_request(Vote{proposal_id, vote_for}, "vote", kp);
    const auto r = frontend_process(frontend, vote, voter_cert);

    // The vote should not yet succeed
    check_result_state(r, ProposalState::OPEN);
  }

  {
    DOCTEST_INFO("Read current votes");

    const auto proposal_result =
      get_proposal(frontend, proposal_id, proposer_cert);

    const auto& votes = proposal_result.votes;
    DOCTEST_CHECK(votes.size() == 2);

    const auto proposer_vote = votes.find(proposer_id);
    DOCTEST_CHECK(proposer_vote != votes.end());
    DOCTEST_CHECK(proposer_vote->second == vote_against);

    const auto voter_vote = votes.find(voter_id);
    DOCTEST_CHECK(voter_vote != votes.end());
    DOCTEST_CHECK(voter_vote->second == vote_for);
  }

  {
    DOCTEST_INFO("Proposer votes for");

    const auto vote =
      create_signed_request(Vote{proposal_id, vote_for}, "vote", kp);
    const auto r = frontend_process(frontend, vote, proposer_cert);

    // The vote should now succeed
    check_result_state(r, ProposalState::ACCEPTED);
  }
}

struct NewMember
{
  MemberId id;
  tls::KeyPairPtr kp = tls::make_key_pair();
  Cert cert;
};

DOCTEST_TEST_CASE("Add new members until there are 7 then reject")
{
  logger::config::level() = logger::INFO;

  constexpr auto initial_members = 3;
  constexpr auto n_new_members = 7;
  constexpr auto max_members = 8;
  NetworkTables network;
  network.tables->set_encryptor(encryptor);
  Store::Tx gen_tx;
  GenesisGenerator gen(network, gen_tx);
  gen.init_values();
  StubNodeState node(std::make_shared<NetworkTables>(network));
  // add three initial active members
  // the proposer
  auto proposer_id = gen.add_member(member_cert, {}, MemberStatus::ACTIVE);

  // the voters
  const auto voter_a_cert = get_cert_data(1, kp);
  auto voter_a = gen.add_member(voter_a_cert, {}, MemberStatus::ACTIVE);
  const auto voter_b_cert = get_cert_data(2, kp);
  auto voter_b = gen.add_member(voter_b_cert, {}, MemberStatus::ACTIVE);

  set_whitelists(gen);
  gen.set_gov_scripts(lua::Interpreter().invoke<json>(gov_script_file));
  gen.set_recovery_threshold(1);
  gen.finalize();
  MemberRpcFrontend frontend(network, node);
  frontend.open();

  vector<NewMember> new_members(n_new_members);

  auto i = 0ul;
  for (auto& new_member : new_members)
  {
    const auto proposal_id = i;
    new_member.id = initial_members + i++;

    // new member certificate
    auto cert_pem =
      new_member.kp->self_sign(fmt::format("CN=new member{}", new_member.id));
    auto keyshare = dummy_key_share;
    auto v = tls::make_verifier(cert_pem);
    const auto _cert = v->raw();
    new_member.cert = {_cert->raw.p, _cert->raw.p + _cert->raw.len};

    // check new_member id does not work before member is added
    const auto read_next_req = create_request(
      read_params<int>(ValueIds::NEXT_MEMBER_ID, Tables::VALUES), "read");
    const auto r = frontend_process(frontend, read_next_req, new_member.cert);
    check_error(r, HTTP_STATUS_FORBIDDEN);

    // propose new member, as proposer
    Propose::In proposal;
    proposal.script = std::string(R"xxx(
      tables, member_info = ...
      return Calls:call("new_member", member_info)
    )xxx");
    proposal.parameter["cert"] = cert_pem;
    proposal.parameter["keyshare"] = keyshare;

    const auto propose = create_signed_request(proposal, "propose", kp);

    {
      const auto r = frontend_process(frontend, propose, member_cert);
      const auto result = parse_response_body<Propose::Out>(r);

      // the proposal should be accepted, but not succeed immediately
      DOCTEST_CHECK(result.proposal_id == proposal_id);
      DOCTEST_CHECK(result.state == ProposalState::OPEN);
    }

    // read initial proposal, as second member
    const Proposal initial_read =
      get_proposal(frontend, proposal_id, voter_a_cert);
    DOCTEST_CHECK(initial_read.proposer == proposer_id);
    DOCTEST_CHECK(initial_read.script == proposal.script);
    DOCTEST_CHECK(initial_read.parameter == proposal.parameter);

    // vote as second member
    Script vote_ballot(fmt::format(
      R"xxx(
        local tables, calls = ...
        local n = 0
        tables["ccf.members"]:foreach( function(k, v) n = n + 1 end )
        if n < {} then
          return true
        else
          return false
        end
      )xxx",
      max_members));

    const auto vote =
      create_signed_request(Vote{proposal_id, vote_ballot}, "vote", kp);

    {
      const auto r = frontend_process(frontend, vote, voter_a_cert);
      const auto result = parse_response_body<ProposalInfo>(r);

      if (new_member.id < max_members)
      {
        // vote should succeed
        DOCTEST_CHECK(result.state == ProposalState::ACCEPTED);
        // check that member with the new new_member cert can make RPCs now
        DOCTEST_CHECK(
          parse_response_body<int>(frontend_process(
            frontend, read_next_req, new_member.cert)) == new_member.id + 1);

        // successful proposals are removed from the kv, so we can't confirm
        // their final state
      }
      else
      {
        // vote should not succeed
        DOCTEST_CHECK(result.state == ProposalState::OPEN);
        // check that member with the new new_member cert can make RPCs now
        check_error(
          frontend_process(frontend, read_next_req, new_member.cert),
          HTTP_STATUS_FORBIDDEN);

        // re-read proposal, as second member
        const Proposal final_read =
          get_proposal(frontend, proposal_id, voter_a_cert);
        DOCTEST_CHECK(final_read.proposer == proposer_id);
        DOCTEST_CHECK(final_read.script == proposal.script);
        DOCTEST_CHECK(final_read.parameter == proposal.parameter);

        const auto my_vote = final_read.votes.find(voter_a);
        DOCTEST_CHECK(my_vote != final_read.votes.end());
        DOCTEST_CHECK(my_vote->second == vote_ballot);
      }
    }
  }

  DOCTEST_SUBCASE("ACK from newly added members")
  {
    // iterate over all new_members, except for the last one
    for (auto new_member = new_members.cbegin(); new_member !=
         new_members.cend() - (initial_members + n_new_members - max_members);
         new_member++)
    {
      // (1) read ack entry
      const auto read_state_digest_req = create_request(
        read_params(new_member->id, Tables::MEMBER_ACKS), "read");
      const auto ack0 = parse_response_body<StateDigest>(
        frontend_process(frontend, read_state_digest_req, new_member->cert));
      DOCTEST_REQUIRE(std::all_of(
        ack0.state_digest.begin(), ack0.state_digest.end(), [](uint8_t i) {
          return i == 0;
        }));

      {
        // make sure that there is a signature in the signatures table since
        // ack's depend on that
        Store::Tx tx;
        auto sig_view = tx.get_view(network.signatures);
        Signature sig_value;
        sig_view->put(0, sig_value);
        DOCTEST_REQUIRE(tx.commit() == kv::CommitSuccess::OK);
      }

      // (2) ask for a fresher digest of state
      const auto freshen_state_digest_req =
        create_request(nullptr, "updateAckStateDigest");
      const auto freshen_state_digest = parse_response_body<StateDigest>(
        frontend_process(frontend, freshen_state_digest_req, new_member->cert));
      DOCTEST_CHECK(freshen_state_digest.state_digest != ack0.state_digest);

      // (3) read ack entry again and check that the state digest has changed
      const auto ack1 = parse_response_body<StateDigest>(
        frontend_process(frontend, read_state_digest_req, new_member->cert));
      DOCTEST_CHECK(ack0.state_digest != ack1.state_digest);
      DOCTEST_CHECK(freshen_state_digest.state_digest == ack1.state_digest);

      // (4) sign stale state and send it
      StateDigest params;
      params.state_digest = ack0.state_digest;
      const auto send_stale_sig_req =
        create_signed_request(params, "ack", new_member->kp);
      check_error(
        frontend_process(frontend, send_stale_sig_req, new_member->cert),
        HTTP_STATUS_BAD_REQUEST);

      // (5) sign new state digest and send it
      params.state_digest = ack1.state_digest;
      const auto send_good_sig_req =
        create_signed_request(params, "ack", new_member->kp);
      const auto good_response =
        frontend_process(frontend, send_good_sig_req, new_member->cert);
      DOCTEST_CHECK(good_response.status == HTTP_STATUS_OK);
      DOCTEST_CHECK(parse_response_body<bool>(good_response));

      // (6) read own member status
      const auto read_status_req =
        create_request(read_params(new_member->id, Tables::MEMBERS), "read");
      const auto mi = parse_response_body<MemberInfo>(
        frontend_process(frontend, read_status_req, new_member->cert));
      DOCTEST_CHECK(mi.status == MemberStatus::ACTIVE);
    }
  }
}

DOCTEST_TEST_CASE("Accept node")
{
  NetworkTables network;
  network.tables->set_encryptor(encryptor);
  Store::Tx gen_tx;
  GenesisGenerator gen(network, gen_tx);
  gen.init_values();
  StubNodeState node;
  auto new_kp = tls::make_key_pair();

  const auto member_0_cert = get_cert_data(0, new_kp);
  const auto member_1_cert = get_cert_data(1, kp);
  const auto member_0 = gen.add_member(member_0_cert, {}, MemberStatus::ACTIVE);
  const auto member_1 = gen.add_member(member_1_cert, {}, MemberStatus::ACTIVE);

  // node to be tested
  // new node certificate
  auto new_ca = new_kp->self_sign("CN=new node");
  NodeInfo ni;
  ni.cert = new_ca;
  gen.add_node(ni);
  set_whitelists(gen);
  gen.set_gov_scripts(lua::Interpreter().invoke<json>(gov_script_file));
  gen.finalize();
  MemberRpcFrontend frontend(network, node);
  frontend.open();
  auto node_id = 0;

  // check node exists with status pending
  {
    auto read_values =
      create_request(read_params<int>(node_id, Tables::NODES), "read");
    const auto r = parse_response_body<NodeInfo>(
      frontend_process(frontend, read_values, member_0_cert));

    DOCTEST_CHECK(r.status == NodeStatus::PENDING);
  }

  // m0 proposes adding new node
  {
    Script proposal(R"xxx(
      local tables, node_id = ...
      return Calls:call("trust_node", node_id)
    )xxx");
    const auto propose =
      create_signed_request(Propose::In{proposal, node_id}, "propose", new_kp);
    const auto r = parse_response_body<Propose::Out>(
      frontend_process(frontend, propose, member_0_cert));

    DOCTEST_CHECK(r.state == ProposalState::OPEN);
    DOCTEST_CHECK(r.proposal_id == 0);
  }

  // m1 votes for accepting a single new node
  {
    Script vote_ballot(R"xxx(
        local tables, calls = ...
        return #calls == 1 and calls[1].func == "trust_node"
       )xxx");
    const auto vote = create_signed_request(Vote{0, vote_ballot}, "vote", kp);

    check_result_state(
      frontend_process(frontend, vote, member_1_cert), ProposalState::ACCEPTED);
  }

  // check node exists with status pending
  {
    const auto read_values =
      create_request(read_params<int>(node_id, Tables::NODES), "read");
    const auto r = parse_response_body<NodeInfo>(
      frontend_process(frontend, read_values, member_0_cert));
    DOCTEST_CHECK(r.status == NodeStatus::TRUSTED);
  }

  // m0 proposes retire node
  {
    Script proposal(R"xxx(
      local tables, node_id = ...
      return Calls:call("retire_node", node_id)
    )xxx");
    const auto propose =
      create_signed_request(Propose::In{proposal, node_id}, "propose", new_kp);
    const auto r = parse_response_body<Propose::Out>(
      frontend_process(frontend, propose, member_0_cert));

    DOCTEST_CHECK(r.state == ProposalState::OPEN);
    DOCTEST_CHECK(r.proposal_id == 1);
  }

  // m1 votes for retiring node
  {
    const Script vote_ballot("return true");
    const auto vote = create_signed_request(Vote{1, vote_ballot}, "vote", kp);
    check_result_state(
      frontend_process(frontend, vote, member_1_cert), ProposalState::ACCEPTED);
  }

  // check that node exists with status retired
  {
    auto read_values =
      create_request(read_params<int>(node_id, Tables::NODES), "read");
    const auto r = parse_response_body<NodeInfo>(
      frontend_process(frontend, read_values, member_0_cert));
    DOCTEST_CHECK(r.status == NodeStatus::RETIRED);
  }

  // check that retired node cannot be trusted
  {
    Script proposal(R"xxx(
      local tables, node_id = ...
      return Calls:call("trust_node", node_id)
    )xxx");
    const auto propose =
      create_signed_request(Propose::In{proposal, node_id}, "propose", new_kp);
    const auto r = parse_response_body<Propose::Out>(
      frontend_process(frontend, propose, member_0_cert));

    const Script vote_ballot("return true");
    const auto vote =
      create_signed_request(Vote{r.proposal_id, vote_ballot}, "vote", kp);
    check_result_state(
      frontend_process(frontend, vote, member_1_cert), ProposalState::FAILED);
  }

  // check that retired node cannot be retired again
  {
    Script proposal(R"xxx(
      local tables, node_id = ...
      return Calls:call("retire_node", node_id)
    )xxx");
    const auto propose =
      create_signed_request(Propose::In{proposal, node_id}, "propose", new_kp);
    const auto r = parse_response_body<Propose::Out>(
      frontend_process(frontend, propose, member_0_cert));

    const Script vote_ballot("return true");
    const auto vote =
      create_signed_request(Vote{r.proposal_id, vote_ballot}, "vote", kp);
    check_result_state(
      frontend_process(frontend, vote, member_1_cert), ProposalState::FAILED);
  }
}

ProposalInfo test_raw_writes(
  NetworkTables& network,
  GenesisGenerator& gen,
  StubNodeState& node,
  Propose::In proposal,
  const int n_members = 1,
  const int pro_votes = 1,
  bool explicit_proposer_vote = false)
{
  std::vector<std::vector<uint8_t>> member_certs;
  auto frontend = init_frontend(network, gen, node, n_members, member_certs);
  frontend.open();

  // check values before
  {
    Store::Tx tx;
    auto next_member_id_r =
      tx.get_view(network.values)->get(ValueIds::NEXT_MEMBER_ID);
    DOCTEST_CHECK(next_member_id_r);
    DOCTEST_CHECK(*next_member_id_r == n_members);
  }

  // propose
  const auto proposal_id = 0ul;
  {
    const uint8_t proposer_id = 0;
    const auto propose = create_signed_request(proposal, "propose", kp);
    const auto r = parse_response_body<Propose::Out>(
      frontend_process(frontend, propose, member_certs[0]));

    const auto expected_state =
      (n_members == 1) ? ProposalState::ACCEPTED : ProposalState::OPEN;
    DOCTEST_CHECK(r.state == expected_state);
    DOCTEST_CHECK(r.proposal_id == proposal_id);
    if (r.state == ProposalState::ACCEPTED)
      return r;
  }

  // con votes
  for (int i = n_members - 1; i >= pro_votes; i--)
  {
    const Script vote("return false");
    const auto vote_serialized =
      create_signed_request(Vote{proposal_id, vote}, "vote", kp);

    check_result_state(
      frontend_process(frontend, vote_serialized, member_certs[i]),
      ProposalState::OPEN);
  }

  // pro votes (proposer also votes)
  ProposalInfo info = {};
  for (uint8_t i = explicit_proposer_vote ? 0 : 1; i < pro_votes; i++)
  {
    const Script vote("return true");
    const auto vote_serialized =
      create_signed_request(Vote{proposal_id, vote}, "vote", kp);
    if (info.state == ProposalState::OPEN)
    {
      info = parse_response_body<ProposalInfo>(
        frontend_process(frontend, vote_serialized, member_certs[i]));
    }
    else
    {
      // proposal has been accepted - additional votes return an error
      check_error(
        frontend_process(frontend, vote_serialized, member_certs[i]),
        HTTP_STATUS_BAD_REQUEST);
    }
  }
  return info;
}

DOCTEST_TEST_CASE("Propose raw writes")
{
  logger::config::level() = logger::INFO;
  DOCTEST_SUBCASE("insensitive tables")
  {
    const auto n_members = 3;
    for (int pro_votes = 0; pro_votes <= n_members; pro_votes++)
    {
      const bool should_succeed = pro_votes > n_members / 2;
      NetworkTables network;
      network.tables->set_encryptor(encryptor);
      Store::Tx gen_tx;
      GenesisGenerator gen(network, gen_tx);
      gen.init_values();
      StubNodeState node;
      nlohmann::json recovery_threshold = 4;

      Store::Tx tx_before;
      auto configuration = tx_before.get_view(network.config)->get(0);
      DOCTEST_REQUIRE_FALSE(configuration.has_value());

      const auto expected_state =
        should_succeed ? ProposalState::ACCEPTED : ProposalState::OPEN;
      const auto proposal_info = test_raw_writes(
        network,
        gen,
        node,
        {R"xxx(
        local tables, recovery_threshold = ...
        local p = Puts:new()
        p:put("ccf.config", 0, {recovery_threshold = recovery_threshold})
        return Calls:call("raw_puts", p)
      )xxx"s,
         4},
        n_members,
        pro_votes);
      DOCTEST_CHECK(proposal_info.state == expected_state);
      if (!should_succeed)
        continue;

      // check results
      Store::Tx tx_after;
      configuration = tx_after.get_view(network.config)->get(0);
      DOCTEST_CHECK(configuration.has_value());
      DOCTEST_CHECK(configuration->recovery_threshold == recovery_threshold);
    }
  }

  DOCTEST_SUBCASE("sensitive tables")
  {
    // propose changes to sensitive tables; changes must only be accepted
    // unanimously create new network for each case
    const auto sensitive_tables = {Tables::WHITELISTS, Tables::GOV_SCRIPTS};
    const auto n_members = 3;
    // let proposer vote/not vote
    for (const auto proposer_vote : {true, false})
    {
      for (int pro_votes = 0; pro_votes < n_members; pro_votes++)
      {
        for (const auto& sensitive_table : sensitive_tables)
        {
          NetworkTables network;
          network.tables->set_encryptor(encryptor);
          Store::Tx gen_tx;
          GenesisGenerator gen(network, gen_tx);
          gen.init_values();
          StubNodeState node;

          const auto sensitive_put =
            "return Calls:call('raw_puts', Puts:put('"s + sensitive_table +
            "', 9, {'aaa'}))"s;
          const auto expected_state = (n_members == pro_votes) ?
            ProposalState::ACCEPTED :
            ProposalState::OPEN;
          const auto proposal_info = test_raw_writes(
            network,
            gen,
            node,
            {sensitive_put},
            n_members,
            pro_votes,
            proposer_vote);
          DOCTEST_CHECK(proposal_info.state == expected_state);
        }
      }
    }
  }
}

DOCTEST_TEST_CASE("Remove proposal")
{
  NewMember caller;
  auto cert = caller.kp->self_sign("CN=new member");
  auto v = tls::make_verifier(cert);
  caller.cert = v->der_cert_data();

  NetworkTables network;
  network.tables->set_encryptor(encryptor);
  Store::Tx gen_tx;
  GenesisGenerator gen(network, gen_tx);
  gen.init_values();

  StubNodeState node;
  gen.add_member(member_cert, {}, MemberStatus::ACTIVE);
  gen.add_member(cert, {}, MemberStatus::ACTIVE);
  set_whitelists(gen);
  gen.set_gov_scripts(lua::Interpreter().invoke<json>(gov_script_file));
  gen.finalize();
  MemberRpcFrontend frontend(network, node);
  frontend.open();
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
    DOCTEST_CHECK(!proposal);
  }

  {
    const auto propose =
      create_signed_request(Propose::In{proposal_script, 0}, "propose", kp);
    const auto r = parse_response_body<Propose::Out>(
      frontend_process(frontend, propose, member_cert));

    DOCTEST_CHECK(r.proposal_id == proposal_id);
    DOCTEST_CHECK(r.state == ProposalState::OPEN);
  }

  // check that the proposal is there
  {
    Store::Tx tx;
    auto proposal = tx.get_view(network.proposals)->get(proposal_id);
    DOCTEST_CHECK(proposal);
    DOCTEST_CHECK(proposal->state == ProposalState::OPEN);
    DOCTEST_CHECK(
      proposal->script.text.value() == proposal_script.text.value());
  }

  DOCTEST_SUBCASE("Attempt withdraw proposal with non existing id")
  {
    json param;
    param["id"] = wrong_proposal_id;
    const auto withdraw = create_signed_request(param, "withdraw", kp);

    check_error(
      frontend_process(frontend, withdraw, member_cert),
      HTTP_STATUS_BAD_REQUEST);
  }

  DOCTEST_SUBCASE("Attempt withdraw proposal that you didn't propose")
  {
    json param;
    param["id"] = proposal_id;
    const auto withdraw = create_signed_request(param, "withdraw", caller.kp);

    check_error(
      frontend_process(frontend, withdraw, cert), HTTP_STATUS_FORBIDDEN);
  }

  DOCTEST_SUBCASE("Successfully withdraw proposal")
  {
    json param;
    param["id"] = proposal_id;
    const auto withdraw = create_signed_request(param, "withdraw", kp);

    check_result_state(
      frontend_process(frontend, withdraw, member_cert),
      ProposalState::WITHDRAWN);

    // check that the proposal is now withdrawn
    {
      Store::Tx tx;
      auto proposal = tx.get_view(network.proposals)->get(proposal_id);
      DOCTEST_CHECK(proposal.has_value());
      DOCTEST_CHECK(proposal->state == ProposalState::WITHDRAWN);
    }
  }
}

DOCTEST_TEST_CASE("Complete proposal after initial rejection")
{
  NetworkTables network;
  network.tables->set_encryptor(encryptor);
  Store::Tx gen_tx;
  GenesisGenerator gen(network, gen_tx);
  gen.init_values();
  StubNodeState node;
  std::vector<std::vector<uint8_t>> member_certs;
  auto frontend = init_frontend(network, gen, node, 3, member_certs);
  frontend.open();

  {
    DOCTEST_INFO("Propose");
    const auto proposal =
      "return Calls:call('raw_puts', Puts:put('ccf.values', 999, 999))"s;
    const auto propose =
      create_signed_request(Propose::In{proposal}, "propose", kp);

    Store::Tx tx;
    const auto r = parse_response_body<Propose::Out>(
      frontend_process(frontend, propose, member_certs[0]));
    DOCTEST_CHECK(r.state == ProposalState::OPEN);
  }

  {
    DOCTEST_INFO("Vote that rejects initially");
    const Script vote(R"xxx(
    local tables = ...
    return tables["ccf.values"]:get(123) == 123
    )xxx");
    const auto vote_serialized =
      create_signed_request(Vote{0, vote}, "vote", kp);

    check_result_state(
      frontend_process(frontend, vote_serialized, member_certs[1]),
      ProposalState::OPEN);
  }

  {
    DOCTEST_INFO("Try to complete");
    const auto complete =
      create_signed_request(ProposalAction{0}, "complete", kp);

    check_result_state(
      frontend_process(frontend, complete, member_certs[1]),
      ProposalState::OPEN);
  }

  {
    DOCTEST_INFO("Put value that makes vote agree");
    Store::Tx tx;
    tx.get_view(network.values)->put(123, 123);
    DOCTEST_CHECK(tx.commit() == kv::CommitSuccess::OK);
  }

  {
    DOCTEST_INFO("Try again to complete");
    const auto complete =
      create_signed_request(ProposalAction{0}, "complete", kp);

    check_result_state(
      frontend_process(frontend, complete, member_certs[1]),
      ProposalState::ACCEPTED);
  }
}

DOCTEST_TEST_CASE("Vetoed proposal gets rejected")
{
  NetworkTables network;
  network.tables->set_encryptor(encryptor);
  Store::Tx gen_tx;
  GenesisGenerator gen(network, gen_tx);
  gen.init_values();
  StubNodeState node;
  const auto voter_a_cert = get_cert_data(1, kp);
  auto voter_a = gen.add_member(voter_a_cert, {}, MemberStatus::ACTIVE);
  const auto voter_b_cert = get_cert_data(2, kp);
  auto voter_b = gen.add_member(voter_b_cert, {}, MemberStatus::ACTIVE);
  set_whitelists(gen);
  gen.set_gov_scripts(lua::Interpreter().invoke<json>(gov_veto_script_file));
  gen.finalize();
  MemberRpcFrontend frontend(network, node);
  frontend.open();

  Script proposal(R"xxx(
    tables, user_cert = ...
      return Calls:call("new_user", user_cert)
    )xxx");

  const vector<uint8_t> user_cert = kp->self_sign("CN=new user");
  const auto propose =
    create_signed_request(Propose::In{proposal, user_cert}, "propose", kp);

  const auto r = parse_response_body<Propose::Out>(
    frontend_process(frontend, propose, voter_a_cert));
  DOCTEST_CHECK(r.state == ProposalState::OPEN);
  DOCTEST_CHECK(r.proposal_id == 0);

  const ccf::Script vote_against("return false");
  {
    DOCTEST_INFO("Member vetoes proposal");

    const auto vote = create_signed_request(Vote{0, vote_against}, "vote", kp);
    const auto r = frontend_process(frontend, vote, voter_b_cert);

    check_result_state(r, ProposalState::REJECTED);
  }

  {
    DOCTEST_INFO("Check proposal was rejected");

    const auto proposal = get_proposal(frontend, 0, voter_a_cert);

    DOCTEST_CHECK(proposal.state == ProposalState::REJECTED);
  }
}

DOCTEST_TEST_CASE("Add user via proposed call")
{
  NetworkTables network;
  network.tables->set_encryptor(encryptor);
  Store::Tx gen_tx;
  GenesisGenerator gen(network, gen_tx);
  gen.init_values();
  StubNodeState node;
  const auto member_cert = get_cert_data(0, kp);
  gen.add_member(member_cert, {}, MemberStatus::ACTIVE);
  set_whitelists(gen);
  gen.set_gov_scripts(lua::Interpreter().invoke<json>(gov_script_file));
  gen.finalize();
  MemberRpcFrontend frontend(network, node);
  frontend.open();

  Script proposal(R"xxx(
    tables, user_cert = ...
      return Calls:call("new_user", user_cert)
    )xxx");

  const vector<uint8_t> user_cert = kp->self_sign("CN=new user");
  const auto propose =
    create_signed_request(Propose::In{proposal, user_cert}, "propose", kp);

  const auto r = parse_response_body<Propose::Out>(
    frontend_process(frontend, propose, member_cert));
  DOCTEST_CHECK(r.state == ProposalState::ACCEPTED);
  DOCTEST_CHECK(r.proposal_id == 0);

  Store::Tx tx1;
  const auto uid = tx1.get_view(network.values)->get(ValueIds::NEXT_USER_ID);
  DOCTEST_CHECK(uid);
  DOCTEST_CHECK(*uid == 1);
  const auto uid1 = tx1.get_view(network.user_certs)
                      ->get(tls::make_verifier(user_cert)->der_cert_data());
  DOCTEST_CHECK(uid1);
  DOCTEST_CHECK(*uid1 == 0);
}

DOCTEST_TEST_CASE("Passing members ballot with operator")
{
  // Members pass a ballot with a constitution that includes an operator
  // Operator votes, but is _not_ taken into consideration
  NetworkTables network;
  network.tables->set_encryptor(encryptor);
  Store::Tx gen_tx;
  GenesisGenerator gen(network, gen_tx);
  gen.init_values();

  // Operating member, as set in operator_gov.lua
  const auto operator_cert = get_cert_data(0, kp);
  const auto operator_id =
    gen.add_member(operator_cert, {}, MemberStatus::ACTIVE);

  // Non-operating members
  std::map<size_t, ccf::Cert> members;
  for (size_t i = 1; i < 4; i++)
  {
    auto cert = get_cert_data(i, kp);
    members[gen.add_member(cert, {}, MemberStatus::ACTIVE)] = cert;
  }

  set_whitelists(gen);
  gen.set_gov_scripts(
    lua::Interpreter().invoke<json>(operator_gov_script_file));
  gen.finalize();

  StubNodeState node;
  MemberRpcFrontend frontend(network, node);
  frontend.open();

  size_t proposal_id;
  size_t proposer_id = 1;
  size_t voter_id = 2;

  const ccf::Script vote_for("return true");
  const ccf::Script vote_against("return false");
  {
    DOCTEST_INFO("Propose and vote for");

    const auto proposed_member = get_cert_data(4, kp);

    Propose::In proposal;
    proposal.script = std::string(R"xxx(
      tables, member_info = ...
      return Calls:call("new_member", member_info)
    )xxx");
    proposal.parameter["cert"] = proposed_member;
    proposal.parameter["keyshare"] = dummy_key_share;
    proposal.ballot = vote_for;

    const auto propose = create_signed_request(proposal, "propose", kp);
    const auto r = parse_response_body<Propose::Out>(frontend_process(
      frontend,
      propose,
      tls::make_verifier(members[proposer_id])->der_cert_data()));

    DOCTEST_CHECK(r.state == ProposalState::OPEN);

    proposal_id = r.proposal_id;
  }

  {
    DOCTEST_INFO("Operator votes, but without effect");

    const auto vote =
      create_signed_request(Vote{proposal_id, vote_for}, "vote", kp);
    const auto r = frontend_process(frontend, vote, operator_cert);

    check_result_state(r, ProposalState::OPEN);
  }

  {
    DOCTEST_INFO("Second member votes for proposal, which passes");

    const auto vote =
      create_signed_request(Vote{proposal_id, vote_for}, "vote", kp);
    const auto r = frontend_process(frontend, vote, members[voter_id]);

    check_result_state(r, ProposalState::ACCEPTED);
  }

  {
    DOCTEST_INFO("Validate vote tally");

    const auto readj = create_signed_request(
      read_params(proposal_id, Tables::PROPOSALS), "read", kp);

    const auto proposal =
      get_proposal(frontend, proposal_id, members[proposer_id]);

    const auto& votes = proposal.votes;
    DOCTEST_CHECK(votes.size() == 3);

    const auto operator_vote = votes.find(operator_id);
    DOCTEST_CHECK(operator_vote != votes.end());
    DOCTEST_CHECK(operator_vote->second == vote_for);

    const auto proposer_vote = votes.find(proposer_id);
    DOCTEST_CHECK(proposer_vote != votes.end());
    DOCTEST_CHECK(proposer_vote->second == vote_for);

    const auto voter_vote = votes.find(voter_id);
    DOCTEST_CHECK(voter_vote != votes.end());
    DOCTEST_CHECK(voter_vote->second == vote_for);
  }
}

DOCTEST_TEST_CASE("Passing operator vote")
{
  // Operator issues a proposal that only requires its own vote
  // and gets it through without member votes
  NetworkTables network;
  network.tables->set_encryptor(encryptor);
  Store::Tx gen_tx;
  GenesisGenerator gen(network, gen_tx);
  gen.init_values();
  auto new_kp = tls::make_key_pair();
  auto new_ca = new_kp->self_sign("CN=new node");
  NodeInfo ni;
  ni.cert = new_ca;
  gen.add_node(ni);

  // Operating member, as set in operator_gov.lua
  const auto operator_cert = get_cert_data(0, kp);
  const auto operator_id =
    gen.add_member(operator_cert, {}, MemberStatus::ACTIVE);

  // Non-operating members
  std::map<size_t, ccf::Cert> members;
  for (size_t i = 1; i < 4; i++)
  {
    auto cert = get_cert_data(i, kp);
    members[gen.add_member(cert, {}, MemberStatus::ACTIVE)] = cert;
  }

  set_whitelists(gen);
  gen.set_gov_scripts(
    lua::Interpreter().invoke<json>(operator_gov_script_file));
  gen.finalize();

  StubNodeState node;
  MemberRpcFrontend frontend(network, node);
  frontend.open();

  size_t proposal_id;

  const ccf::Script vote_for("return true");
  const ccf::Script vote_against("return false");

  auto node_id = 0;
  {
    DOCTEST_INFO("Check node exists with status pending");
    auto read_values =
      create_request(read_params<int>(node_id, Tables::NODES), "read");
    const auto r = parse_response_body<NodeInfo>(
      frontend_process(frontend, read_values, operator_cert));

    DOCTEST_CHECK(r.status == NodeStatus::PENDING);
  }

  {
    DOCTEST_INFO("Operator proposes and votes for node");
    Script proposal(R"xxx(
      local tables, node_id = ...
      return Calls:call("trust_node", node_id)
    )xxx");

    const auto propose = create_signed_request(
      Propose::In{proposal, node_id, vote_for}, "propose", kp);
    const auto r = parse_response_body<Propose::Out>(
      frontend_process(frontend, propose, operator_cert));

    DOCTEST_CHECK(r.state == ProposalState::ACCEPTED);
    proposal_id = r.proposal_id;
  }

  {
    DOCTEST_INFO("Validate vote tally");

    const auto readj = create_signed_request(
      read_params(proposal_id, Tables::PROPOSALS), "read", kp);

    const auto proposal = get_proposal(frontend, proposal_id, operator_cert);

    const auto& votes = proposal.votes;
    DOCTEST_CHECK(votes.size() == 1);

    const auto proposer_vote = votes.find(operator_id);
    DOCTEST_CHECK(proposer_vote != votes.end());
    DOCTEST_CHECK(proposer_vote->second == vote_for);
  }
}

DOCTEST_TEST_CASE("Members passing an operator vote")
{
  // Operator proposes a vote, but does not vote for it
  // A majority of members pass the vote
  NetworkTables network;
  network.tables->set_encryptor(encryptor);
  Store::Tx gen_tx;
  GenesisGenerator gen(network, gen_tx);
  gen.init_values();
  auto new_kp = tls::make_key_pair();
  auto new_ca = new_kp->self_sign("CN=new node");
  NodeInfo ni;
  ni.cert = new_ca;
  gen.add_node(ni);

  // Operating member, as set in operator_gov.lua
  const auto operator_cert = get_cert_data(0, kp);
  const auto operator_id =
    gen.add_member(operator_cert, {}, MemberStatus::ACTIVE);

  // Non-operating members
  std::map<size_t, ccf::Cert> members;
  for (size_t i = 1; i < 4; i++)
  {
    auto cert = get_cert_data(i, kp);
    members[gen.add_member(cert, {}, MemberStatus::ACTIVE)] = cert;
  }

  set_whitelists(gen);
  gen.set_gov_scripts(
    lua::Interpreter().invoke<json>(operator_gov_script_file));
  gen.finalize();

  StubNodeState node;
  MemberRpcFrontend frontend(network, node);
  frontend.open();

  size_t proposal_id;

  const ccf::Script vote_for("return true");
  const ccf::Script vote_against("return false");

  auto node_id = 0;
  {
    DOCTEST_INFO("Check node exists with status pending");
    const auto read_values =
      create_request(read_params<int>(node_id, Tables::NODES), "read");
    const auto r = parse_response_body<NodeInfo>(
      frontend_process(frontend, read_values, operator_cert));
    DOCTEST_CHECK(r.status == NodeStatus::PENDING);
  }

  {
    DOCTEST_INFO("Operator proposes and votes against adding node");
    Script proposal(R"xxx(
      local tables, node_id = ...
      return Calls:call("trust_node", node_id)
    )xxx");

    const auto propose = create_signed_request(
      Propose::In{proposal, node_id, vote_against}, "propose", kp);
    const auto r = parse_response_body<Propose::Out>(
      frontend_process(frontend, propose, operator_cert));

    DOCTEST_CHECK(r.state == ProposalState::OPEN);
    proposal_id = r.proposal_id;
  }

  size_t first_voter_id = 1;
  size_t second_voter_id = 2;

  {
    DOCTEST_INFO("First member votes for proposal");

    const auto vote =
      create_signed_request(Vote{proposal_id, vote_for}, "vote", kp);
    const auto r = frontend_process(frontend, vote, members[first_voter_id]);

    check_result_state(r, ProposalState::OPEN);
  }

  {
    DOCTEST_INFO("Second member votes for proposal");

    const auto vote =
      create_signed_request(Vote{proposal_id, vote_for}, "vote", kp);
    const auto r = frontend_process(frontend, vote, members[second_voter_id]);

    check_result_state(r, ProposalState::ACCEPTED);
  }

  {
    DOCTEST_INFO("Validate vote tally");

    const auto readj = create_signed_request(
      read_params(proposal_id, Tables::PROPOSALS), "read", kp);

    const auto proposal = get_proposal(frontend, proposal_id, operator_cert);

    const auto& votes = proposal.votes;
    DOCTEST_CHECK(votes.size() == 3);

    const auto proposer_vote = votes.find(operator_id);
    DOCTEST_CHECK(proposer_vote != votes.end());
    DOCTEST_CHECK(proposer_vote->second == vote_against);

    const auto first_vote = votes.find(first_voter_id);
    DOCTEST_CHECK(first_vote != votes.end());
    DOCTEST_CHECK(first_vote->second == vote_for);

    const auto second_vote = votes.find(second_voter_id);
    DOCTEST_CHECK(second_vote != votes.end());
    DOCTEST_CHECK(second_vote->second == vote_for);
  }
}

DOCTEST_TEST_CASE("User data")
{
  NetworkTables network;
  network.tables->set_encryptor(encryptor);
  Store::Tx gen_tx;
  GenesisGenerator gen(network, gen_tx);
  gen.init_values();
  const auto member_id = gen.add_member(member_cert, {}, MemberStatus::ACTIVE);
  const auto user_id = gen.add_user(user_cert);
  set_whitelists(gen);
  gen.set_gov_scripts(lua::Interpreter().invoke<json>(gov_script_file));
  gen.finalize();

  StubNodeState node;
  MemberRpcFrontend frontend(network, node);
  frontend.open();

  const auto read_user_info =
    create_request(read_params(user_id, Tables::USERS), "read");

  {
    DOCTEST_INFO("user data is initially empty");
    const auto read_response = parse_response_body<ccf::UserInfo>(
      frontend_process(frontend, read_user_info, member_cert));
    DOCTEST_CHECK(read_response.user_data.is_null());
  }

  {
    auto user_data_object = nlohmann::json::object();
    user_data_object["name"] = "bob";
    user_data_object["permissions"] = {"read", "delete"};

    DOCTEST_INFO("user data can be set to an object");
    Propose::In proposal;
    proposal.script = fmt::format(
      R"xxx(
        proposed_user_data = {{
          name = "bob",
          permissions = {{"read", "delete"}}
        }}
        return Calls:call("set_user_data", {{user_id = {}, user_data =
        proposed_user_data}})
      )xxx",
      user_id);
    const auto proposal_serialized =
      create_signed_request(proposal, "propose", kp);
    const auto propose_response = parse_response_body<Propose::Out>(
      frontend_process(frontend, proposal_serialized, member_cert));
    DOCTEST_CHECK(propose_response.state == ProposalState::ACCEPTED);

    DOCTEST_INFO("user data object can be read");
    const auto read_response = parse_response_body<ccf::UserInfo>(
      frontend_process(frontend, read_user_info, member_cert));
    DOCTEST_CHECK(read_response.user_data == user_data_object);
  }

  {
    const auto user_data_string = "ADMINISTRATOR";

    DOCTEST_INFO("user data can be overwritten");
    Propose::In proposal;
    proposal.script = std::string(R"xxx(
      local tables, param = ...
      return Calls:call("set_user_data", {user_id = param.id, user_data =
      param.data})
    )xxx");
    proposal.parameter["id"] = user_id;
    proposal.parameter["data"] = user_data_string;
    const auto proposal_serialized =
      create_signed_request(proposal, "propose", kp);
    const auto propose_response = parse_response_body<Propose::Out>(
      frontend_process(frontend, proposal_serialized, member_cert));
    DOCTEST_CHECK(propose_response.state == ProposalState::ACCEPTED);

    DOCTEST_INFO("user data object can be read");
    const auto response = parse_response_body<ccf::UserInfo>(
      frontend_process(frontend, read_user_info, member_cert));
    DOCTEST_CHECK(response.user_data == user_data_string);
  }
}

DOCTEST_TEST_CASE("Submit recovery shares")
{
  // Setup original state
  NetworkTables network;
  auto node = StubNodeState(std::make_shared<NetworkTables>(network));
  MemberRpcFrontend frontend(network, node);
  std::map<size_t, ccf::Cert> members;
  size_t members_count = 4;
  size_t recovery_threshold = 2;
  DOCTEST_REQUIRE(recovery_threshold <= members_count);
  std::map<size_t, EncryptedShare> retrieved_shares;

  DOCTEST_INFO("Setup state");
  {
    Store::Tx gen_tx;

    GenesisGenerator gen(network, gen_tx);
    gen.init_values();
    gen.create_service({});

    for (size_t i = 0; i < members_count; i++)
    {
      auto cert = get_cert_data(i, kp);
      members[gen.add_member(cert, {}, MemberStatus::ACTIVE)] = cert;
    }
    gen.set_recovery_threshold(recovery_threshold);
    DOCTEST_REQUIRE(node.split_ledger_secrets(gen_tx));
    gen.finalize();

    frontend.open();
  }

  DOCTEST_INFO("Retrieve recovery shares");
  {
    const auto get_recovery_shares =
      create_request(nullptr, "getEncryptedRecoveryShare");

    for (auto const& m : members)
    {
      retrieved_shares[m.first] = parse_response_body<EncryptedShare>(
        frontend_process(frontend, get_recovery_shares, m.second));
    }
  }

  DOCTEST_INFO("Submit share before the service is in correct state");
  {
    MemberId member_id = 0;
    const auto submit_recovery_share = create_request(
      SubmitRecoveryShare({retrieved_shares[member_id].encrypted_share}),
      "submitRecoveryShare");

    check_error(
      frontend_process(frontend, submit_recovery_share, members[member_id]),
      HTTP_STATUS_FORBIDDEN);
  }

  DOCTEST_INFO("Change service state to waiting for recovery shares");
  {
    Store::Tx tx;
    GenesisGenerator g(network, tx);

    DOCTEST_REQUIRE(g.service_wait_for_shares());

    g.finalize();
  }

  DOCTEST_INFO("Submit recovery shares");
  {
    size_t member_count = 0;
    for (auto const& m : members)
    {
      const auto submit_recovery_share = create_request(
        SubmitRecoveryShare({retrieved_shares[m.first].encrypted_share}),
        "submitRecoveryShare");

      auto ret = parse_response_body<bool>(
        frontend_process(frontend, submit_recovery_share, m.second));

      member_count++;

      // Share submission should only complete when the recovery threshold has
      // been reached
      if (member_count < recovery_threshold)
      {
        DOCTEST_REQUIRE(!ret);
      }
      else
      {
        DOCTEST_REQUIRE(ret);
        break;
      }
    }
  }
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