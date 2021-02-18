// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "node/rpc/test/frontend_test_infra.h"

DOCTEST_TEST_CASE("Member query/read")
{
  // initialize the network state
  NetworkState network;
  auto gen_tx = network.tables->create_tx();
  GenesisGenerator gen(network, gen_tx);
  gen.init_values();
  gen.create_service({});
  ShareManager share_manager(network);
  StubNodeState node;
  MemberRpcFrontend frontend(network, node, share_manager);
  frontend.open();
  const auto member_id = gen.add_member(member_cert);
  gen.finalize();

  const enclave::SessionContext member_session(
    enclave::InvalidSessionId, member_cert.raw());

  // put value to read
  constexpr auto key = 123;
  constexpr auto value = 456;
  auto tx = network.tables->create_tx();
  tx.rw(network.values)->put(key, value);
  DOCTEST_CHECK(tx.commit() == kv::CommitResult::SUCCESS);

  static constexpr auto query = R"xxx(
  local tables = ...
  return tables["public:ccf.internal.values"]:get(123)
  )xxx";

  DOCTEST_SUBCASE("Query: bytecode/script allowed access")
  {
    // set member ACL so that the VALUES table is accessible
    auto tx = network.tables->create_tx();
    tx.rw(network.whitelists)->put(WlIds::MEMBER_CAN_READ, {Tables::VALUES});
    DOCTEST_CHECK(tx.commit() == kv::CommitResult::SUCCESS);

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
    auto tx = network.tables->create_tx();
    tx.rw(network.whitelists)->put(WlIds::MEMBER_CAN_READ, {});
    DOCTEST_CHECK(tx.commit() == kv::CommitResult::SUCCESS);

    auto req = create_request(query_params(query, true), "query");
    const auto response = frontend_process(frontend, req, member_cert);

    check_error(response, HTTP_STATUS_INTERNAL_SERVER_ERROR);
  }

  DOCTEST_SUBCASE("Read: allowed access, key exists")
  {
    auto tx = network.tables->create_tx();
    tx.rw(network.whitelists)->put(WlIds::MEMBER_CAN_READ, {Tables::VALUES});
    DOCTEST_CHECK(tx.commit() == kv::CommitResult::SUCCESS);

    auto read_call =
      create_request(read_params<int>(key, Tables::VALUES), "read");
    const auto r = frontend_process(frontend, read_call, member_cert);
    const auto result = parse_response_body<int>(r);
    DOCTEST_CHECK(result == value);
  }

  DOCTEST_SUBCASE("Read: allowed access, key doesn't exist")
  {
    constexpr auto wrong_key = 321;
    auto tx = network.tables->create_tx();
    tx.rw(network.whitelists)->put(WlIds::MEMBER_CAN_READ, {Tables::VALUES});
    DOCTEST_CHECK(tx.commit() == kv::CommitResult::SUCCESS);

    auto read_call =
      create_request(read_params<int>(wrong_key, Tables::VALUES), "read");
    const auto response = frontend_process(frontend, read_call, member_cert);

    check_error(response, HTTP_STATUS_NOT_FOUND);
  }

  DOCTEST_SUBCASE("Read: access not allowed")
  {
    auto tx = network.tables->create_tx();
    tx.rw(network.whitelists)->put(WlIds::MEMBER_CAN_READ, {});
    DOCTEST_CHECK(tx.commit() == kv::CommitResult::SUCCESS);

    auto read_call =
      create_request(read_params<int>(key, Tables::VALUES), "read");
    const auto response = frontend_process(frontend, read_call, member_cert);

    check_error(response, HTTP_STATUS_INTERNAL_SERVER_ERROR);
  }
}

DOCTEST_TEST_CASE("Proposer ballot")
{
  NetworkState network;
  init_network(network);
  auto gen_tx = network.tables->create_tx();
  GenesisGenerator gen(network, gen_tx);
  gen.init_values();
  gen.create_service({});

  const auto proposer_cert = get_cert(0, kp);
  const auto proposer_id = gen.add_member(proposer_cert);
  gen.activate_member(proposer_id);
  const auto voter_cert = get_cert(1, kp);
  const auto voter_id = gen.add_member(voter_cert);
  gen.activate_member(voter_id);

  set_whitelists(gen);
  gen.set_gov_scripts(lua::Interpreter().invoke<json>(gov_script_file));
  gen.finalize();

  ShareManager share_manager(network);
  StubNodeState node;
  MemberRpcFrontend frontend(network, node, share_manager);

  frontend.open();

  ProposalId proposal_id;

  const ccf::Script vote_for("return true");
  const ccf::Script vote_against("return false");
  {
    DOCTEST_INFO("Propose, no votes");

    const auto proposed_member = get_cert(2, kp);

    Propose::In proposal;
    proposal.script = std::string(R"xxx(
      tables, member_info = ...
      return Calls:call("new_member", member_info)
    )xxx");
    proposal.parameter["cert"] = proposed_member;
    proposal.parameter["encryption_pub_key"] = dummy_enc_pubk;
    const auto propose =
      create_signed_request(proposal, "proposals", kp, proposer_cert);
    const auto r = frontend_process(frontend, propose, proposer_cert);

    // the proposal should be accepted, but not succeed immediately
    const auto result = parse_response_body<Propose::Out>(r);
    DOCTEST_CHECK(result.state == ProposalState::OPEN);

    proposal_id = result.proposal_id;
  }

  {
    DOCTEST_INFO("Second member votes for proposal");

    const auto vote = create_signed_request(
      Vote{vote_for},
      fmt::format("proposals/{}/votes", proposal_id),
      kp,
      voter_cert);
    const auto r = frontend_process(frontend, vote, voter_cert);

    // The vote should not yet succeed
    check_result_state(r, ProposalState::OPEN);
  }

  {
    DOCTEST_INFO("Read current votes");

    const auto proposal_result =
      get_proposal(frontend, proposal_id, proposer_cert);

    const auto& votes = proposal_result.votes;
    DOCTEST_CHECK(votes.size() == 1);

    const auto proposer_vote = votes.find(proposer_id);
    DOCTEST_CHECK(proposer_vote == votes.end());

    const auto voter_vote = votes.find(voter_id);
    DOCTEST_CHECK(voter_vote != votes.end());
    DOCTEST_CHECK(voter_vote->second == vote_for);

    {
      DOCTEST_INFO("Get votes directly");
      const auto voter_vote2 =
        get_vote(frontend, proposal_id, voter_id, proposer_cert);
      DOCTEST_CHECK(voter_vote2 == vote_for);
    }
  }

  {
    DOCTEST_INFO("Proposer votes for");

    const auto vote = create_signed_request(
      Vote{vote_for},
      fmt::format("proposals/{}/votes", proposal_id),
      kp,
      proposer_cert);
    const auto r = frontend_process(frontend, vote, proposer_cert);

    // The vote should now succeed
    check_result_state(r, ProposalState::ACCEPTED);
  }
}

DOCTEST_TEST_CASE("Reject duplicate vote")
{
  NetworkState network;
  init_network(network);
  auto gen_tx = network.tables->create_tx();
  GenesisGenerator gen(network, gen_tx);
  gen.init_values();
  gen.create_service({});

  const auto proposer_cert = get_cert(0, kp);
  const auto proposer_id = gen.add_member(proposer_cert);
  gen.activate_member(proposer_id);

  set_whitelists(gen);
  gen.set_gov_scripts(lua::Interpreter().invoke<json>(gov_script_file));
  gen.finalize();

  ShareManager share_manager(network);
  StubNodeState node;
  MemberRpcFrontend frontend(network, node, share_manager);
  frontend.open();

  ProposalId proposal_id;

  const ccf::Script vote_for("return true");
  const ccf::Script vote_against("return false");
  {
    DOCTEST_INFO("Propose, no votes");

    const auto proposed_member = get_cert(2, kp);

    Propose::In proposal;
    proposal.script = std::string(R"xxx(
      tables, member_info = ...
      return Calls:call("new_member", member_info)
    )xxx");
    proposal.parameter["cert"] = proposed_member;
    proposal.parameter["encryption_pub_key"] = dummy_enc_pubk;
    const auto propose =
      create_signed_request(proposal, "proposals", kp, proposer_cert);
    const auto r = frontend_process(frontend, propose, proposer_cert);

    // the proposal should be accepted, but not succeed immediately
    const auto result = parse_response_body<Propose::Out>(r);
    DOCTEST_CHECK(result.state == ProposalState::OPEN);

    proposal_id = result.proposal_id;
  }

  {
    DOCTEST_INFO("Proposer votes for");

    const auto vote = create_signed_request(
      Vote{vote_for},
      fmt::format("proposals/{}/votes", proposal_id),
      kp,
      proposer_cert);
    const auto r = frontend_process(frontend, vote, proposer_cert);

    // The vote should now succeed
    check_result_state(r, ProposalState::ACCEPTED);
  }

  {
    DOCTEST_INFO("Proposer cannot vote again");

    const auto vote = create_signed_request(
      Vote{vote_against},
      fmt::format("proposals/{}/votes", proposal_id),
      kp,
      proposer_cert);
    check_error(
      frontend_process(frontend, vote, proposer_cert), HTTP_STATUS_BAD_REQUEST);
  }
}

struct NewMember
{
  MemberId id;
  tls::KeyPairPtr kp = tls::make_key_pair();
  tls::Pem cert;
};

DOCTEST_TEST_CASE("Add new members until there are 7 then reject")
{
  logger::config::level() = logger::INFO;

  constexpr auto initial_members = 3;
  constexpr auto n_new_members = 7;
  constexpr auto max_members = 8;
  NetworkState network;
  NodeId node_id = 0;
  network.ledger_secrets = std::make_shared<LedgerSecrets>(node_id);
  network.ledger_secrets->init();
  init_network(network);
  auto gen_tx = network.tables->create_tx();
  GenesisGenerator gen(network, gen_tx);
  gen.init_values();
  gen.create_service({});
  gen.init_configuration({1});
  ShareManager share_manager(network);
  StubNodeState node;
  // add three initial active members
  // the proposer
  auto proposer_id = gen.add_member({member_cert, dummy_enc_pubk});
  gen.activate_member(proposer_id);

  // the voters
  const auto voter_a_cert = get_cert(1, kp);
  auto voter_a = gen.add_member({voter_a_cert, dummy_enc_pubk});
  gen.activate_member(voter_a);
  const auto voter_b_cert = get_cert(2, kp);
  auto voter_b = gen.add_member({voter_b_cert, dummy_enc_pubk});
  gen.activate_member(voter_b);

  set_whitelists(gen);
  gen.set_gov_scripts(lua::Interpreter().invoke<json>(gov_script_file));
  gen.open_service();
  gen.finalize();
  MemberRpcFrontend frontend(network, node, share_manager);
  frontend.open();

  vector<NewMember> new_members(n_new_members);

  auto i = 0ul;
  for (auto& new_member : new_members)
  {
    new_member.id = initial_members + i++;

    // new member certificate
    auto cert_pem =
      new_member.kp->self_sign(fmt::format("CN=new member{}", new_member.id));
    auto encryption_pub_key = dummy_enc_pubk;
    new_member.cert = cert_pem;

    // check new_member id does not work before member is added
    const auto read_next_req = create_request(
      read_params<int>(ValueIds::NEXT_MEMBER_ID, Tables::VALUES), "read");
    const auto r = frontend_process(frontend, read_next_req, new_member.cert);
    check_error(r, HTTP_STATUS_UNAUTHORIZED);

    // propose new member, as proposer
    Propose::In proposal;
    proposal.script = std::string(R"xxx(
      tables, member_info = ...
      return Calls:call("new_member", member_info)
    )xxx");
    proposal.parameter["cert"] = cert_pem;
    proposal.parameter["encryption_pub_key"] = dummy_enc_pubk;

    const auto propose =
      create_signed_request(proposal, "proposals", kp, member_cert);

    ProposalId proposal_id;
    {
      const auto r = frontend_process(frontend, propose, member_cert);
      const auto result = parse_response_body<Propose::Out>(r);

      // the proposal should be accepted, but not succeed immediately
      proposal_id = result.proposal_id;
      DOCTEST_CHECK(result.state == ProposalState::OPEN);
    }

    {
      // vote for own proposal
      Script vote_yes("return true");
      const auto vote = create_signed_request(
        Vote{vote_yes},
        fmt::format("proposals/{}/votes", proposal_id),
        kp,
        member_cert);
      const auto r = frontend_process(frontend, vote, member_cert);
      const auto result = parse_response_body<ProposalInfo>(r);
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
        tables["public:ccf.gov.members.info"]:foreach( function(k, v) n = n + 1 end )
        if n < {} then
          return true
        else
          return false
        end
      )xxx",
      max_members));

    const auto vote = create_signed_request(
      Vote{vote_ballot},
      fmt::format("proposals/{}/votes", proposal_id),
      kp,
      voter_a_cert);

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
          HTTP_STATUS_UNAUTHORIZED);

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
        auto tx = network.tables->create_tx();
        auto signatures = tx.rw(network.signatures);
        PrimarySignature sig_value;
        signatures->put(0, sig_value);
        DOCTEST_REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
      }

      // (2) ask for a fresher digest of state
      const auto freshen_state_digest_req =
        create_request(nullptr, "ack/update_state_digest");
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
        create_signed_request(params, "ack", new_member->kp, new_member->cert);
      check_error(
        frontend_process(frontend, send_stale_sig_req, new_member->cert),
        HTTP_STATUS_BAD_REQUEST);

      // (5) sign new state digest and send it
      params.state_digest = ack1.state_digest;
      const auto send_good_sig_req =
        create_signed_request(params, "ack", new_member->kp, new_member->cert);
      const auto good_response =
        frontend_process(frontend, send_good_sig_req, new_member->cert);
      DOCTEST_CHECK(good_response.status == HTTP_STATUS_NO_CONTENT);

      // (6) read own member status
      const auto read_status_req =
        create_request(read_params(new_member->id, Tables::MEMBERS), "read");
      const auto mi = parse_response_body<MemberInfo>(
        frontend_process(frontend, read_status_req, new_member->cert));
      DOCTEST_CHECK(mi.status == MemberStatus::ACTIVE);
      DOCTEST_CHECK(mi.cert == new_member->cert);
    }
  }
}

DOCTEST_TEST_CASE("Accept node")
{
  NetworkState network;
  NodeId node_id = 0;
  network.ledger_secrets = std::make_shared<LedgerSecrets>(node_id);
  network.ledger_secrets->init();
  init_network(network);
  auto gen_tx = network.tables->create_tx();
  GenesisGenerator gen(network, gen_tx);
  gen.init_values();
  gen.create_service({});
  ShareManager share_manager(network);
  StubNodeState node;
  auto new_kp = tls::make_key_pair();

  const auto member_0_cert = get_cert(0, new_kp);
  const auto member_1_cert = get_cert(1, kp);
  const auto member_0 = gen.add_member(member_0_cert);
  const auto member_1 = gen.add_member(member_1_cert);
  gen.activate_member(member_0);
  gen.activate_member(member_1);

  // node to be tested
  // new node certificate
  auto new_ca = new_kp->self_sign("CN=new node");
  NodeInfo ni;
  ni.cert = new_ca;
  gen.add_node(ni);
  set_whitelists(gen);
  gen.set_gov_scripts(lua::Interpreter().invoke<json>(gov_script_file));
  gen.finalize();
  MemberRpcFrontend frontend(network, node, share_manager);
  frontend.open();

  // check node exists with status pending
  {
    auto read_values =
      create_request(read_params<int>(node_id, Tables::NODES), "read");
    const auto r = parse_response_body<NodeInfo>(
      frontend_process(frontend, read_values, member_0_cert));

    DOCTEST_CHECK(r.status == NodeStatus::PENDING);
  }

  // m0 proposes adding new node
  ProposalId trust_node_proposal_id;
  {
    Script proposal(R"xxx(
      local tables, node_id = ...
      return Calls:call("trust_node", node_id)
    )xxx");
    const auto propose = create_signed_request(
      Propose::In{proposal, node_id}, "proposals", new_kp, member_0_cert);
    const auto r = parse_response_body<Propose::Out>(
      frontend_process(frontend, propose, member_0_cert));

    DOCTEST_CHECK(r.state == ProposalState::OPEN);
    trust_node_proposal_id = r.proposal_id;
  }

  {
    // vote for own proposal
    Script vote_yes("return true");
    const auto vote = create_signed_request(
      Vote{vote_yes},
      fmt::format("proposals/{}/votes", trust_node_proposal_id),
      new_kp,
      member_0_cert);
    const auto r = frontend_process(frontend, vote, member_0_cert);
    const auto result = parse_response_body<ProposalInfo>(r);
    DOCTEST_CHECK(result.state == ProposalState::OPEN);
  }

  // m1 votes for accepting a single new node
  {
    Script vote_ballot(R"xxx(
        local tables, calls = ...
        return #calls == 1 and calls[1].func == "trust_node"
       )xxx");
    const auto vote = create_signed_request(
      Vote{vote_ballot},
      fmt::format("proposals/{}/votes", trust_node_proposal_id),
      kp,
      member_1_cert);

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
  ProposalId retire_node_proposal_id;
  {
    Script proposal(R"xxx(
      local tables, node_id = ...
      return Calls:call("retire_node", node_id)
    )xxx");
    const auto propose = create_signed_request(
      Propose::In{proposal, node_id}, "proposals", new_kp, member_0_cert);
    const auto r = parse_response_body<Propose::Out>(
      frontend_process(frontend, propose, member_0_cert));

    DOCTEST_CHECK(r.state == ProposalState::OPEN);
    retire_node_proposal_id = r.proposal_id;
  }

  {
    // vote for own proposal
    Script vote_yes("return true");
    const auto vote = create_signed_request(
      Vote{vote_yes},
      fmt::format("proposals/{}/votes", retire_node_proposal_id),
      new_kp,
      member_0_cert);
    const auto r = frontend_process(frontend, vote, member_0_cert);
    const auto result = parse_response_body<ProposalInfo>(r);
    DOCTEST_CHECK(result.state == ProposalState::OPEN);
  }

  // m1 votes for retiring node
  {
    const Script vote_ballot("return true");
    const auto vote = create_signed_request(
      Vote{vote_ballot},
      fmt::format("proposals/{}/votes", retire_node_proposal_id),
      kp,
      member_1_cert);
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
    const auto propose = create_signed_request(
      Propose::In{proposal, node_id}, "proposals", new_kp, member_0_cert);
    const auto r = parse_response_body<Propose::Out>(
      frontend_process(frontend, propose, member_0_cert));

    const Script vote_ballot("return true");
    auto vote = create_signed_request(
      Vote{vote_ballot},
      fmt::format("proposals/{}/votes", r.proposal_id),
      new_kp,
      member_0_cert);
    frontend_process(frontend, vote, member_0_cert);

    vote = create_signed_request(
      Vote{vote_ballot},
      fmt::format("proposals/{}/votes", r.proposal_id),
      kp,
      member_1_cert);
    check_result_state(
      frontend_process(frontend, vote, member_1_cert), ProposalState::FAILED);
  }

  // check that retired node cannot be retired again
  {
    Script proposal(R"xxx(
      local tables, node_id = ...
      return Calls:call("retire_node", node_id)
    )xxx");
    const auto propose = create_signed_request(
      Propose::In{proposal, node_id}, "proposals", new_kp, member_0_cert);
    const auto r = parse_response_body<Propose::Out>(
      frontend_process(frontend, propose, member_0_cert));

    const Script vote_ballot("return true");
    auto vote = create_signed_request(
      Vote{vote_ballot},
      fmt::format("proposals/{}/votes", r.proposal_id),
      new_kp,
      member_0_cert);
    frontend_process(frontend, vote, member_0_cert);

    vote = create_signed_request(
      Vote{vote_ballot},
      fmt::format("proposals/{}/votes", r.proposal_id),
      kp,
      member_1_cert);
    check_result_state(
      frontend_process(frontend, vote, member_1_cert), ProposalState::FAILED);
  }
}

ProposalInfo test_raw_writes(
  NetworkState& network,
  GenesisGenerator& gen,
  StubNodeState& node,
  ShareManager& share_manager,
  Propose::In proposal,
  const int n_members = 1,
  const int pro_votes = 1,
  bool explicit_proposer_vote = false)
{
  std::vector<tls::Pem> member_certs;
  auto frontend =
    init_frontend(network, gen, node, share_manager, n_members, member_certs);
  frontend.open();

  // check values before
  {
    auto tx = network.tables->create_tx();
    auto next_member_id_r =
      tx.rw(network.values)->get(ValueIds::NEXT_MEMBER_ID);
    DOCTEST_CHECK(next_member_id_r);
    DOCTEST_CHECK(*next_member_id_r == n_members);
  }

  // propose
  ProposalId proposal_id;
  {
    const uint8_t proposer_id = 0;
    const auto propose =
      create_signed_request(proposal, "proposals", kp, member_certs[0]);
    const auto r = parse_response_body<Propose::Out>(
      frontend_process(frontend, propose, member_certs[0]));

    const auto expected_state =
      (n_members == 1) ? ProposalState::ACCEPTED : ProposalState::OPEN;
    DOCTEST_CHECK(r.state == expected_state);
    proposal_id = r.proposal_id;
    if (r.state == ProposalState::ACCEPTED)
      return r;
  }

  // con votes
  for (int i = n_members - 1; i >= pro_votes; i--)
  {
    const Script vote("return false");
    const auto vote_serialized = create_signed_request(
      Vote{vote},
      fmt::format("proposals/{}/votes", proposal_id),
      kp,
      member_certs[i]);

    check_result_state(
      frontend_process(frontend, vote_serialized, member_certs[i]),
      ProposalState::OPEN);
  }

  // pro votes (proposer also votes)
  ProposalInfo info = {};
  for (uint8_t i = explicit_proposer_vote ? 0 : 1; i < pro_votes; i++)
  {
    const Script vote("return true");
    const auto vote_serialized = create_signed_request(
      Vote{vote},
      fmt::format("proposals/{}/votes", proposal_id),
      kp,
      member_certs[i]);
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
      NetworkState network;
      init_network(network);
      auto gen_tx = network.tables->create_tx();
      GenesisGenerator gen(network, gen_tx);
      gen.init_values();
      gen.create_service({});
      ShareManager share_manager(network);
      StubNodeState node;
      nlohmann::json recovery_threshold = 4;

      auto tx_before = network.tables->create_tx();
      auto configuration = tx_before.rw(network.config)->get(0);
      DOCTEST_REQUIRE_FALSE(configuration.has_value());

      const auto expected_state =
        should_succeed ? ProposalState::ACCEPTED : ProposalState::OPEN;
      const auto proposal_info = test_raw_writes(
        network,
        gen,
        node,
        share_manager,
        {R"xxx(
        local tables, recovery_threshold = ...
        local p = Puts:new()
        p:put("public:ccf.gov.service.config", 0, {recovery_threshold = recovery_threshold, consensus = "CFT"})
        return Calls:call("raw_puts", p)
      )xxx"s,
         4},
        n_members,
        pro_votes,
        true);
      DOCTEST_CHECK(proposal_info.state == expected_state);
      if (!should_succeed)
        continue;

      // check results
      auto tx_after = network.tables->create_tx();
      configuration = tx_after.rw(network.config)->get(0);
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
    for (const auto proposer_vote : {true})
    {
      for (int pro_votes = 0; pro_votes < n_members; pro_votes++)
      {
        for (const auto& sensitive_table : sensitive_tables)
        {
          NetworkState network;
          init_network(network);
          auto gen_tx = network.tables->create_tx();
          GenesisGenerator gen(network, gen_tx);
          gen.init_values();
          gen.create_service({});
          ShareManager share_manager(network);
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
            share_manager,
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
  caller.cert = v->cert_pem();

  NetworkState network;
  init_network(network);
  auto gen_tx = network.tables->create_tx();
  GenesisGenerator gen(network, gen_tx);
  gen.init_values();
  gen.create_service({});

  ShareManager share_manager(network);
  StubNodeState node;
  gen.activate_member(gen.add_member(member_cert));
  gen.activate_member(gen.add_member(cert));
  set_whitelists(gen);
  gen.set_gov_scripts(lua::Interpreter().invoke<json>(gov_script_file));
  gen.finalize();
  MemberRpcFrontend frontend(network, node, share_manager);
  frontend.open();
  ProposalId proposal_id;
  auto wrong_proposal_id = 1;
  ccf::Script proposal_script(R"xxx(
      local tables, param = ...
      return {}
    )xxx");

  // check that the proposal doesn't exist
  {
    auto tx = network.tables->create_tx();
    auto proposal = tx.rw(network.proposals)->get(proposal_id);
    DOCTEST_CHECK(!proposal);
  }

  {
    const auto propose = create_signed_request(
      Propose::In{proposal_script, 0}, "proposals", kp, member_cert);
    const auto r = parse_response_body<Propose::Out>(
      frontend_process(frontend, propose, member_cert));

    proposal_id = r.proposal_id;
    DOCTEST_CHECK(r.state == ProposalState::OPEN);
  }

  // check that the proposal is there
  {
    auto tx = network.tables->create_tx();
    auto proposal = tx.rw(network.proposals)->get(proposal_id);
    DOCTEST_CHECK(proposal);
    DOCTEST_CHECK(proposal->state == ProposalState::OPEN);
    DOCTEST_CHECK(
      proposal->script.text.value() == proposal_script.text.value());
  }

  DOCTEST_SUBCASE("Attempt withdraw proposal with non existing id")
  {
    const auto withdraw = create_signed_request(
      nullptr,
      fmt::format("proposals/{}/withdraw", wrong_proposal_id),
      kp,
      member_cert);

    check_error(
      frontend_process(frontend, withdraw, member_cert),
      HTTP_STATUS_BAD_REQUEST);
  }

  DOCTEST_SUBCASE("Attempt withdraw proposal that you didn't propose")
  {
    const auto withdraw = create_signed_request(
      nullptr,
      fmt::format("proposals/{}/withdraw", proposal_id),
      caller.kp,
      cert);

    check_error(
      frontend_process(frontend, withdraw, cert), HTTP_STATUS_FORBIDDEN);
  }

  DOCTEST_SUBCASE("Successfully withdraw proposal")
  {
    const auto withdraw = create_signed_request(
      nullptr,
      fmt::format("proposals/{}/withdraw", proposal_id),
      kp,
      member_cert);

    check_result_state(
      frontend_process(frontend, withdraw, member_cert),
      ProposalState::WITHDRAWN);

    // check that the proposal is now withdrawn
    {
      auto tx = network.tables->create_tx();
      auto proposal = tx.rw(network.proposals)->get(proposal_id);
      DOCTEST_CHECK(proposal.has_value());
      DOCTEST_CHECK(proposal->state == ProposalState::WITHDRAWN);
    }
  }
}

DOCTEST_TEST_CASE("Vetoed proposal gets rejected")
{
  NetworkState network;
  init_network(network);
  auto gen_tx = network.tables->create_tx();
  GenesisGenerator gen(network, gen_tx);
  gen.init_values();
  gen.create_service({});
  ShareManager share_manager(network);
  StubNodeState node;
  const auto voter_a_cert = get_cert(1, kp);
  auto voter_a = gen.add_member(voter_a_cert);
  const auto voter_b_cert = get_cert(2, kp);
  auto voter_b = gen.add_member(voter_b_cert);
  gen.activate_member(voter_a);
  gen.activate_member(voter_b);
  set_whitelists(gen);
  gen.set_gov_scripts(lua::Interpreter().invoke<json>(gov_veto_script_file));
  gen.finalize();
  MemberRpcFrontend frontend(network, node, share_manager);
  frontend.open();

  Script proposal(R"xxx(
    tables, user_cert = ...
      return Calls:call("new_user", user_cert)
    )xxx");

  const auto propose = create_signed_request(
    Propose::In{proposal, user_cert}, "proposals", kp, voter_a_cert);

  const auto r = parse_response_body<Propose::Out>(
    frontend_process(frontend, propose, voter_a_cert));
  DOCTEST_CHECK(r.state == ProposalState::OPEN);

  const ccf::Script vote_against("return false");
  {
    DOCTEST_INFO("Member vetoes proposal");

    const auto vote = create_signed_request(
      Vote{vote_against},
      fmt::format("proposals/{}/votes", r.proposal_id),
      kp,
      voter_b_cert);
    const auto r = frontend_process(frontend, vote, voter_b_cert);

    check_result_state(r, ProposalState::REJECTED);
  }

  {
    DOCTEST_INFO("Check proposal was rejected");

    const auto proposal = get_proposal(frontend, r.proposal_id, voter_a_cert);

    DOCTEST_CHECK(proposal.state == ProposalState::REJECTED);
  }
}

DOCTEST_TEST_CASE("Add and remove user via proposed calls")
{
  NetworkState network;
  init_network(network);
  auto gen_tx = network.tables->create_tx();
  GenesisGenerator gen(network, gen_tx);
  gen.init_values();
  gen.create_service({});
  ShareManager share_manager(network);
  StubNodeState node;
  const auto member_cert = get_cert(0, kp);
  gen.activate_member(gen.add_member(member_cert));
  set_whitelists(gen);
  gen.set_gov_scripts(lua::Interpreter().invoke<json>(gov_script_file));
  gen.finalize();
  MemberRpcFrontend frontend(network, node, share_manager);
  frontend.open();

  ccf::Cert user_der;

  {
    DOCTEST_INFO("Add user");

    Script proposal(R"xxx(
        tables, user_cert = ...
        return Calls:call("new_user", {cert = user_cert})
      )xxx");

    const auto user_cert = kp->self_sign("CN=new user");
    const auto propose = create_signed_request(
      Propose::In{proposal, user_cert}, "proposals", kp, member_cert);

    auto r = parse_response_body<Propose::Out>(
      frontend_process(frontend, propose, member_cert));

    DOCTEST_CHECK(r.state == ProposalState::OPEN);
    // vote for own proposal
    Script vote_yes("return true");
    const auto vote = create_signed_request(
      Vote{vote_yes},
      fmt::format("proposals/{}/votes", r.proposal_id),
      kp,
      member_cert);
    r = parse_response_body<ProposalInfo>(
      frontend_process(frontend, vote, member_cert));

    DOCTEST_CHECK(r.state == ProposalState::ACCEPTED);

    auto tx1 = network.tables->create_tx();
    const auto uid = tx1.rw(network.values)->get(ValueIds::NEXT_USER_ID);
    DOCTEST_CHECK(uid);
    DOCTEST_CHECK(*uid == 1);
    user_der = tls::make_verifier(user_cert)->cert_der();
    const auto uid1 = tx1.rw(network.user_certs)->get(user_der);
    DOCTEST_CHECK(uid1);
    DOCTEST_CHECK(*uid1 == 0);
  }

  {
    DOCTEST_INFO("Remove user");

    Script proposal(R"xxx(
      tables, user_id = ...
        return Calls:call("remove_user", user_id)
      )xxx");

    const auto propose = create_signed_request(
      Propose::In{proposal, 0}, "proposals", kp, member_cert);

    auto r = parse_response_body<Propose::Out>(
      frontend_process(frontend, propose, member_cert));

    DOCTEST_CHECK(r.state == ProposalState::OPEN);
    // vote for own proposal
    Script vote_yes("return true");
    const auto vote = create_signed_request(
      Vote{vote_yes},
      fmt::format("proposals/{}/votes", r.proposal_id),
      kp,
      member_cert);
    r = parse_response_body<ProposalInfo>(
      frontend_process(frontend, vote, member_cert));

    DOCTEST_CHECK(r.state == ProposalState::ACCEPTED);

    auto tx1 = network.tables->create_tx();
    auto user = tx1.rw(network.users)->get(0);
    DOCTEST_CHECK(!user.has_value());
    auto user_cert = tx1.rw(network.user_certs)->get(user_der);
    DOCTEST_CHECK(!user_cert.has_value());
  }
}

nlohmann::json operator_member_data()
{
  auto md = nlohmann::json::object();
  md["is_operator"] = true;
  return md;
}

DOCTEST_TEST_CASE(
  "Passing members ballot with operator" * doctest::test_suite("operator"))
{
  // Members pass a ballot with a constitution that includes an operator
  // Operator votes, but is _not_ taken into consideration
  NetworkState network;
  init_network(network);
  auto gen_tx = network.tables->create_tx();
  GenesisGenerator gen(network, gen_tx);
  gen.init_values();
  gen.create_service({});

  // Operating member, as indicated by member data
  const auto operator_cert = get_cert(0, kp);
  const auto operator_id =
    gen.add_member({operator_cert, {}, operator_member_data()});
  gen.activate_member(operator_id);

  // Non-operating members
  std::map<size_t, tls::Pem> members;
  for (size_t i = 1; i < 4; i++)
  {
    auto cert = get_cert(i, kp);
    auto id = gen.add_member(cert);
    gen.activate_member(id);
    members[id] = cert;
  }

  set_whitelists(gen);
  gen.set_gov_scripts(
    lua::Interpreter().invoke<json>(operator_gov_script_file));
  gen.finalize();

  ShareManager share_manager(network);
  StubNodeState node;
  MemberRpcFrontend frontend(network, node, share_manager);
  frontend.open();

  ProposalId proposal_id;
  size_t proposer_id = 1;
  size_t voter_id = 2;

  const ccf::Script vote_for("return true");
  const ccf::Script vote_against("return false");
  {
    DOCTEST_INFO("Propose and vote for");

    const auto proposed_member = get_cert(4, kp);

    Propose::In proposal;
    proposal.script = std::string(R"xxx(
      tables, member_info = ...
      return Calls:call("new_member", member_info)
    )xxx");
    proposal.parameter["cert"] = proposed_member;
    proposal.parameter["encryption_pub_key"] = dummy_enc_pubk;

    const auto propose =
      create_signed_request(proposal, "proposals", kp, members[proposer_id]);
    const auto r = parse_response_body<Propose::Out>(frontend_process(
      frontend, propose, tls::make_verifier(members[proposer_id])->cert_der()));

    DOCTEST_CHECK(r.state == ProposalState::OPEN);

    proposal_id = r.proposal_id;
  }

  {
    DOCTEST_INFO("First member votes");

    const auto vote = create_signed_request(
      Vote{vote_for},
      fmt::format("proposals/{}/votes", proposal_id),
      kp,
      members[proposer_id]);
    const auto r = frontend_process(frontend, vote, members[proposer_id]);

    check_result_state(r, ProposalState::OPEN);
  }

  {
    DOCTEST_INFO("Operator votes, but without effect");

    const auto vote = create_signed_request(
      Vote{vote_for},
      fmt::format("proposals/{}/votes", proposal_id),
      kp,
      operator_cert);
    const auto r = frontend_process(frontend, vote, operator_cert);

    check_result_state(r, ProposalState::OPEN);
  }

  {
    DOCTEST_INFO("Second member votes for proposal, which passes");

    const auto vote = create_signed_request(
      Vote{vote_for},
      fmt::format("proposals/{}/votes", proposal_id),
      kp,
      members[voter_id]);
    const auto r = frontend_process(frontend, vote, members[voter_id]);

    check_result_state(r, ProposalState::ACCEPTED);
  }

  {
    DOCTEST_INFO("Validate vote tally");

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

DOCTEST_TEST_CASE("Passing operator change" * doctest::test_suite("operator"))
{
  // Operator issues a proposal that is an operator change
  // and gets it through without member votes
  NetworkState network;
  NodeId node_id = 0;
  network.ledger_secrets = std::make_shared<LedgerSecrets>(node_id);
  network.ledger_secrets->init();
  init_network(network);
  auto gen_tx = network.tables->create_tx();
  GenesisGenerator gen(network, gen_tx);
  gen.init_values();
  gen.create_service({});
  auto new_kp = tls::make_key_pair();
  auto new_ca = new_kp->self_sign("CN=new node");
  NodeInfo ni;
  ni.cert = new_ca;
  gen.add_node(ni);

  // Operating member, as indicated by member data
  const auto operator_cert = get_cert(0, kp);
  const auto operator_id =
    gen.add_member({operator_cert, std::nullopt, operator_member_data()});
  gen.activate_member(operator_id);

  // Non-operating members
  std::map<size_t, tls::Pem> members;
  for (size_t i = 1; i < 4; i++)
  {
    auto cert = get_cert(i, kp);
    auto id = gen.add_member({cert, dummy_enc_pubk});
    gen.activate_member(id);
    members[id] = cert;
  }

  set_whitelists(gen);
  gen.set_gov_scripts(
    lua::Interpreter().invoke<json>(operator_gov_script_file));
  gen.finalize();

  ShareManager share_manager(network);
  StubNodeState node;
  MemberRpcFrontend frontend(network, node, share_manager);
  frontend.open();

  ProposalId proposal_id;

  const ccf::Script vote_for("return true");
  const ccf::Script vote_against("return false");

  {
    DOCTEST_INFO("Check node exists with status pending");
    auto read_values =
      create_request(read_params<int>(node_id, Tables::NODES), "read");
    const auto r = parse_response_body<NodeInfo>(
      frontend_process(frontend, read_values, operator_cert));

    DOCTEST_CHECK(r.status == NodeStatus::PENDING);
  }

  {
    DOCTEST_INFO("Operator proposes node");
    Script proposal(R"xxx(
      local tables, node_id = ...
      return Calls:call("trust_node", node_id)
    )xxx");

    const auto propose = create_signed_request(
      Propose::In{proposal, node_id}, "proposals", kp, operator_cert);
    const auto r = parse_response_body<Propose::Out>(
      frontend_process(frontend, propose, operator_cert));

    DOCTEST_CHECK(r.state == ProposalState::ACCEPTED);
    proposal_id = r.proposal_id;
  }

  {
    DOCTEST_INFO("Validate vote tally");

    const auto proposal = get_proposal(frontend, proposal_id, operator_cert);

    const auto& votes = proposal.votes;
    DOCTEST_CHECK(votes.size() == 0);

    const auto proposer_vote = votes.find(operator_id);
    DOCTEST_CHECK(proposer_vote == votes.end());
  }

  auto new_operator_kp = tls::make_key_pair();
  const auto new_operator_cert = get_cert(42, new_operator_kp);

  {
    DOCTEST_INFO("Operator adds another operator");
    Propose::In proposal;
    proposal.script = std::string(R"xxx(
      local tables, member_info = ...
      return Calls:call("new_member", member_info)
    )xxx");

    proposal.parameter["cert"] = new_operator_cert;
    proposal.parameter["member_data"] = operator_member_data();

    const auto propose =
      create_signed_request(proposal, "proposals", kp, operator_cert);
    const auto r = parse_response_body<Propose::Out>(
      frontend_process(frontend, propose, operator_cert));

    DOCTEST_CHECK(r.state == ProposalState::ACCEPTED);

    {
      DOCTEST_INFO("New operator acks to become active");
      const auto state_digest_req =
        create_request(nullptr, "ack/update_state_digest");
      const auto ack = parse_response_body<StateDigest>(
        frontend_process(frontend, state_digest_req, new_operator_cert));

      StateDigest params;
      params.state_digest = ack.state_digest;
      const auto ack_req = create_signed_request(
        params, "ack", new_operator_kp, new_operator_cert);
      const auto resp = frontend_process(frontend, ack_req, new_operator_cert);
    }
  }

  {
    DOCTEST_INFO("New operator retires original operator");
    Propose::In proposal;
    proposal.script = fmt::format(
      R"xxx(return Calls:call("retire_member", {}))xxx", operator_id);

    const auto propose = create_signed_request(
      proposal, "proposals", new_operator_kp, new_operator_cert);
    const auto r = parse_response_body<Propose::Out>(
      frontend_process(frontend, propose, new_operator_cert));

    DOCTEST_CHECK(r.state == ProposalState::ACCEPTED);
  }

  {
    DOCTEST_INFO("New operator cannot add non-operator member");

    auto new_member_kp = tls::make_key_pair();
    const auto new_member_cert = get_cert(100, new_member_kp);

    Propose::In proposal;
    proposal.script = std::string(R"xxx(
      local tables, member_info = ...
      return Calls:call("new_member", member_info)
    )xxx");

    proposal.parameter["cert"] = new_member_cert;
    proposal.parameter["encryption_pub_key"] = dummy_enc_pubk;
    proposal.parameter["member_data"] =
      nullptr; // blank member_data => not an operator

    const auto propose = create_signed_request(
      proposal, "proposals", new_operator_kp, new_operator_cert);
    const auto r = parse_response_body<Propose::Out>(
      frontend_process(frontend, propose, new_operator_cert));

    DOCTEST_CHECK(r.state == ProposalState::OPEN);
  }

  {
    DOCTEST_INFO("New operator cannot retire non-operator member");

    const auto normal_member_id = members.begin()->first;

    Propose::In proposal;
    proposal.script = fmt::format(
      R"xxx(return Calls:call("retire_member", {}))xxx", normal_member_id);

    const auto propose = create_signed_request(
      proposal, "proposals", new_operator_kp, new_operator_cert);
    const auto r = parse_response_body<Propose::Out>(
      frontend_process(frontend, propose, new_operator_cert));

    DOCTEST_CHECK(r.state == ProposalState::OPEN);
  }
}

DOCTEST_TEST_CASE(
  "Members passing an operator change" * doctest::test_suite("operator"))
{
  // Member proposes an operator change
  // A majority of members pass the vote
  NetworkState network;
  NodeId node_id = 0;
  network.ledger_secrets = std::make_shared<LedgerSecrets>(node_id);
  network.ledger_secrets->init();
  init_network(network);
  auto gen_tx = network.tables->create_tx();
  GenesisGenerator gen(network, gen_tx);
  gen.init_values();
  gen.create_service({});
  auto new_kp = tls::make_key_pair();
  auto new_ca = new_kp->self_sign("CN=new node");
  NodeInfo ni;
  ni.cert = new_ca;
  gen.add_node(ni);

  // Not operating member
  const auto proposer_cert = get_cert(0, kp);
  const auto proposer_id = gen.add_member(proposer_cert);
  gen.activate_member(proposer_id);

  // Non-operating members
  std::map<size_t, tls::Pem> members;
  for (size_t i = 1; i < 3; i++)
  {
    auto cert = get_cert(i, kp);
    auto id = gen.add_member(cert);
    gen.activate_member(id);
    members[id] = cert;
  }

  set_whitelists(gen);
  gen.set_gov_scripts(
    lua::Interpreter().invoke<json>(operator_gov_script_file));
  gen.finalize();

  ShareManager share_manager(network);
  StubNodeState node;
  MemberRpcFrontend frontend(network, node, share_manager);
  frontend.open();

  ProposalId proposal_id;

  const ccf::Script vote_for("return true");
  const ccf::Script vote_against("return false");

  {
    DOCTEST_INFO("Check node exists with status pending");
    const auto read_values =
      create_request(read_params<int>(node_id, Tables::NODES), "read");
    const auto r = parse_response_body<NodeInfo>(
      frontend_process(frontend, read_values, proposer_cert));
    DOCTEST_CHECK(r.status == NodeStatus::PENDING);
  }

  {
    DOCTEST_INFO("Member proposes");
    Script proposal(R"xxx(
      local tables, node_id = ...
      return Calls:call("trust_node", node_id)
    )xxx");

    const auto propose = create_signed_request(
      Propose::In{proposal, node_id}, "proposals", kp, proposer_cert);
    const auto r = parse_response_body<Propose::Out>(
      frontend_process(frontend, propose, proposer_cert));

    DOCTEST_CHECK(r.state == ProposalState::OPEN);
    proposal_id = r.proposal_id;
  }

  {
    DOCTEST_INFO("Member votes against");

    const auto vote = create_signed_request(
      Vote{vote_against},
      fmt::format("proposals/{}/votes", proposal_id),
      kp,
      proposer_cert);
    const auto r = frontend_process(frontend, vote, proposer_cert);

    check_result_state(r, ProposalState::OPEN);
  }

  size_t first_voter_id = 1;
  size_t second_voter_id = 2;

  {
    DOCTEST_INFO("First member votes for proposal");

    const auto vote = create_signed_request(
      Vote{vote_for},
      fmt::format("proposals/{}/votes", proposal_id),
      kp,
      members[first_voter_id]);
    const auto r = frontend_process(frontend, vote, members[first_voter_id]);

    check_result_state(r, ProposalState::OPEN);
  }

  {
    DOCTEST_INFO("Second member votes for proposal");

    const auto vote = create_signed_request(
      Vote{vote_for},
      fmt::format("proposals/{}/votes", proposal_id),
      kp,
      members[second_voter_id]);
    const auto r = frontend_process(frontend, vote, members[second_voter_id]);

    check_result_state(r, ProposalState::ACCEPTED);
  }

  {
    DOCTEST_INFO("Validate vote tally");

    const auto proposal = get_proposal(frontend, proposal_id, proposer_cert);

    const auto& votes = proposal.votes;
    DOCTEST_CHECK(votes.size() == 3);

    const auto proposer_vote = votes.find(proposer_id);
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
  NetworkState network;
  init_network(network);
  auto gen_tx = network.tables->create_tx();
  GenesisGenerator gen(network, gen_tx);
  gen.init_values();
  gen.create_service({});
  const auto member_id = gen.add_member(member_cert);
  gen.activate_member(member_id);
  set_whitelists(gen);
  gen.set_gov_scripts(lua::Interpreter().invoke<json>(gov_script_file));

  ShareManager share_manager(network);
  StubNodeState node;
  MemberRpcFrontend frontend(network, node, share_manager);
  frontend.open();

  ccf::UserId user_id;
  std::vector<uint8_t> read_user_info;

  DOCTEST_SUBCASE("No initial user data")
  {
    user_id = gen.add_user({user_cert});
    gen.finalize();

    read_user_info =
      create_request(read_params(user_id, Tables::USERS), "read");

    {
      DOCTEST_INFO("user data is initially empty");
      const auto read_response = parse_response_body<ccf::UserInfo>(
        frontend_process(frontend, read_user_info, member_cert));
      DOCTEST_CHECK(read_response.user_data.is_null());
    }
  }

  DOCTEST_SUBCASE("Initial user data")
  {
    const auto user_data_string = "BOB";
    user_id = gen.add_user({user_cert, user_data_string});
    gen.finalize();

    read_user_info =
      create_request(read_params(user_id, Tables::USERS), "read");

    {
      DOCTEST_INFO("initial user data object can be read");
      const auto read_response = parse_response_body<ccf::UserInfo>(
        frontend_process(frontend, read_user_info, member_cert));
      DOCTEST_CHECK(read_response.user_data == user_data_string);
    }
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
      create_signed_request(proposal, "proposals", kp, member_cert);
    const auto propose_response = parse_response_body<Propose::Out>(
      frontend_process(frontend, proposal_serialized, member_cert));

    DOCTEST_CHECK(propose_response.state == ProposalState::OPEN);

    {
      // vote for own proposal
      Script vote_yes("return true");
      const auto vote = create_signed_request(
        Vote{vote_yes},
        fmt::format("proposals/{}/votes", propose_response.proposal_id),
        kp,
        member_cert);
      const auto r = frontend_process(frontend, vote, member_cert);
      const auto result = parse_response_body<ProposalInfo>(r);
      DOCTEST_CHECK(result.state == ProposalState::ACCEPTED);
    }

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
      create_signed_request(proposal, "proposals", kp, member_cert);
    const auto propose_response = parse_response_body<Propose::Out>(
      frontend_process(frontend, proposal_serialized, member_cert));
    DOCTEST_CHECK(propose_response.state == ProposalState::OPEN);

    {
      // vote for own proposal
      Script vote_yes("return true");
      const auto vote = create_signed_request(
        Vote{vote_yes},
        fmt::format("proposals/{}/votes", propose_response.proposal_id),
        kp,
        member_cert);
      const auto r = frontend_process(frontend, vote, member_cert);
      const auto result = parse_response_body<ProposalInfo>(r);
      DOCTEST_CHECK(result.state == ProposalState::ACCEPTED);
    }

    DOCTEST_INFO("user data object can be read");
    const auto response = parse_response_body<ccf::UserInfo>(
      frontend_process(frontend, read_user_info, member_cert));
    DOCTEST_CHECK(response.user_data == user_data_string);
  }
}

DOCTEST_TEST_CASE("Submit recovery shares")
{
  NetworkState network;
  NodeId node_id = 0;
  network.ledger_secrets = std::make_shared<LedgerSecrets>(node_id);
  network.ledger_secrets->init();

  ShareManager share_manager(network);
  StubRecoverableNodeState node(share_manager);
  MemberRpcFrontend frontend(network, node, share_manager);
  std::map<size_t, std::pair<tls::Pem, tls::RSAKeyPairPtr>> members;

  size_t members_count = 4;
  size_t recovery_threshold = 2;
  DOCTEST_REQUIRE(recovery_threshold <= members_count);
  std::map<size_t, std::vector<uint8_t>> retrieved_shares;

  DOCTEST_INFO("Setup state");
  {
    auto gen_tx = network.tables->create_tx();
    GenesisGenerator gen(network, gen_tx);
    gen.init_values();
    gen.create_service({});

    for (size_t i = 0; i < members_count; i++)
    {
      auto cert = get_cert(i, kp);
      auto enc_kp = tls::make_rsa_key_pair();

      auto id = gen.add_member({cert, enc_kp->public_key_pem()});
      gen.activate_member(id);
      members[id] = {cert, enc_kp};
    }
    gen.init_configuration({recovery_threshold});
    share_manager.issue_recovery_shares(gen_tx);
    gen.finalize();
    frontend.open();
  }

  DOCTEST_INFO("Retrieve and decrypt recovery shares");
  {
    const auto get_recovery_shares =
      create_request(nullptr, "recovery_share", HTTP_GET);

    for (auto const& m : members)
    {
      auto resp = parse_response_body<GetRecoveryShare::Out>(
        frontend_process(frontend, get_recovery_shares, m.second.first));

      auto encrypted_share = tls::raw_from_b64(resp.encrypted_share);
      retrieved_shares[m.first] = m.second.second->unwrap(encrypted_share);
    }
  }

  DOCTEST_INFO("Submit share before the service is in correct state");
  {
    MemberId member_id = 0;
    const auto submit_recovery_share = create_request(
      SubmitRecoveryShare::In{tls::b64_from_raw(retrieved_shares[member_id])},
      "recovery_share");

    check_error(
      frontend_process(
        frontend, submit_recovery_share, members[member_id].first),
      HTTP_STATUS_FORBIDDEN);
  }

  DOCTEST_INFO("Change service state to waiting for recovery shares");
  {
    auto tx = network.tables->create_tx();
    GenesisGenerator g(network, tx);
    DOCTEST_REQUIRE(g.service_wait_for_shares());
    g.finalize();
  }

  DOCTEST_INFO(
    "Threshold cannot be changed while service is waiting for shares");
  {
    auto tx = network.tables->create_tx();
    GenesisGenerator g(network, tx);
    DOCTEST_REQUIRE_FALSE(g.set_recovery_threshold(recovery_threshold));
  }

  DOCTEST_INFO("Submit bogus recovery shares");
  {
    size_t submitted_shares_count = 0;
    for (auto const& m : members)
    {
      auto bogus_recovery_share = retrieved_shares[m.first];
      bogus_recovery_share[0] = bogus_recovery_share[0] + 1;
      const auto submit_recovery_share = create_request(
        SubmitRecoveryShare::In{tls::b64_from_raw(bogus_recovery_share)},
        "recovery_share");

      auto rep =
        frontend_process(frontend, submit_recovery_share, m.second.first);

      submitted_shares_count++;

      auto tx = network.tables->create_tx();
      auto submitted_shares = tx.rw(network.submitted_shares);
      // Share submission should only complete when the recovery threshold
      // has been reached
      if (submitted_shares_count >= recovery_threshold)
      {
        check_error(rep, HTTP_STATUS_INTERNAL_SERVER_ERROR);

        // On error, all submitted shares should have been cleared
        size_t submitted_shares_count = 0;
        submitted_shares->foreach(
          [&submitted_shares_count](const auto& member_id, const auto& share) {
            submitted_shares_count++;
            return true;
          });
        DOCTEST_REQUIRE(submitted_shares_count == 0);
        break;
      }
      else
      {
        DOCTEST_REQUIRE(submitted_shares->has(m.first));
      }
    }
  }

  // It is still possible to re-submit recovery shares if a threshold of at
  // least one bogus share has been submitted.

  DOCTEST_INFO("Submit recovery shares");
  {
    size_t submitted_shares_count = 0;
    for (auto const& m : members)
    {
      const auto submit_recovery_share = create_request(
        SubmitRecoveryShare::In{tls::b64_from_raw(retrieved_shares[m.first])},
        "recovery_share");

      auto rep =
        frontend_process(frontend, submit_recovery_share, m.second.first);

      submitted_shares_count++;

      // Share submission should only complete when the recovery threshold
      // has been reached
      if (submitted_shares_count >= recovery_threshold)
      {
        DOCTEST_REQUIRE(
          parse_response_body(rep).find(
            "End of recovery procedure initiated.") != std::string::npos);
        break;
      }
    }
  }
}

DOCTEST_TEST_CASE("Number of active members with recovery shares limits")
{
  auto level_before = logger::config::level();
  logger::config::level() = logger::INFO;

  NetworkState network;
  network.ledger_secrets = std::make_shared<LedgerSecrets>();
  network.ledger_secrets->init();
  network.tables->set_encryptor(encryptor);
  ShareManager share_manager(network);
  StubNodeState node;
  MemberRpcFrontend frontend(network, node, share_manager);
  frontend.open();

  std::map<size_t, tls::Pem> members;

  auto gen_tx = network.tables->create_tx();
  GenesisGenerator gen(network, gen_tx);
  gen.init_values();
  gen.create_service({});
  gen.init_configuration({1});
  set_whitelists(gen);
  gen.set_gov_scripts(lua::Interpreter().invoke<json>(gov_script_file));

  DOCTEST_INFO("Add one too many members with recovery share");
  {
    // Members are not yet active
    for (size_t i = 0; i < max_active_recovery_members + 1; i++)
    {
      auto cert = get_cert(i, kp);
      members[gen.add_member({cert, dummy_enc_pubk})] = cert;
    }
    gen.finalize();
  }

  DOCTEST_INFO("Activate members until reaching limit");
  {
    for (auto const& m : members)
    {
      auto resp = activate(frontend, kp, m.second);

      if (m.first >= max_active_recovery_members)
      {
        DOCTEST_CHECK(resp.status == HTTP_STATUS_FORBIDDEN);
      }
      else
      {
        DOCTEST_CHECK(resp.status == HTTP_STATUS_NO_CONTENT);
      }
    }
  }

  DOCTEST_INFO("It is still OK to add and activate a non-recovery member");
  {
    auto gen_tx = network.tables->create_tx();
    GenesisGenerator gen(network, gen_tx);
    auto cert = get_cert(members.size(), kp);
    gen.add_member(cert); // No public encryption key added
    gen.finalize();
    auto resp = activate(frontend, kp, cert);

    DOCTEST_CHECK(resp.status == HTTP_STATUS_NO_CONTENT);
  }

  // Revert logging
  logger::config::level() = level_before;
}

DOCTEST_TEST_CASE("Open network sequence")
{
  // Setup original state
  NetworkState network(ConsensusType::CFT);
  network.ledger_secrets = std::make_shared<LedgerSecrets>();
  network.ledger_secrets->init();

  ShareManager share_manager(network);
  StubNodeState node;
  MemberRpcFrontend frontend(network, node, share_manager);
  std::map<size_t, std::pair<tls::Pem, std::vector<uint8_t>>> members;

  size_t members_count = 4;
  size_t recovery_threshold = 100;
  DOCTEST_REQUIRE(members_count < recovery_threshold);

  DOCTEST_INFO("Setup state");
  {
    auto gen_tx = network.tables->create_tx();
    GenesisGenerator gen(network, gen_tx);
    gen.init_values();
    gen.create_service({});

    // Adding accepted members
    for (size_t i = 0; i < members_count; i++)
    {
      auto cert = get_cert(i, kp);
      auto id = gen.add_member({cert, dummy_enc_pubk});
      members[id] = {cert, {}};
    }
    gen.init_configuration({recovery_threshold});
    gen.finalize();
    frontend.open();
  }

  DOCTEST_INFO("Open fails as recovery threshold is too high");
  {
    auto gen_tx = network.tables->create_tx();
    GenesisGenerator gen(network, gen_tx);

    DOCTEST_REQUIRE_FALSE(gen.open_service());
  }

  DOCTEST_INFO("Activate all members - open still fails");
  {
    auto gen_tx = network.tables->create_tx();
    GenesisGenerator gen(network, gen_tx);
    for (auto const& m : members)
    {
      gen.activate_member(m.first);
    }
    DOCTEST_REQUIRE_FALSE(gen.open_service());
    gen.finalize();
  }

  DOCTEST_INFO("Reduce recovery threshold");
  {
    auto gen_tx = network.tables->create_tx();
    GenesisGenerator gen(network, gen_tx);
    gen.set_recovery_threshold(members_count);

    DOCTEST_REQUIRE(gen.open_service());
  }
}

int main(int argc, char** argv)
{
  doctest::Context context;
  context.applyCommandLine(argc, argv);
  int res = context.run();
  if (context.shouldExit())
    return res;
  return res;
}
