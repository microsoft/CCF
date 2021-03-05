// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "node/rpc/test/frontend_test_infra.h"

DOCTEST_TEST_CASE("Unique proposal ids")
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
  const auto proposed_member = get_cert(2, kp);

  Propose::In proposal;
  proposal.script = std::string(R"xxx(
    tables, member_info = ...
    for i = 1,10000000,1
    do
    u = i ^ 0.5
    end
    return Calls:call("new_member", member_info)
  )xxx");
  proposal.parameter["cert"] = proposed_member;
  proposal.parameter["encryption_pub_key"] = dummy_enc_pubk;
  const auto propose =
    create_signed_request(proposal, "proposals", kp, proposer_cert);

  Propose::Out out1;
  Propose::Out out2;

  auto fn = [](
              MemberRpcFrontend& f,
              const std::vector<uint8_t>& r,
              const crypto::Pem& i,
              Propose::Out& o) {
    const auto rs = frontend_process(f, r, i);
    o = parse_response_body<Propose::Out>(rs);
  };

  auto t1 = std::thread(
    fn,
    std::ref(frontend),
    std::ref(propose),
    std::ref(proposer_cert),
    std::ref(out1));
  auto t2 = std::thread(
    fn,
    std::ref(frontend),
    std::ref(propose),
    std::ref(proposer_cert),
    std::ref(out2));
  t1.join();
  t2.join();

  DOCTEST_CHECK(out1.state == ProposalState::OPEN);
  DOCTEST_CHECK(out2.state == ProposalState::OPEN);
  DOCTEST_CHECK(out1.proposal_id != out2.proposal_id);

  auto metrics_req = create_request(nlohmann::json(), "api/metrics", HTTP_GET);
  auto metrics = frontend_process(frontend, metrics_req, proposer_cert);
  auto metrics_json = serdes::unpack(metrics.body, serdes::Pack::Text);
  for (auto& row : metrics_json["metrics"])
  {
    if (row["path"] == "proposals")
    {
      DOCTEST_CHECK(row["retries"] == 1);
    }
  }
}

class NullTxHistoryWithOverride : public ccf::NullTxHistory
{
  kv::Version forced_version;
  bool forced = false;

public:
  NullTxHistoryWithOverride(
    kv::Store& store_, const NodeId& id_, crypto::KeyPair& kp_) :
    ccf::NullTxHistory(store_, id_, kp_)
  {}

  void force_version(kv::Version v)
  {
    forced_version = v;
    forced = true;
  }

  std::pair<kv::TxID, crypto::Sha256Hash> get_replicated_state_txid_and_root()
    override
  {
    if (forced)
    {
      forced = false;
      return {{term, forced_version},
              crypto::Sha256Hash(std::to_string(version))};
    }
    else
    {
      return {{term, version}, crypto::Sha256Hash(std::to_string(version))};
    }
  }
};

DOCTEST_TEST_CASE("Compaction conflict")
{
  NetworkState network;
  network.tables->set_encryptor(encryptor);
  auto history = std::make_shared<NullTxHistoryWithOverride>(
    *network.tables, kv::test::PrimaryNodeId, *kp);
  network.tables->set_history(history);
  auto consensus = std::make_shared<kv::test::PrimaryStubConsensus>();
  network.tables->set_consensus(consensus);
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

  // Stub transaction, at which we can compact
  auto tx = network.tables->create_tx();
  tx.rw(network.values)->put(42, 42);
  DOCTEST_CHECK(tx.commit() == kv::CommitResult::SUCCESS);
  auto cv = tx.get_version();
  network.tables->compact(cv);

  ShareManager share_manager(network);
  StubNodeState node;
  MemberRpcFrontend frontend(network, node, share_manager);

  frontend.open();
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

  // Force history version to an already compacted version to trigger compaction
  // conflict
  history->force_version(cv - 1);

  const auto rs = frontend_process(frontend, propose, proposer_cert);
  const auto out = parse_response_body<Propose::Out>(rs);
  DOCTEST_CHECK(out.state == ProposalState::OPEN);

  auto metrics_req = create_request(nlohmann::json(), "api/metrics", HTTP_GET);
  auto metrics = frontend_process(frontend, metrics_req, proposer_cert);
  auto metrics_json = serdes::unpack(metrics.body, serdes::Pack::Text);
  for (auto& row : metrics_json["metrics"])
  {
    if (row["path"] == "proposals")
    {
      DOCTEST_CHECK(row["retries"] == 1);
    }
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
