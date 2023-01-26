// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "node/rpc/test/frontend_test_infra.h"

std::unique_ptr<threading::ThreadMessaging>
  threading::ThreadMessaging::singleton = nullptr;

constexpr auto test_constitution = R"xxx(
export function validate(input) {
  return { valid: true, description: "All good" };
}
export function resolve(proposal, proposerId, votes) {
  // Busy wait
  let u = 0;
  for (let i = 0; i < 1000000; i++) {
    u = i ^ 0.5;
  }
  return "Open";
}
export function apply(proposal, proposalId) {
}
)xxx";

DOCTEST_TEST_CASE("Unique proposal ids")
{
  NetworkState network;
  init_network(network);
  auto gen_tx = network.tables->create_tx();
  GenesisGenerator gen(network, gen_tx);
  gen.create_service(network.identity->cert, ccf::TxID{});

  const auto proposer_cert = get_cert(0, kp);
  const auto proposer_id = gen.add_member(proposer_cert);
  gen.activate_member(proposer_id);
  const auto voter_cert = get_cert(1, kp);
  const auto voter_id = gen.add_member(voter_cert);
  gen.activate_member(voter_id);

  gen.set_constitution(test_constitution);

  DOCTEST_REQUIRE(gen_tx.commit() == kv::CommitResult::SUCCESS);

  ShareManager share_manager(network);
  StubNodeContext context;
  MemberRpcFrontend frontend(network, context, share_manager);

  frontend.open();
  const auto proposed_member = get_cert(2, kp);

  nlohmann::json proposal_body = "Ignored";
  const auto propose =
    create_signed_request(proposal_body, "proposals", kp, proposer_cert);

  jsgov::ProposalInfoSummary out1;
  jsgov::ProposalInfoSummary out2;

  auto fn = [](
              MemberRpcFrontend& f,
              const std::vector<uint8_t>& r,
              const crypto::Pem& i,
              jsgov::ProposalInfoSummary& o) {
    const auto rs = frontend_process(f, r, i);
    o = parse_response_body<jsgov::ProposalInfoSummary>(rs);
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

  // Count retries to confirm that these proposals conflicted and one was
  // retried (potentially multiple times, if very unlucky and gets a retried
  // root before the earlier transaction has set it)
  auto metrics_req = create_request(nlohmann::json(), "api/metrics", HTTP_GET);
  auto metrics = frontend_process(frontend, metrics_req, proposer_cert);
  auto metrics_json = serdes::unpack(metrics.body, serdes::Pack::Text);
  for (auto& row : metrics_json["metrics"])
  {
    if (row["path"] == "proposals")
    {
      DOCTEST_CHECK(row["retries"] >= 1);
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

  std::tuple<kv::TxID, crypto::Sha256Hash, kv::Term>
  get_replicated_state_txid_and_root() override
  {
    if (forced)
    {
      forced = false;
      return {
        {term_of_last_version, forced_version},
        crypto::Sha256Hash(std::to_string(version)),
        term_of_next_version};
    }
    else
    {
      return {
        {term_of_last_version, version},
        crypto::Sha256Hash(std::to_string(version)),
        term_of_next_version};
    }
  }
};

DOCTEST_TEST_CASE("Compaction conflict")
{
  NetworkState network;
  init_network(network);
  network.tables->set_encryptor(encryptor);
  auto history = std::make_shared<NullTxHistoryWithOverride>(
    *network.tables, kv::test::PrimaryNodeId, *kp);
  network.tables->set_history(history);
  auto consensus = std::make_shared<kv::test::PrimaryStubConsensus>();
  network.tables->set_consensus(consensus);
  auto gen_tx = network.tables->create_tx();
  GenesisGenerator gen(network, gen_tx);
  gen.create_service(network.identity->cert, ccf::TxID{});

  const auto proposer_cert = get_cert(0, kp);
  const auto proposer_id = gen.add_member(proposer_cert);
  gen.activate_member(proposer_id);
  const auto voter_cert = get_cert(1, kp);
  const auto voter_id = gen.add_member(voter_cert);
  gen.activate_member(voter_id);

  gen.set_constitution(test_constitution);

  DOCTEST_REQUIRE(gen_tx.commit() == kv::CommitResult::SUCCESS);

  // Stub transaction, at which we can compact. Write to a table which the
  // proposal execution will try to read, so that it tries to retrieve a
  // MapHandle at this forced compacted version
  auto tx = network.tables->create_tx();
  tx.rw(network.member_info)->put({}, {});
  DOCTEST_CHECK(tx.commit() == kv::CommitResult::SUCCESS);
  auto cv = tx.commit_version();
  network.tables->compact(cv);

  ShareManager share_manager(network);
  StubNodeContext context;
  MemberRpcFrontend frontend(network, context, share_manager);

  frontend.open();
  const auto proposed_member = get_cert(2, kp);

  nlohmann::json proposal_body = "Ignored";
  const auto propose =
    create_signed_request(proposal_body, "proposals", kp, proposer_cert);

  // Force history version to an already compacted version to trigger compaction
  // conflict
  history->force_version(cv - 1);

  const auto rs = frontend_process(frontend, propose, proposer_cert);
  const auto out = parse_response_body<jsgov::ProposalInfoSummary>(rs);
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
  js::register_class_ids();

  // Require 3 task queues, because "Unique proposal ids" starts 2 worker
  // threads
  threading::ThreadMessaging::init(3);
  doctest::Context context;
  context.applyCommandLine(argc, argv);
  int res = context.run();
  if (context.shouldExit())
    return res;
  return res;
}
