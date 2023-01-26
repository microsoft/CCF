// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "test_common.h"

#define DOCTEST_CONFIG_NO_SHORT_MACRO_NAMES
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

std::unique_ptr<threading::ThreadMessaging>
  threading::ThreadMessaging::singleton = nullptr;

using ms = std::chrono::milliseconds;

DOCTEST_TEST_CASE("Single node startup" * doctest::test_suite("single"))
{
  ccf::NodeId node_id = kv::test::PrimaryNodeId;
  auto kv_store = std::make_shared<Store>(node_id);

  TRaft r0(
    raft_settings,
    std::make_unique<Adaptor>(kv_store),
    std::make_unique<aft::LedgerStubProxy>(node_id),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::State>(node_id),
    nullptr,
    nullptr);
  r0.start_ticking();

  kv::Configuration::Nodes config;
  config.try_emplace(node_id);
  r0.add_configuration(0, config);

  DOCTEST_INFO("DOCTEST_REQUIRE Initial State");

  DOCTEST_REQUIRE(!r0.is_primary());
  DOCTEST_REQUIRE(!r0.primary().has_value());
  DOCTEST_REQUIRE(r0.get_view() == 0);
  DOCTEST_REQUIRE(r0.get_committed_seqno() == 0);

  DOCTEST_INFO(
    "In the absence of other nodes, become leader after election timeout");

  r0.periodic(ms(0));
  DOCTEST_REQUIRE(!r0.is_primary());

  r0.periodic(election_timeout * 2);
  DOCTEST_REQUIRE(r0.is_primary());
  DOCTEST_REQUIRE(r0.primary() == node_id);
}

DOCTEST_TEST_CASE("Single node commit" * doctest::test_suite("single"))
{
  ccf::NodeId node_id = kv::test::PrimaryNodeId;
  auto kv_store = std::make_shared<Store>(node_id);

  TRaft r0(
    raft_settings,
    std::make_unique<Adaptor>(kv_store),
    std::make_unique<aft::LedgerStubProxy>(node_id),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::State>(node_id),
    nullptr,
    nullptr);

  aft::Configuration::Nodes config;
  config[node_id] = {};
  r0.add_configuration(0, config);

  DOCTEST_INFO("Become leader after election timeout");

  r0.start_ticking();
  r0.periodic(election_timeout * 2);
  DOCTEST_REQUIRE(r0.is_primary());

  DOCTEST_INFO("Observe that data is committed on replicate immediately");

  for (size_t i = 1; i <= 5; ++i)
  {
    auto entry = std::make_shared<std::vector<uint8_t>>();
    entry->push_back(1);
    entry->push_back(2);
    entry->push_back(3);

    auto hooks = std::make_shared<kv::ConsensusHookPtrs>();

    r0.replicate(kv::BatchVector{{i, entry, true, hooks}}, 1);
    DOCTEST_REQUIRE(r0.get_last_idx() == i);
    DOCTEST_REQUIRE(r0.get_committed_seqno() == i);
  }
}

DOCTEST_TEST_CASE(
  "Multiple nodes startup and election" * doctest::test_suite("multiple"))
{
  ccf::NodeId node_id0 = kv::test::PrimaryNodeId;
  ccf::NodeId node_id1 = kv::test::FirstBackupNodeId;
  ccf::NodeId node_id2 = kv::test::SecondBackupNodeId;
  ccf::NodeId node_id3 = kv::test::ThirdBackupNodeId;

  auto kv_store0 = std::make_shared<Store>(node_id0);
  auto kv_store1 = std::make_shared<Store>(node_id1);
  auto kv_store2 = std::make_shared<Store>(node_id2);
  auto kv_store3 = std::make_shared<Store>(node_id3);

  TRaft r0(
    raft_settings,
    std::make_unique<Adaptor>(kv_store0),
    std::make_unique<aft::LedgerStubProxy>(node_id0),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::State>(node_id0),
    nullptr,
    nullptr);
  TRaft r1(
    raft_settings,
    std::make_unique<Adaptor>(kv_store1),
    std::make_unique<aft::LedgerStubProxy>(node_id1),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::State>(node_id1),
    nullptr,
    nullptr);
  TRaft r2(
    raft_settings,
    std::make_unique<Adaptor>(kv_store2),
    std::make_unique<aft::LedgerStubProxy>(node_id2),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::State>(node_id2),
    nullptr,
    nullptr);
  TRaft r3(
    raft_settings,
    std::make_unique<Adaptor>(kv_store3),
    std::make_unique<aft::LedgerStubProxy>(node_id3),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::State>(node_id3),
    nullptr,
    nullptr);

  aft::Configuration::Nodes config;
  config[node_id0] = {};
  config[node_id1] = {};
  config[node_id2] = {};
  config[node_id3] = {};
  r0.add_configuration(0, config);
  r1.add_configuration(0, config);
  r2.add_configuration(0, config);
  r3.add_configuration(0, config);

  auto r0c = channel_stub_proxy(r0);
  auto r1c = channel_stub_proxy(r1);
  auto r2c = channel_stub_proxy(r2);
  auto r3c = channel_stub_proxy(r3);

  DOCTEST_INFO("Node 0 exceeds its election timeout and starts an election");

  r0.start_ticking();
  r0.periodic(election_timeout * 2);
  DOCTEST_REQUIRE(
    r0c->count_messages_with_type(aft::RaftMsgType::raft_request_vote) == 3);

  DOCTEST_INFO("Node 1 receives the request vote");

  auto rv_raw = r0c->pop_first(aft::RaftMsgType::raft_request_vote, node_id1);
  DOCTEST_REQUIRE(rv_raw.has_value());
  {
    auto rvc = *(aft::RequestVote*)rv_raw->data();
    DOCTEST_REQUIRE(rvc.term == 1);
    DOCTEST_REQUIRE(rvc.last_committable_idx == 0);
    DOCTEST_REQUIRE(
      rvc.term_of_last_committable_idx == aft::ViewHistory::InvalidView);
  }

  receive_message(r0, r1, *rv_raw);

  DOCTEST_INFO("Node 2 receives the request vote");

  rv_raw = r0c->pop_first(aft::RaftMsgType::raft_request_vote, node_id2);
  DOCTEST_REQUIRE(rv_raw.has_value());
  {
    auto rvc = *(aft::RequestVote*)rv_raw->data();
    DOCTEST_REQUIRE(rvc.term == 1);
    DOCTEST_REQUIRE(rvc.last_committable_idx == 0);
    DOCTEST_REQUIRE(
      rvc.term_of_last_committable_idx == aft::ViewHistory::InvalidView);
  }

  receive_message(r0, r2, *rv_raw);

  DOCTEST_INFO("Node 1 votes for Node 0");

  DOCTEST_REQUIRE(
    r1c->count_messages_with_type(
      aft::RaftMsgType::raft_request_vote_response) == 1);

  auto rvr_raw =
    r1c->pop_first(aft::RaftMsgType::raft_request_vote_response, node_id0);
  DOCTEST_REQUIRE(rvr_raw.has_value());
  {
    auto rvrc = *(aft::RequestVoteResponse*)rvr_raw->data();
    DOCTEST_REQUIRE(rvrc.term == 1);
    DOCTEST_REQUIRE(rvrc.vote_granted);
  }

  receive_message(r1, r0, *rvr_raw);

  DOCTEST_INFO("Node 2 votes for Node 0");

  DOCTEST_REQUIRE(
    r2c->count_messages_with_type(
      aft::RaftMsgType::raft_request_vote_response) == 1);

  rvr_raw =
    r2c->pop_first(aft::RaftMsgType::raft_request_vote_response, node_id0);
  DOCTEST_REQUIRE(rvr_raw.has_value());
  {
    auto rvrc = *(aft::RequestVoteResponse*)rvr_raw->data();
    DOCTEST_REQUIRE(rvrc.term == 1);
    DOCTEST_REQUIRE(rvrc.vote_granted);
  }

  receive_message(r2, r0, *rvr_raw);

  DOCTEST_INFO(
    "Node 0 is now leader, and sends empty append entries to other nodes");

  DOCTEST_REQUIRE(r0.is_primary());
  DOCTEST_REQUIRE(
    r0c->count_messages_with_type(aft::RaftMsgType::raft_append_entries) == 3);

  auto ae_raw = r0c->pop_first(aft::RaftMsgType::raft_append_entries, node_id1);
  DOCTEST_REQUIRE(ae_raw.has_value());
  {
    auto aec = *(aft::AppendEntries*)ae_raw->data();
    DOCTEST_REQUIRE(aec.idx == 0);
    DOCTEST_REQUIRE(aec.term == 1);
    DOCTEST_REQUIRE(aec.prev_idx == 0);
    DOCTEST_REQUIRE(aec.prev_term == aft::ViewHistory::InvalidView);
    DOCTEST_REQUIRE(aec.leader_commit_idx == 0);
  }

  ae_raw = r0c->pop_first(aft::RaftMsgType::raft_append_entries, node_id2);
  DOCTEST_REQUIRE(ae_raw.has_value());
  {
    auto aec = *(aft::AppendEntries*)ae_raw->data();
    DOCTEST_REQUIRE(aec.idx == 0);
    DOCTEST_REQUIRE(aec.term == 1);
    DOCTEST_REQUIRE(aec.prev_idx == 0);
    DOCTEST_REQUIRE(aec.prev_term == aft::ViewHistory::InvalidView);
    DOCTEST_REQUIRE(aec.leader_commit_idx == 0);
  }

  // See https://github.com/microsoft/CCF/issues/3808
  DOCTEST_INFO("Node 3 finds out that Node 0 is primary from append entries");

  // Intercept vote request from 0 to 3
  auto vote_for_r0 =
    r0c->pop_first(aft::RaftMsgType::raft_request_vote, node_id3);
  rvr_raw = r0c->pop_first(aft::RaftMsgType::raft_append_entries, node_id3);

  receive_message(r0, r3, *rvr_raw);

  auto r3_primary = r3.primary();
  DOCTEST_REQUIRE(r3_primary.has_value());
  DOCTEST_REQUIRE(r3_primary.value() == r0.id());

  DOCTEST_INFO(
    "Node 3 does not grant its vote to Node 0 since the primary node is now "
    "known");

  receive_message(r0, r3, *vote_for_r0);

  auto vote_resp_raw =
    r3c->pop_first(aft::RaftMsgType::raft_request_vote_response, node_id0);
  DOCTEST_REQUIRE(vote_resp_raw.has_value());
  {
    auto vr = *(aft::RequestVoteResponse*)vote_resp_raw->data();
    DOCTEST_REQUIRE(vr.vote_granted == false);
  }
}

DOCTEST_TEST_CASE(
  "Multiple nodes append entries" * doctest::test_suite("multiple"))
{
  ccf::NodeId node_id0 = kv::test::PrimaryNodeId;
  ccf::NodeId node_id1 = kv::test::FirstBackupNodeId;
  ccf::NodeId node_id2 = kv::test::SecondBackupNodeId;

  auto kv_store0 = std::make_shared<Store>(node_id0);
  auto kv_store1 = std::make_shared<Store>(node_id1);
  auto kv_store2 = std::make_shared<Store>(node_id2);

  TRaft r0(
    raft_settings,
    std::make_unique<Adaptor>(kv_store0),
    std::make_unique<aft::LedgerStubProxy>(node_id0),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::State>(node_id0),
    nullptr,
    nullptr);
  TRaft r1(
    raft_settings,
    std::make_unique<Adaptor>(kv_store1),
    std::make_unique<aft::LedgerStubProxy>(node_id1),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::State>(node_id1),
    nullptr,
    nullptr);
  TRaft r2(
    raft_settings,
    std::make_unique<Adaptor>(kv_store2),
    std::make_unique<aft::LedgerStubProxy>(node_id2),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::State>(node_id2),
    nullptr,
    nullptr);

  aft::Configuration::Nodes config;
  config[node_id0] = {};
  config[node_id1] = {};
  config[node_id2] = {};
  r0.add_configuration(0, config);
  r1.add_configuration(0, config);
  r2.add_configuration(0, config);

  std::map<ccf::NodeId, TRaft*> nodes;
  nodes[node_id0] = &r0;
  nodes[node_id1] = &r1;
  nodes[node_id2] = &r2;

  auto r0c = channel_stub_proxy(r0);
  auto r1c = channel_stub_proxy(r1);
  auto r2c = channel_stub_proxy(r2);

  r0.start_ticking();
  r0.periodic(election_timeout * 2);

  DOCTEST_INFO("Send request_votes to other nodes");
  DOCTEST_REQUIRE(2 == dispatch_all(nodes, node_id0, r0c->messages));

  DOCTEST_INFO("Send request_vote_reponses back");
  DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_id1, r1c->messages));
  DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_id2, r2c->messages));

  DOCTEST_INFO("Send empty append_entries to other nodes");
  DOCTEST_REQUIRE(2 == dispatch_all(nodes, node_id0, r0c->messages));

  DOCTEST_INFO("Send append_entries_reponses back");
  DOCTEST_REQUIRE(
    1 ==
    dispatch_all_and_DOCTEST_CHECK<aft::AppendEntriesResponse>(
      nodes, node_id1, r1c->messages, [](const auto& msg) {
        DOCTEST_REQUIRE(msg.last_log_idx == 0);
        DOCTEST_REQUIRE(msg.success == aft::AppendEntriesResponseType::OK);
      }));
  DOCTEST_REQUIRE(
    1 ==
    dispatch_all_and_DOCTEST_CHECK<aft::AppendEntriesResponse>(
      nodes, node_id2, r2c->messages, [](const auto& msg) {
        DOCTEST_REQUIRE(msg.last_log_idx == 0);
        DOCTEST_REQUIRE(msg.success == aft::AppendEntriesResponseType::OK);
      }));

  DOCTEST_INFO("There ought to be no messages pending anywhere now");
  DOCTEST_REQUIRE(r0c->messages.size() == 0);
  DOCTEST_REQUIRE(r1c->messages.size() == 0);
  DOCTEST_REQUIRE(r2c->messages.size() == 0);

  DOCTEST_INFO("Try to replicate on a follower, and fail");
  std::vector<uint8_t> entry = {1, 2, 3};
  auto data = std::make_shared<std::vector<uint8_t>>(entry);
  auto hooks = std::make_shared<kv::ConsensusHookPtrs>();
  DOCTEST_REQUIRE_FALSE(
    r1.replicate(kv::BatchVector{{1, data, true, hooks}}, 1));

  DOCTEST_INFO("Tell the leader to replicate a message");
  DOCTEST_REQUIRE(r0.replicate(kv::BatchVector{{1, data, true, hooks}}, 1));
  DOCTEST_REQUIRE(r0.ledger->ledger.size() == 1);

  // The test ledger adds its own header. Confirm that the expected data is
  // present, at the end of this ledger entry
  const auto& actual = r0.ledger->ledger.front();
  DOCTEST_REQUIRE(actual.size() >= entry.size());
  for (size_t i = 0; i < entry.size(); ++i)
  {
    DOCTEST_REQUIRE(actual[actual.size() - entry.size() + i] == entry[i]);
  }
  DOCTEST_INFO("The other nodes are not told about this yet");
  DOCTEST_REQUIRE(r0c->messages.size() == 0);

  r0.periodic(request_timeout);

  DOCTEST_INFO("Now the other nodes are sent append_entries");
  DOCTEST_REQUIRE(
    2 ==
    dispatch_all_and_DOCTEST_CHECK<aft::AppendEntries>(
      nodes, node_id0, r0c->messages, [](const auto& msg) {
        DOCTEST_REQUIRE(msg.idx == 1);
        DOCTEST_REQUIRE(msg.term == 1);
        DOCTEST_REQUIRE(msg.prev_idx == 0);
        DOCTEST_REQUIRE(msg.prev_term == aft::ViewHistory::InvalidView);
        DOCTEST_REQUIRE(msg.leader_commit_idx == 0);
      }));

  DOCTEST_INFO("Which they acknowledge correctly");
  DOCTEST_REQUIRE(
    1 ==
    dispatch_all_and_DOCTEST_CHECK<aft::AppendEntriesResponse>(
      nodes, node_id1, r1c->messages, [](const auto& msg) {
        DOCTEST_REQUIRE(msg.last_log_idx == 1);
        DOCTEST_REQUIRE(msg.success == aft::AppendEntriesResponseType::OK);
      }));
  DOCTEST_REQUIRE(
    1 ==
    dispatch_all_and_DOCTEST_CHECK<aft::AppendEntriesResponse>(
      nodes, node_id2, r2c->messages, [](const auto& msg) {
        DOCTEST_REQUIRE(msg.last_log_idx == 1);
        DOCTEST_REQUIRE(msg.success == aft::AppendEntriesResponseType::OK);
      }));
}

DOCTEST_TEST_CASE("Multiple nodes late join" * doctest::test_suite("multiple"))
{
  ccf::NodeId node_id0 = kv::test::PrimaryNodeId;
  ccf::NodeId node_id1 = kv::test::FirstBackupNodeId;
  ccf::NodeId node_id2 = kv::test::SecondBackupNodeId;

  auto kv_store0 = std::make_shared<Store>(node_id0);
  auto kv_store1 = std::make_shared<Store>(node_id1);
  auto kv_store2 = std::make_shared<Store>(node_id2);

  TRaft r0(
    raft_settings,
    std::make_unique<Adaptor>(kv_store0),
    std::make_unique<aft::LedgerStubProxy>(node_id0),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::State>(node_id0),
    nullptr,
    nullptr);
  TRaft r1(
    raft_settings,
    std::make_unique<Adaptor>(kv_store1),
    std::make_unique<aft::LedgerStubProxy>(node_id1),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::State>(node_id1),
    nullptr,
    nullptr);
  TRaft r2(
    raft_settings,
    std::make_unique<Adaptor>(kv_store2),
    std::make_unique<aft::LedgerStubProxy>(node_id2),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::State>(node_id2),
    nullptr,
    nullptr);

  aft::Configuration::Nodes config;
  config[node_id0] = {};
  config[node_id1] = {};
  r0.add_configuration(0, config);
  r1.add_configuration(0, config);

  std::map<ccf::NodeId, TRaft*> nodes;
  nodes[node_id0] = &r0;
  nodes[node_id1] = &r1;

  auto r0c = channel_stub_proxy(r0);
  auto r1c = channel_stub_proxy(r1);
  auto r2c = channel_stub_proxy(r2);

  r0.start_ticking();
  r0.periodic(election_timeout * 2);

  DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_id0, r0c->messages));
  DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_id1, r1c->messages));
  DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_id0, r0c->messages));

  DOCTEST_REQUIRE(
    1 ==
    dispatch_all_and_DOCTEST_CHECK<aft::AppendEntriesResponse>(
      nodes, node_id1, r1c->messages, [](const auto& msg) {
        DOCTEST_REQUIRE(msg.last_log_idx == 0);
        DOCTEST_REQUIRE(msg.success == aft::AppendEntriesResponseType::OK);
      }));

  DOCTEST_REQUIRE(r0c->messages.size() == 0);
  DOCTEST_REQUIRE(r1c->messages.size() == 0);

  std::vector<uint8_t> first_entry = {1, 2, 3};
  auto data = std::make_shared<std::vector<uint8_t>>(first_entry);
  auto hooks = std::make_shared<kv::ConsensusHookPtrs>();
  DOCTEST_REQUIRE(r0.replicate(kv::BatchVector{{1, data, true, hooks}}, 1));
  r0.periodic(request_timeout);

  DOCTEST_REQUIRE(
    1 ==
    dispatch_all_and_DOCTEST_CHECK<aft::AppendEntries>(
      nodes, node_id0, r0c->messages, [](const auto& msg) {
        DOCTEST_REQUIRE(msg.idx == 1);
        DOCTEST_REQUIRE(msg.term == 1);
        DOCTEST_REQUIRE(msg.prev_idx == 0);
        DOCTEST_REQUIRE(msg.prev_term == aft::ViewHistory::InvalidView);
        DOCTEST_REQUIRE(msg.leader_commit_idx == 0);
      }));

  DOCTEST_REQUIRE(
    1 ==
    dispatch_all_and_DOCTEST_CHECK<aft::AppendEntriesResponse>(
      nodes, node_id1, r1c->messages, [](const auto& msg) {
        DOCTEST_REQUIRE(msg.last_log_idx == 1);
        DOCTEST_REQUIRE(msg.success == aft::AppendEntriesResponseType::OK);
      }));

  DOCTEST_INFO("Node 2 joins the ensemble");

  aft::Configuration::Nodes config1;
  config1[node_id0] = {};
  config1[node_id1] = {};
  config1[node_id2] = {};
  r0.add_configuration(0, config1);
  r1.add_configuration(0, config1);
  r2.add_configuration(0, config1);

  nodes[node_id2] = &r2;

  DOCTEST_INFO("Node 0 sends Node 2 what it's missed by joining late");
  DOCTEST_REQUIRE(r2c->messages.size() == 0);
  DOCTEST_REQUIRE(r1c->messages.size() == 0);

  DOCTEST_REQUIRE(
    1 ==
    dispatch_all_and_DOCTEST_CHECK<aft::AppendEntries>(
      nodes, node_id0, r0c->messages, [](const auto& msg) {
        DOCTEST_REQUIRE(msg.idx == 1);
        DOCTEST_REQUIRE(msg.term == 1);
        DOCTEST_REQUIRE(msg.prev_idx == 1);
        DOCTEST_REQUIRE(msg.prev_term == 1);
        DOCTEST_REQUIRE(msg.leader_commit_idx == 1);
      }));
}

DOCTEST_TEST_CASE("Recv append entries logic" * doctest::test_suite("multiple"))
{
  ccf::NodeId node_id0 = kv::test::PrimaryNodeId;
  ccf::NodeId node_id1 = kv::test::FirstBackupNodeId;

  auto kv_store0 = std::make_shared<SigStore>(node_id0);
  auto kv_store1 = std::make_shared<SigStore>(node_id1);

  TRaft r0(
    raft_settings,
    std::make_unique<SigAdaptor>(kv_store0),
    std::make_unique<aft::LedgerStubProxy>(node_id0),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::State>(node_id0),
    nullptr,
    nullptr);
  TRaft r1(
    raft_settings,
    std::make_unique<SigAdaptor>(kv_store1),
    std::make_unique<aft::LedgerStubProxy>(node_id1),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::State>(node_id1),
    nullptr,
    nullptr);
  auto hooks = std::make_shared<kv::ConsensusHookPtrs>();

  aft::Configuration::Nodes config0;
  config0[node_id0] = {};
  config0[node_id1] = {};
  r0.add_configuration(0, config0);
  r1.add_configuration(0, config0);

  std::map<ccf::NodeId, TRaft*> nodes;
  nodes[node_id0] = &r0;
  nodes[node_id1] = &r1;

  auto r0c = channel_stub_proxy(r0);
  auto r1c = channel_stub_proxy(r1);

  r0.start_ticking();
  r0.periodic(election_timeout * 2);

  DOCTEST_INFO("Initial election");
  {
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_id0, r0c->messages));
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_id1, r1c->messages));

    DOCTEST_REQUIRE(r0.is_primary());
    DOCTEST_REQUIRE(r0c->messages.size() == 1);
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_id0, r0c->messages));
    DOCTEST_REQUIRE(r0c->messages.size() == 0);
  }

  std::vector<uint8_t> ae_idx_2; // To save for later use

  DOCTEST_INFO("Replicate two entries");
  {
    std::vector<uint8_t> first_entry = {1, 1, 1};
    auto data_1 = std::make_shared<std::vector<uint8_t>>(first_entry);
    std::vector<uint8_t> second_entry = {2, 2, 2};
    auto data_2 = std::make_shared<std::vector<uint8_t>>(second_entry);

    DOCTEST_REQUIRE(r0.replicate(kv::BatchVector{{1, data_1, true, hooks}}, 1));
    DOCTEST_REQUIRE(r0.replicate(kv::BatchVector{{2, data_2, true, hooks}}, 1));
    DOCTEST_REQUIRE(r0.ledger->ledger.size() == 2);
    r0.periodic(request_timeout);
    DOCTEST_REQUIRE(r0c->messages.size() == 1);

    // Receive append entries (idx: 2, prev_idx: 0)
    ae_idx_2 = r0c->messages.front().second;
    receive_message(r0, r1, ae_idx_2);
    DOCTEST_REQUIRE(r1.ledger->ledger.size() == 2);
  }

  DOCTEST_INFO("Receiving same append entries has no effect");
  {
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_id0, r0c->messages));
    DOCTEST_REQUIRE(r1.ledger->ledger.size() == 2);
  }

  DOCTEST_INFO("Replicate one more entry but send AE all entries");
  {
    std::vector<uint8_t> third_entry = {3, 3, 3};
    auto data = std::make_shared<std::vector<uint8_t>>(third_entry);
    DOCTEST_REQUIRE(r0.replicate(kv::BatchVector{{3, data, true, hooks}}, 1));
    DOCTEST_REQUIRE(r0.ledger->ledger.size() == 3);

    // Simulate that the append entries was not deserialised successfully
    // This ensures that r0 re-sends an AE with prev_idx = 0 next time
    auto aer_v = r1c->messages.front().second;
    r1c->messages.pop_front();
    auto aer = *(aft::AppendEntriesResponse*)aer_v.data();
    aer.success = aft::AppendEntriesResponseType::FAIL;
    const auto p = reinterpret_cast<uint8_t*>(&aer);
    receive_message(r1, r0, {p, p + sizeof(aer)});
    r0.periodic(request_timeout);
    DOCTEST_REQUIRE(r0c->messages.size() == 1);

    // Only the third entry is deserialised
    r1.ledger->reset_skip_count();
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_id0, r0c->messages));
    DOCTEST_REQUIRE(r0.ledger->ledger.size() == 3);
    DOCTEST_REQUIRE(r1.ledger->skip_count == 2);
    r1.ledger->reset_skip_count();
  }

  DOCTEST_INFO("Receiving stale append entries has no effect");
  {
    receive_message(r0, r1, ae_idx_2);
    DOCTEST_REQUIRE(r1.ledger->ledger.size() == 3);
  }

  DOCTEST_INFO("Replicate one more entry (normal behaviour)");
  {
    std::vector<uint8_t> fourth_entry = {4, 4, 4};
    auto data = std::make_shared<std::vector<uint8_t>>(fourth_entry);
    DOCTEST_REQUIRE(r0.replicate(kv::BatchVector{{4, data, true, hooks}}, 1));
    DOCTEST_REQUIRE(r0.ledger->ledger.size() == 4);
    r0.periodic(request_timeout);
    DOCTEST_REQUIRE(r0c->messages.size() == 1);
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_id0, r0c->messages));
    DOCTEST_REQUIRE(r1.ledger->ledger.size() == 4);
  }

  DOCTEST_INFO(
    "Replicate one more entry without AE response from previous entry");
  {
    std::vector<uint8_t> fifth_entry = {5, 5, 5};
    auto data = std::make_shared<std::vector<uint8_t>>(fifth_entry);
    DOCTEST_REQUIRE(r0.replicate(kv::BatchVector{{5, data, true, hooks}}, 1));
    DOCTEST_REQUIRE(r0.ledger->ledger.size() == 5);
    r0.periodic(request_timeout);
    DOCTEST_REQUIRE(r0c->messages.size() == 1);
    r0c->messages.pop_front();

    // Simulate that the append entries was not deserialised successfully
    // This ensures that r0 re-sends an AE with prev_idx = 3 next time
    auto aer_v = r1c->messages.front().second;
    r1c->messages.pop_front();
    auto aer = *(aft::AppendEntriesResponse*)aer_v.data();
    aer.success = aft::AppendEntriesResponseType::FAIL;
    const auto p = reinterpret_cast<uint8_t*>(&aer);
    receive_message(r1, r0, {p, p + sizeof(aer)});
    r0.periodic(request_timeout);
    DOCTEST_REQUIRE(r0c->messages.size() == 1);

    // Receive append entries (idx: 5, prev_idx: 3)
    r1.ledger->reset_skip_count();
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_id0, r0c->messages));
    DOCTEST_REQUIRE(r1.ledger->ledger.size() == 5);
    DOCTEST_REQUIRE(r1.ledger->skip_count == 2);
  }

  DOCTEST_INFO("Receive a maliciously crafted cross-view AppendEntries");
  {
    {
      std::vector<uint8_t> entry_6 = {6, 6, 6};
      auto data = std::make_shared<std::vector<uint8_t>>(entry_6);
      DOCTEST_REQUIRE(r0.replicate(kv::BatchVector{{6, data, true, hooks}}, 1));
      DOCTEST_REQUIRE(r0.ledger->ledger.size() == 6);
    }
    const auto last_correct_version = r0.ledger->ledger.size();

    std::vector<uint8_t> dead_branch;
    {
      std::vector<uint8_t> entry_7 = {7, 7, 7};
      auto data = std::make_shared<std::vector<uint8_t>>(entry_7);
      DOCTEST_REQUIRE(r0.replicate(kv::BatchVector{{7, data, true, hooks}}, 1));
      DOCTEST_REQUIRE(r0.ledger->ledger.size() == 7);
      dead_branch = r0.ledger->ledger.back();
    }

    {
      r0.rollback(last_correct_version);
      DOCTEST_REQUIRE(r0.ledger->ledger.size() == last_correct_version);

      // How do we force Raft to increment its view? Currently by hacking to
      // follower then force_become_primary. There should be a neater way to do
      // this.
      r0.become_aware_of_new_term(2);
      r0.force_become_primary(); // The term actually jumps by 2 in this
                                 // function. Oh well, what can you do
    }

    std::vector<uint8_t> live_branch;
    {
      std::vector<uint8_t> entry_7b = {7, 7, 'b'};
      auto data = std::make_shared<std::vector<uint8_t>>(entry_7b);
      DOCTEST_REQUIRE(r0.replicate(kv::BatchVector{{7, data, true, hooks}}, 4));
      DOCTEST_REQUIRE(r0.ledger->ledger.size() == 7);
      live_branch = r0.ledger->ledger.back();
    }

    {
      std::vector<uint8_t> entry_8 = {8, 8, 8};
      auto data = std::make_shared<std::vector<uint8_t>>(entry_8);
      DOCTEST_REQUIRE(r0.replicate(kv::BatchVector{{8, data, true, hooks}}, 4));
      DOCTEST_REQUIRE(r0.ledger->ledger.size() == 8);
      DOCTEST_REQUIRE(r0.ledger->ledger.size() > last_correct_version);
    }

    {
      // But now a malicious host fiddles with the ledger, and inserts a valid
      // value from an old branch!
      // NB: It's important that node 0 has not sent any AppendEntries about the
      // latest entries yet! It should only do so after this point, where it
      // will include incorrect entries.
      r0.ledger->ledger[6] = dead_branch;
    }

    {
      // Even after multiple round trip coherence attempts, the bad ledger
      // remains and prevents progress
      for (size_t i = 0; i < 10; ++i)
      {
        r0.periodic(request_timeout);
        dispatch_all(nodes, node_id0, r0c->messages);
        dispatch_all(nodes, node_id1, r1c->messages);
      }
      // Receiver refuses these new entries, because they see a mismatch
      DOCTEST_REQUIRE(r1.ledger->ledger.size() == last_correct_version);
    }

    {
      // Now the ledger is corrected (ie - an honest primary takes over and
      // sends the correct values)
      r0.ledger->ledger[6] = live_branch;
    }

    {
      for (size_t i = 0; i < 10; ++i)
      {
        r0.periodic(request_timeout);
        dispatch_all(nodes, node_id0, r0c->messages);
        dispatch_all(nodes, node_id1, r1c->messages);
      }

      // Now the follower has fully caught up
      DOCTEST_REQUIRE(r1.ledger->ledger.size() == r0.ledger->ledger.size());
    }
  }
}

DOCTEST_TEST_CASE("Exceed append entries limit")
{
  logger::config::level() = logger::INFO;

  ccf::NodeId node_id0 = kv::test::PrimaryNodeId;
  ccf::NodeId node_id1 = kv::test::FirstBackupNodeId;
  ccf::NodeId node_id2 = kv::test::SecondBackupNodeId;

  auto kv_store0 = std::make_shared<Store>(node_id0);
  auto kv_store1 = std::make_shared<Store>(node_id1);
  auto kv_store2 = std::make_shared<Store>(node_id2);

  TRaft r0(
    raft_settings,
    std::make_unique<Adaptor>(kv_store0),
    std::make_unique<aft::LedgerStubProxy>(node_id0),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::State>(node_id0),
    nullptr,
    nullptr);
  TRaft r1(
    raft_settings,
    std::make_unique<Adaptor>(kv_store1),
    std::make_unique<aft::LedgerStubProxy>(node_id1),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::State>(node_id1),
    nullptr,
    nullptr);
  TRaft r2(
    raft_settings,
    std::make_unique<Adaptor>(kv_store2),
    std::make_unique<aft::LedgerStubProxy>(node_id2),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::State>(node_id2),
    nullptr,
    nullptr);

  aft::Configuration::Nodes config0;
  config0[node_id0] = {};
  config0[node_id1] = {};
  r0.add_configuration(0, config0);
  r1.add_configuration(0, config0);

  std::map<ccf::NodeId, TRaft*> nodes;
  nodes[node_id0] = &r0;
  nodes[node_id1] = &r1;

  auto r0c = channel_stub_proxy(r0);
  auto r1c = channel_stub_proxy(r1);

  r0.start_ticking();
  r0.periodic(election_timeout * 2);

  DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_id0, r0c->messages));
  DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_id1, r1c->messages));
  DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_id0, r0c->messages));

  DOCTEST_REQUIRE(
    1 ==
    dispatch_all_and_DOCTEST_CHECK<aft::AppendEntriesResponse>(
      nodes, node_id1, r1c->messages, [](const auto& msg) {
        DOCTEST_REQUIRE(msg.last_log_idx == 0);
        DOCTEST_REQUIRE(msg.success == aft::AppendEntriesResponseType::OK);
      }));

  DOCTEST_REQUIRE(r0c->messages.size() == 0);
  DOCTEST_REQUIRE(r1c->messages.size() == 0);

  // large entries of size (append_entries_size_limit / 2), so 2nd and 4th entry
  // will exceed append entries limit size which means that 2nd and 4th entries
  // will trigger send_append_entries()
  auto data = std::make_shared<std::vector<uint8_t>>(
    (r0.append_entries_size_limit / 2), 1);
  // I want to get ~500 messages sent over 1mill entries
  auto individual_entries = 1'000'000;
  auto num_small_entries_sent = 500;
  auto num_big_entries = 4;

  // send_append_entries() triggered or not
  bool expected_ae = false;

  for (size_t i = 1; i <= num_big_entries; ++i)
  {
    auto hooks = std::make_shared<kv::ConsensusHookPtrs>();
    DOCTEST_REQUIRE(r0.replicate(kv::BatchVector{{i, data, true, hooks}}, 1));
    const auto received_ae =
      dispatch_all_and_DOCTEST_CHECK<aft::AppendEntries>(
        nodes, node_id0, r0c->messages, [&i](const auto& msg) {
          DOCTEST_REQUIRE(msg.term == 1);
        }) > 0;
    DOCTEST_REQUIRE(received_ae == expected_ae);
    expected_ae = !expected_ae;
  }

  int data_size = (num_small_entries_sent * r0.append_entries_size_limit) /
    (individual_entries - num_big_entries);
  auto smaller_data = std::make_shared<std::vector<uint8_t>>(data_size, 1);

  for (size_t i = num_big_entries + 1; i <= individual_entries; ++i)
  {
    auto hooks = std::make_shared<kv::ConsensusHookPtrs>();
    DOCTEST_REQUIRE(
      r0.replicate(kv::BatchVector{{i, smaller_data, true, hooks}}, 1));
    dispatch_all(nodes, node_id0, r0c->messages);
  }

  // Tick to allow any remaining entries to be sent
  r0.periodic(request_timeout);
  dispatch_all(nodes, node_id0, r0c->messages);

  {
    DOCTEST_INFO("Nodes 0 and 1 have the same complete ledger");
    DOCTEST_REQUIRE(r0.ledger->ledger.size() == individual_entries);
    DOCTEST_REQUIRE(r1.ledger->ledger.size() == individual_entries);
  }

  DOCTEST_INFO("Node 2 joins the ensemble");

  aft::Configuration::Nodes config1;
  config1[node_id0] = {};
  config1[node_id1] = {};
  config1[node_id2] = {};
  r0.add_configuration(0, config1);
  r1.add_configuration(0, config1);
  r2.add_configuration(0, config1);

  nodes[node_id2] = &r2;

  auto r2c = channel_stub_proxy(r2);

  DOCTEST_INFO("Node 0 sends Node 2 what it's missed by joining late");
  DOCTEST_REQUIRE(r2c->messages.size() == 0);

  DOCTEST_REQUIRE(
    1 ==
    dispatch_all_and_DOCTEST_CHECK<aft::AppendEntries>(
      nodes, node_id0, r0c->messages, [&individual_entries](const auto& msg) {
        DOCTEST_REQUIRE(msg.idx == individual_entries);
        DOCTEST_REQUIRE(msg.term == 1);
        DOCTEST_REQUIRE(msg.prev_idx == individual_entries);
      }));

  DOCTEST_REQUIRE(r2.ledger->ledger.size() == 0);

  DOCTEST_INFO("Node 2 asks for Node 0 to send all the data up to now");
  DOCTEST_REQUIRE(r2c->messages.size() == 1);
  auto aer = r2c->messages.front().second;
  r2c->messages.pop_front();
  receive_message(r2, r0, aer);
  r0.periodic(request_timeout);

  DOCTEST_REQUIRE(r0c->messages.size() > num_small_entries_sent);
  auto sent_entries = dispatch_all(nodes, node_id0, r0c->messages);
  DOCTEST_REQUIRE(sent_entries > num_small_entries_sent);
  DOCTEST_REQUIRE(r2.ledger->ledger.size() == individual_entries);
}

DOCTEST_TEST_CASE(
  "Nodes only run for election when they should" *
  doctest::test_suite("multiple"))
{
  ccf::NodeId node_id0 = kv::test::PrimaryNodeId;
  ccf::NodeId node_id1 = kv::test::FirstBackupNodeId;

  auto kv_store0 = std::make_shared<Store>(node_id0);
  auto kv_store1 = std::make_shared<Store>(node_id1);

  TRaft r0(
    raft_settings,
    std::make_unique<Adaptor>(kv_store0),
    std::make_unique<aft::LedgerStubProxy>(node_id0),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::State>(node_id0),
    nullptr,
    nullptr);
  TRaft r1(
    raft_settings,
    std::make_unique<Adaptor>(kv_store1),
    std::make_unique<aft::LedgerStubProxy>(node_id1),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::State>(node_id1),
    nullptr,
    nullptr);

  std::map<ccf::NodeId, TRaft*> nodes;
  nodes[node_id0] = &r0;
  nodes[node_id1] = &r1;

  aft::Configuration::Nodes config;
  config[node_id0] = {};
  config[node_id1] = {};
  r0.add_configuration(0, config);
  r1.add_configuration(0, config);

  auto r0c = channel_stub_proxy(r0);
  auto r1c = channel_stub_proxy(r1);

  DOCTEST_INFO(
    "Node 0 exceeds its election timeout and does not start an election "
    "because it is not ticking");
  r0.periodic(election_timeout * 2);
  DOCTEST_REQUIRE(
    r0c->count_messages_with_type(aft::RaftMsgType::raft_request_vote) == 0);

  DOCTEST_INFO(
    "Node 0 starts ticking, exceeds its election timeout and so does start an "
    "election");
  r0.start_ticking();
  r0.periodic(election_timeout * 2);

  DOCTEST_INFO("Initial election");
  {
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_id0, r0c->messages));
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_id1, r1c->messages));

    DOCTEST_REQUIRE(r0.is_primary());
    DOCTEST_REQUIRE(r0c->messages.size() == 1);
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_id0, r0c->messages));
    DOCTEST_REQUIRE(r0c->messages.size() == 0);
  }

  DOCTEST_INFO(
    "Node 1 exceeds its election timeout but does not start an election "
    "because it isn't ticking yet");
  r1.periodic(election_timeout * 2);
  DOCTEST_REQUIRE(
    r1c->count_messages_with_type(aft::RaftMsgType::raft_request_vote) == 0);

  r1.start_ticking();
  DOCTEST_INFO(
    "Node 1 is now ticking, exceeds its election timeout and so calls an "
    "election");
  r1.periodic(election_timeout * 2);
  DOCTEST_REQUIRE(
    r1c->count_messages_with_type(aft::RaftMsgType::raft_request_vote) == 1);
}