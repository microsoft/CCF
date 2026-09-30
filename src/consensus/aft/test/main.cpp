// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "node/commit_callback_subsystem.h"
#include "test_common.h"

#define DOCTEST_CONFIG_NO_SHORT_MACRO_NAMES
#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest/doctest.h>

using ms = std::chrono::milliseconds;

DOCTEST_TEST_CASE("Single node startup" * doctest::test_suite("single"))
{
  ccf::NodeId node_id = ccf::kv::test::PrimaryNodeId;
  auto kv_store = std::make_shared<Store>(node_id);

  TRaft r0(
    raft_settings,
    std::make_unique<Adaptor>(kv_store),
    std::make_unique<aft::LedgerStubProxy>(node_id),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::State>(node_id),
    nullptr);
  r0.start_ticking();

  ccf::kv::Configuration::Nodes config;
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
  ccf::NodeId node_id = ccf::kv::test::PrimaryNodeId;
  auto kv_store = std::make_shared<Store>(node_id);

  TRaft r0(
    raft_settings,
    std::make_unique<Adaptor>(kv_store),
    std::make_unique<aft::LedgerStubProxy>(node_id),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::State>(node_id),
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

    r0.replicate(ccf::kv::BatchVector{{i, entry, true, hooks}}, 1);
    DOCTEST_REQUIRE(r0.get_last_idx() == i);
    DOCTEST_REQUIRE(r0.get_committed_seqno() == i);
  }
}

DOCTEST_TEST_CASE(
  "Register peer addresses with existing channels" *
  doctest::test_suite("multiple"))
{
  const auto node_id0 = ccf::kv::test::PrimaryNodeId;
  const auto node_id1 = ccf::kv::test::FirstBackupNodeId;
  const auto node_id2 = ccf::kv::test::SecondBackupNodeId;
  auto kv_store = std::make_shared<Store>(node_id0);
  // The stub models existing channels without registered peer addresses.
  auto channels = std::make_shared<aft::ChannelStubProxy>();

  TRaft raft(
    raft_settings,
    std::make_unique<Adaptor>(kv_store),
    std::make_unique<aft::LedgerStubProxy>(node_id0),
    channels,
    std::make_shared<aft::State>(node_id0),
    nullptr);

  DOCTEST_REQUIRE(channels->node_addresses.empty());

  aft::Configuration::Nodes config;
  config[node_id0] = {};
  config[node_id1] = {"127.0.0.2", "8001"};
  raft.add_configuration(0, config);

  DOCTEST_REQUIRE(channels->node_addresses.size() == 1);
  DOCTEST_REQUIRE(channels->node_addresses.contains(node_id1));
  DOCTEST_CHECK(channels->node_addresses.at(node_id1).first == "127.0.0.2");
  DOCTEST_CHECK(channels->node_addresses.at(node_id1).second == "8001");
  DOCTEST_CHECK_FALSE(channels->node_addresses.contains(node_id0));

  config[node_id2] = {"127.0.0.3", "8002"};
  raft.add_configuration(1, config);

  DOCTEST_REQUIRE(channels->node_addresses.size() == 2);
  DOCTEST_REQUIRE(channels->node_addresses.contains(node_id2));
  DOCTEST_CHECK(channels->node_addresses.at(node_id2).first == "127.0.0.3");
  DOCTEST_CHECK(channels->node_addresses.at(node_id2).second == "8002");
  DOCTEST_CHECK(channels->node_addresses.at(node_id1).first == "127.0.0.2");
  DOCTEST_CHECK(channels->node_addresses.at(node_id1).second == "8001");
}

DOCTEST_TEST_CASE(
  "Multiple nodes startup and election" * doctest::test_suite("multiple"))
{
  ccf::NodeId node_id0 = ccf::kv::test::PrimaryNodeId;
  ccf::NodeId node_id1 = ccf::kv::test::FirstBackupNodeId;
  ccf::NodeId node_id2 = ccf::kv::test::SecondBackupNodeId;
  ccf::NodeId node_id3 = ccf::kv::test::ThirdBackupNodeId;

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
    nullptr);
  TRaft r1(
    raft_settings,
    std::make_unique<Adaptor>(kv_store1),
    std::make_unique<aft::LedgerStubProxy>(node_id1),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::State>(node_id1),
    nullptr);
  TRaft r2(
    raft_settings,
    std::make_unique<Adaptor>(kv_store2),
    std::make_unique<aft::LedgerStubProxy>(node_id2),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::State>(node_id2),
    nullptr);
  TRaft r3(
    raft_settings,
    std::make_unique<Adaptor>(kv_store3),
    std::make_unique<aft::LedgerStubProxy>(node_id3),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::State>(node_id3),
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
    r0c->count_messages_with_type(aft::RaftMsgType::raft_request_pre_vote) ==
    3);

  DOCTEST_INFO("Node 1 receives the request pre-vote");

  auto rpv_raw =
    r0c->pop_first(aft::RaftMsgType::raft_request_pre_vote, node_id1);
  DOCTEST_REQUIRE(rpv_raw.has_value());
  {
    auto rpv = *(aft::RequestPreVote*)rpv_raw->data();
    DOCTEST_REQUIRE(rpv.term == 0);
    DOCTEST_REQUIRE(rpv.last_committable_idx == 0);
    DOCTEST_REQUIRE(
      rpv.term_of_last_committable_idx == aft::ViewHistory::InvalidView);
  }

  receive_message(r0, r1, *rpv_raw);

  DOCTEST_INFO("Node 2 receives the request pre-vote");

  rpv_raw = r0c->pop_first(aft::RaftMsgType::raft_request_pre_vote, node_id2);
  DOCTEST_REQUIRE(rpv_raw.has_value());
  {
    auto rpv = *(aft::RequestPreVote*)rpv_raw->data();
    DOCTEST_REQUIRE(rpv.term == 0);
    DOCTEST_REQUIRE(rpv.last_committable_idx == 0);
    DOCTEST_REQUIRE(
      rpv.term_of_last_committable_idx == aft::ViewHistory::InvalidView);
  }

  receive_message(r0, r2, *rpv_raw);

  DOCTEST_INFO("Node 1 pre-votes for Node 0");

  DOCTEST_REQUIRE(
    r1c->count_messages_with_type(
      aft::RaftMsgType::raft_request_pre_vote_response) == 1);

  auto rpvr_raw =
    r1c->pop_first(aft::RaftMsgType::raft_request_pre_vote_response, node_id0);
  DOCTEST_REQUIRE(rpvr_raw.has_value());
  {
    auto rvrc = *(aft::RequestPreVoteResponse*)rpvr_raw->data();
    DOCTEST_REQUIRE(rvrc.term == 0);
    DOCTEST_REQUIRE(rvrc.vote_granted);
  }

  receive_message(r1, r0, *rpvr_raw);

  DOCTEST_INFO("Node 2 pre-votes for Node 0");

  DOCTEST_REQUIRE(
    r2c->count_messages_with_type(
      aft::RaftMsgType::raft_request_pre_vote_response) == 1);

  rpvr_raw =
    r2c->pop_first(aft::RaftMsgType::raft_request_pre_vote_response, node_id0);
  DOCTEST_REQUIRE(rpvr_raw.has_value());
  {
    auto rvrc = *(aft::RequestPreVoteResponse*)rpvr_raw->data();
    DOCTEST_REQUIRE(rvrc.term == 0);
    DOCTEST_REQUIRE(rvrc.vote_granted);
  }

  receive_message(r2, r0, *rpvr_raw);

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
  ccf::NodeId node_id0 = ccf::kv::test::PrimaryNodeId;
  ccf::NodeId node_id1 = ccf::kv::test::FirstBackupNodeId;
  ccf::NodeId node_id2 = ccf::kv::test::SecondBackupNodeId;

  auto kv_store0 = std::make_shared<Store>(node_id0);
  auto kv_store1 = std::make_shared<Store>(node_id1);
  auto kv_store2 = std::make_shared<Store>(node_id2);

  TRaft r0(
    raft_settings,
    std::make_unique<Adaptor>(kv_store0),
    std::make_unique<aft::LedgerStubProxy>(node_id0),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::State>(node_id0),
    nullptr);
  TRaft r1(
    raft_settings,
    std::make_unique<Adaptor>(kv_store1),
    std::make_unique<aft::LedgerStubProxy>(node_id1),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::State>(node_id1),
    nullptr);
  TRaft r2(
    raft_settings,
    std::make_unique<Adaptor>(kv_store2),
    std::make_unique<aft::LedgerStubProxy>(node_id2),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::State>(node_id2),
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

  DOCTEST_INFO("Send request_pre_votes to other nodes");
  DOCTEST_REQUIRE(2 == dispatch_all(nodes, node_id0, r0c->messages));

  DOCTEST_INFO("Send request_pre_vote_reponses back");
  DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_id1, r1c->messages));
  DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_id2, r2c->messages));

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
  DOCTEST_REQUIRE_FALSE(
    r1.replicate(ccf::kv::BatchVector{{1, data, true, hooks}}, 1));

  DOCTEST_INFO("Tell the leader to replicate a message");
  DOCTEST_REQUIRE(
    r0.replicate(ccf::kv::BatchVector{{1, data, true, hooks}}, 1));
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
  ccf::NodeId node_id0 = ccf::kv::test::PrimaryNodeId;
  ccf::NodeId node_id1 = ccf::kv::test::FirstBackupNodeId;
  ccf::NodeId node_id2 = ccf::kv::test::SecondBackupNodeId;

  auto kv_store0 = std::make_shared<Store>(node_id0);
  auto kv_store1 = std::make_shared<Store>(node_id1);
  auto kv_store2 = std::make_shared<Store>(node_id2);

  TRaft r0(
    raft_settings,
    std::make_unique<Adaptor>(kv_store0),
    std::make_unique<aft::LedgerStubProxy>(node_id0),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::State>(node_id0),
    nullptr);
  TRaft r1(
    raft_settings,
    std::make_unique<Adaptor>(kv_store1),
    std::make_unique<aft::LedgerStubProxy>(node_id1),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::State>(node_id1),
    nullptr);
  TRaft r2(
    raft_settings,
    std::make_unique<Adaptor>(kv_store2),
    std::make_unique<aft::LedgerStubProxy>(node_id2),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::State>(node_id2),
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

  // Pre-vote
  DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_id0, r0c->messages));
  DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_id1, r1c->messages));
  // Vote
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
  DOCTEST_REQUIRE(
    r0.replicate(ccf::kv::BatchVector{{1, data, true, hooks}}, 1));
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
  ccf::NodeId node_id0 = ccf::kv::test::PrimaryNodeId;
  ccf::NodeId node_id1 = ccf::kv::test::FirstBackupNodeId;

  auto kv_store0 = std::make_shared<Store>(node_id0);
  auto kv_store1 = std::make_shared<Store>(node_id1);

  TRaft r0(
    raft_settings,
    std::make_unique<Adaptor>(kv_store0),
    std::make_unique<aft::LedgerStubProxy>(node_id0),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::State>(node_id0),
    nullptr);
  TRaft r1(
    raft_settings,
    std::make_unique<Adaptor>(kv_store1),
    std::make_unique<aft::LedgerStubProxy>(node_id1),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::State>(node_id1),
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

  DOCTEST_INFO("Initial election");
  {
    // Pre-vote
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_id0, r0c->messages));
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_id1, r1c->messages));
    // Vote
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

    DOCTEST_REQUIRE(
      r0.replicate(ccf::kv::BatchVector{{1, data_1, true, hooks}}, 1));
    DOCTEST_REQUIRE(
      r0.replicate(ccf::kv::BatchVector{{2, data_2, true, hooks}}, 1));
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
    DOCTEST_REQUIRE(
      r0.replicate(ccf::kv::BatchVector{{3, data, true, hooks}}, 1));
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
    DOCTEST_REQUIRE(
      r0.replicate(ccf::kv::BatchVector{{4, data, true, hooks}}, 1));
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
    DOCTEST_REQUIRE(
      r0.replicate(ccf::kv::BatchVector{{5, data, true, hooks}}, 1));
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
      DOCTEST_REQUIRE(
        r0.replicate(ccf::kv::BatchVector{{6, data, true, hooks}}, 1));
      DOCTEST_REQUIRE(r0.ledger->ledger.size() == 6);
    }
    const auto last_correct_version = r0.ledger->ledger.size();

    std::vector<uint8_t> dead_branch;
    {
      std::vector<uint8_t> entry_7 = {7, 7, 7};
      auto data = std::make_shared<std::vector<uint8_t>>(entry_7);
      DOCTEST_REQUIRE(
        r0.replicate(ccf::kv::BatchVector{{7, data, true, hooks}}, 1));
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
      DOCTEST_REQUIRE(
        r0.replicate(ccf::kv::BatchVector{{7, data, true, hooks}}, 4));
      DOCTEST_REQUIRE(r0.ledger->ledger.size() == 7);
      live_branch = r0.ledger->ledger.back();
    }

    {
      std::vector<uint8_t> entry_8 = {8, 8, 8};
      auto data = std::make_shared<std::vector<uint8_t>>(entry_8);
      DOCTEST_REQUIRE(
        r0.replicate(ccf::kv::BatchVector{{8, data, true, hooks}}, 4));
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
  ccf::logger::config::level() = ccf::LoggerLevel::INFO;

  ccf::NodeId node_id0 = ccf::kv::test::PrimaryNodeId;
  ccf::NodeId node_id1 = ccf::kv::test::FirstBackupNodeId;
  ccf::NodeId node_id2 = ccf::kv::test::SecondBackupNodeId;

  auto kv_store0 = std::make_shared<Store>(node_id0);
  auto kv_store1 = std::make_shared<Store>(node_id1);
  auto kv_store2 = std::make_shared<Store>(node_id2);

  TRaft r0(
    raft_settings,
    std::make_unique<Adaptor>(kv_store0),
    std::make_unique<aft::LedgerStubProxy>(node_id0),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::State>(node_id0),
    nullptr);
  TRaft r1(
    raft_settings,
    std::make_unique<Adaptor>(kv_store1),
    std::make_unique<aft::LedgerStubProxy>(node_id1),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::State>(node_id1),
    nullptr);
  TRaft r2(
    raft_settings,
    std::make_unique<Adaptor>(kv_store2),
    std::make_unique<aft::LedgerStubProxy>(node_id2),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::State>(node_id2),
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

  // Pre-vote
  DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_id0, r0c->messages));
  DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_id1, r1c->messages));
  // Vote
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

  for (size_t i = 1; i <= static_cast<size_t>(num_big_entries); ++i)
  {
    DOCTEST_REQUIRE(
      r0.replicate(ccf::kv::BatchVector{{i, data, true, hooks}}, 1));
    const auto received_ae =
      dispatch_all_and_DOCTEST_CHECK<aft::AppendEntries>(
        nodes, node_id0, r0c->messages, [](const auto& msg) {
          DOCTEST_REQUIRE(msg.term == 1);
        }) > 0;
    DOCTEST_REQUIRE(received_ae == expected_ae);
    expected_ae = !expected_ae;
  }

  int data_size = (num_small_entries_sent * r0.append_entries_size_limit) /
    (individual_entries - num_big_entries);
  auto smaller_data = std::make_shared<std::vector<uint8_t>>(data_size, 1);

  for (size_t i = num_big_entries + 1;
       i <= static_cast<size_t>(individual_entries);
       ++i)
  {
    DOCTEST_REQUIRE(
      r0.replicate(ccf::kv::BatchVector{{i, smaller_data, true, hooks}}, 1));
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
  ccf::NodeId node_id0 = ccf::kv::test::PrimaryNodeId;
  ccf::NodeId node_id1 = ccf::kv::test::FirstBackupNodeId;

  auto kv_store0 = std::make_shared<Store>(node_id0);
  auto kv_store1 = std::make_shared<Store>(node_id1);

  TRaft r0(
    raft_settings,
    std::make_unique<Adaptor>(kv_store0),
    std::make_unique<aft::LedgerStubProxy>(node_id0),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::State>(node_id0),
    nullptr);
  TRaft r1(
    raft_settings,
    std::make_unique<Adaptor>(kv_store1),
    std::make_unique<aft::LedgerStubProxy>(node_id1),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::State>(node_id1),
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
    // Pre-vote
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_id0, r0c->messages));
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_id1, r1c->messages));
    // Vote
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
    r1c->count_messages_with_type(aft::RaftMsgType::raft_request_pre_vote) ==
    0);

  r1.start_ticking();
  DOCTEST_INFO(
    "Node 1 is now ticking, exceeds its election timeout and so calls an "
    "election");
  r1.periodic(election_timeout * 2);
  DOCTEST_REQUIRE(
    r1c->count_messages_with_type(aft::RaftMsgType::raft_request_pre_vote) ==
    1);
}

template <typename T>
static T read_msg(const std::vector<uint8_t>& msg)
{
  const uint8_t* data = msg.data();
  size_t size = msg.size();
  return serialized::read<T>(data, size);
}

template <typename T>
static std::vector<uint8_t> as_bytes(const T& msg)
{
  const auto* data = reinterpret_cast<const uint8_t*>(&msg);
  return {data, data + sizeof(T)};
}

static void require_ack(
  const std::optional<aft::AppendEntriesResponse>& response,
  aft::Index last_log_idx)
{
  DOCTEST_REQUIRE(response.has_value());
  DOCTEST_REQUIRE(response->success == aft::AppendEntriesResponseType::OK);
  DOCTEST_REQUIRE(response->last_log_idx == last_log_idx);
}

static void require_nack(
  const std::optional<aft::AppendEntriesResponse>& response,
  aft::Index last_log_idx)
{
  DOCTEST_REQUIRE(response.has_value());
  DOCTEST_REQUIRE(response->success == aft::AppendEntriesResponseType::FAIL);
  DOCTEST_REQUIRE(response->last_log_idx == last_log_idx);
}

struct TestNodeOptions
{
  ccf::consensus::Configuration settings = raft_settings;
  std::shared_ptr<Store> kv = nullptr;
  bool pre_vote_enabled = true;
  std::shared_ptr<ccf::CommitCallbackSubsystem> commit_callbacks = nullptr;
  bool public_only = false;
};

// A node's consensus, and the store it deserialises entries into. aft::Adaptor
// only holds a weak_ptr to the store, so the two are kept together.
struct TestNode
{
  std::shared_ptr<Store> kv;
  TRaft raft;

  explicit TestNode(const ccf::NodeId& id, TestNodeOptions options = {}) :
    kv(
      options.kv != nullptr ? std::move(options.kv) :
                              std::make_shared<Store>(id)),
    raft(
      options.settings,
      std::make_unique<Adaptor>(kv),
      std::make_unique<aft::LedgerStubProxy>(id),
      std::make_shared<aft::ChannelStubProxy>(),
      std::make_shared<aft::State>(id, options.pre_vote_enabled),
      nullptr,
      std::move(options.commit_callbacks),
      options.public_only)
  {}
};

// A primary (node 0) and a backup (node 1) sharing a single configuration. The
// primary has been elected in view 1, and the backup has acknowledged its
// initial heartbeat.
struct PrimaryAndBackup
{
  const ccf::NodeId id0 = ccf::kv::test::PrimaryNodeId;
  const ccf::NodeId id1 = ccf::kv::test::FirstBackupNodeId;
  TestNode node0;
  TestNode node1;
  TRaft& r0;
  TRaft& r1;
  aft::ChannelStubProxy* c0;
  aft::ChannelStubProxy* c1;
  std::map<ccf::NodeId, TRaft*> nodes;

  PrimaryAndBackup(
    TestNodeOptions primary_options = {}, TestNodeOptions backup_options = {}) :
    node0(id0, std::move(primary_options)),
    node1(id1, std::move(backup_options)),
    r0(node0.raft),
    r1(node1.raft),
    c0(channel_stub_proxy(r0)),
    c1(channel_stub_proxy(r1)),
    nodes{{id0, &r0}, {id1, &r1}}
  {
    aft::Configuration::Nodes config;
    config[id0] = {};
    config[id1] = {};
    r0.add_configuration(0, config);
    r1.add_configuration(0, config);

    r0.start_ticking();
    r0.periodic(election_timeout * 2);

    // Pre-vote, vote, then the initial heartbeat, and each response
    for (size_t round = 0; round < 3; ++round)
    {
      DOCTEST_REQUIRE(1 == dispatch_all(nodes, id0));
      DOCTEST_REQUIRE(1 == dispatch_all(nodes, id1));
    }
    DOCTEST_REQUIRE(r0.is_primary());
    DOCTEST_REQUIRE(r0.get_view() == 1);
  }

  // Replicates entries [first, last] on the primary, in its current view
  void replicate(aft::Index first, aft::Index last, bool committable = true)
  {
    for (auto idx = first; idx <= last; ++idx)
    {
      auto data =
        std::make_shared<std::vector<uint8_t>>(3, static_cast<uint8_t>(idx));
      DOCTEST_REQUIRE(r0.replicate(
        ccf::kv::BatchVector{{idx, data, committable, hooks}}, r0.get_view()));
    }
  }

  // Removes the primary's next AppendEntries to the backup from its outbox,
  // without the ledger entries the host appends to it
  std::vector<uint8_t> take_append_entries_header()
  {
    auto msg = c0->pop_first(aft::raft_append_entries, id1);
    DOCTEST_REQUIRE(msg.has_value());
    return msg.value();
  }

  // Appends the primary's ledger entries for this AppendEntries, as the host
  // does when sending it
  std::vector<uint8_t> with_payload(std::vector<uint8_t> header)
  {
    const auto ae = read_msg<aft::AppendEntries>(header);
    const auto payload = r0.ledger->get_append_entries_payload(ae);
    DOCTEST_REQUIRE(payload.has_value());
    header.insert(header.end(), payload->begin(), payload->end());
    return header;
  }

  // Delivers msg from the primary to the backup, and returns the backup's
  // response, if it sent one
  std::optional<aft::AppendEntriesResponse> backup_receives(
    const std::vector<uint8_t>& msg)
  {
    r1.recv_message(id0, msg.data(), msg.size());
    auto response = c1->pop_first(aft::raft_append_entries_response, id0);
    DOCTEST_REQUIRE(c1->messages.empty());
    if (!response.has_value())
    {
      return std::nullopt;
    }
    return read_msg<aft::AppendEntriesResponse>(response.value());
  }

  void primary_receives(const aft::AppendEntriesResponse& response)
  {
    const auto msg = as_bytes(response);
    r0.recv_message(id1, msg.data(), msg.size());
  }
};

DOCTEST_TEST_CASE(
  "Backup NACKs AppendEntries whose entries cannot be read or deserialised" *
  doctest::test_suite("multiple"))
{
  PrimaryAndBackup n;
  n.replicate(1, 1);
  n.r0.periodic(request_timeout);
  const auto header = n.take_append_entries_header();

  DOCTEST_SUBCASE("Entry is missing or truncated")
  {
    // The ledger entry parser throws std::logic_error both for a missing size
    // prefix, and for a size prefix claiming more bytes than are present
    std::vector<uint8_t> oversized_prefix(sizeof(size_t));
    {
      uint8_t* data = oversized_prefix.data();
      size_t size = oversized_prefix.size();
      serialized::write<size_t>(data, size, 1'000'000);
    }

    for (const auto& payload : {std::vector<uint8_t>{}, oversized_prefix})
    {
      auto msg = header;
      msg.insert(msg.end(), payload.begin(), payload.end());
      require_nack(n.backup_receives(msg), 0);
      DOCTEST_REQUIRE(n.r1.get_last_idx() == 0);
      DOCTEST_REQUIRE(n.r1.ledger->ledger.empty());
    }
  }

  DOCTEST_SUBCASE("Entry the backup already holds is missing")
  {
    require_ack(n.backup_receives(n.with_payload(header)), 1);

    // The same AppendEntries arrives again (for instance, duplicated in
    // transit), this time without its entry. The backup skips entries it
    // already holds, but must still parse them to do so.
    require_nack(n.backup_receives(header), 1);
    DOCTEST_REQUIRE(n.r1.get_last_idx() == 1);
    DOCTEST_REQUIRE(n.r1.ledger->ledger == n.r0.ledger->ledger);
  }

  DOCTEST_SUBCASE("Store has been destroyed")
  {
    // aft::Adaptor holds only a weak_ptr to the store, and its deserialize()
    // returns nullptr once the store is gone (for instance, during shutdown)
    n.node1.kv.reset();
    require_nack(n.backup_receives(n.with_payload(header)), 0);
    DOCTEST_REQUIRE(n.r1.get_last_idx() == 0);
    DOCTEST_REQUIRE(n.r1.ledger->ledger.empty());
  }
}

DOCTEST_TEST_CASE(
  "New backup does not acknowledge an AppendEntries starting beyond its log" *
  doctest::test_suite("multiple"))
{
  ccf::NodeId node_id0 = ccf::kv::test::PrimaryNodeId;
  ccf::NodeId node_id1 = ccf::kv::test::FirstBackupNodeId;

  TestNode node0(node_id0);
  TestNode node1(node_id1);
  auto& r0 = node0.raft;
  auto& r1 = node1.raft;
  auto r0c = channel_stub_proxy(r0);
  auto r1c = channel_stub_proxy(r1);

  aft::Configuration::Nodes config0;
  config0[node_id0] = {};
  r0.add_configuration(0, config0);
  r0.start_ticking();
  r0.periodic(election_timeout * 2);
  DOCTEST_REQUIRE(r0.is_primary());

  auto data = std::make_shared<std::vector<uint8_t>>(3, 1);
  for (aft::Index idx = 1; idx <= 2; ++idx)
  {
    DOCTEST_REQUIRE(r0.replicate(
      ccf::kv::BatchVector{{idx, data, true, hooks}}, r0.get_view()));
  }

  DOCTEST_INFO("The primary's first send to a newly added backup fails");
  // A new node's sent_idx starts beyond the primary's log, and is only
  // corrected by a successful send
  r0c->fail_sends = true;
  aft::Configuration::Nodes config1 = config0;
  config1[node_id1] = {};
  r0.add_configuration(0, config1);
  r0c->fail_sends = false;

  DOCTEST_INFO(
    "So its next AppendEntries starts beyond its own log, from prev_term "
    "VIEW_UNKNOWN");
  r0.periodic(request_timeout);
  const auto msg = r0c->pop_first(aft::raft_append_entries, node_id1);
  DOCTEST_REQUIRE(msg.has_value());
  const auto ae = read_msg<aft::AppendEntries>(msg.value());
  DOCTEST_REQUIRE(ae.prev_idx == r0.get_last_idx() + 1);
  DOCTEST_REQUIRE(ae.prev_term == ccf::VIEW_UNKNOWN);
  DOCTEST_REQUIRE(ae.idx == r0.get_last_idx());

  // get_term_internal() returns VIEW_UNKNOWN beyond the backup's log too, so
  // this passes the prev_term check. The backup must not acknowledge entries
  // it does not hold.
  receive_message(r0, r1, msg.value());
  DOCTEST_REQUIRE(r1c->messages.empty());
  DOCTEST_REQUIRE(r1.get_last_idx() == 0);

  DOCTEST_INFO("Replication then proceeds as usual");
  std::map<ccf::NodeId, TRaft*> nodes{{node_id0, &r0}, {node_id1, &r1}};
  // A heartbeat, which the backup NACKs, then the entries, which it ACKs
  for (size_t round = 0; round < 2; ++round)
  {
    r0.periodic(request_timeout);
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_id0));
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_id1));
  }
  DOCTEST_REQUIRE(r1.ledger->ledger == r0.ledger->ledger);
}

DOCTEST_TEST_CASE(
  "Raft messages that cannot be parsed or authenticated are ignored" *
  doctest::test_suite("multiple"))
{
  ccf::NodeId node_id0 = ccf::kv::test::PrimaryNodeId;
  ccf::NodeId node_id1 = ccf::kv::test::FirstBackupNodeId;

  TestNode node1(node_id1);
  auto& r1 = node1.raft;
  auto r1c = channel_stub_proxy(r1);

  aft::Configuration::Nodes config;
  config[node_id0] = {};
  config[node_id1] = {};
  r1.add_configuration(0, config);

  const auto require_unchanged = [&]() {
    DOCTEST_REQUIRE(r1c->messages.empty());
    DOCTEST_REQUIRE(r1.get_view() == 0);
    DOCTEST_REQUIRE(r1.get_last_idx() == 0);
    DOCTEST_REQUIRE(
      r1.get_details().leadership_state == ccf::kv::LeadershipState::None);
  };

  DOCTEST_SUBCASE("Truncated message of each handled type")
  {
    const std::vector<aft::RaftMsgType> handled_types = {
      aft::raft_append_entries,
      aft::raft_append_entries_response,
      aft::raft_request_pre_vote,
      aft::raft_request_vote,
      aft::raft_request_pre_vote_response,
      aft::raft_request_vote_response,
      aft::raft_propose_request_vote,
    };

    for (const auto type : handled_types)
    {
      DOCTEST_INFO("Truncated message of type ", (size_t)type);

      // Only the message type tag, too short for any message struct
      std::vector<uint8_t> msg(sizeof(aft::RaftMsgType));
      {
        uint8_t* data = msg.data();
        size_t size = msg.size();
        serialized::write<aft::RaftMsgType>(data, size, type);
      }

      r1.recv_message(node_id0, msg.data(), msg.size());
      require_unchanged();
    }
  }

  DOCTEST_SUBCASE("Known but unhandled message type")
  {
    const auto msg =
      as_bytes(aft::RaftHeader<aft::raft_append_entries_signed_response>{});
    r1.recv_message(node_id0, msg.data(), msg.size());
    require_unchanged();
  }

  DOCTEST_SUBCASE("Unknown message type")
  {
    const auto msg = as_bytes(static_cast<aft::RaftMsgType>(0xDEADBEEF));
    r1.recv_message(node_id0, msg.data(), msg.size());
    require_unchanged();
  }

  DOCTEST_SUBCASE("Message failing authentication")
  {
    const auto msg = as_bytes(aft::RequestVote{
      .term = 5, .last_committable_idx = 0, .term_of_last_committable_idx = 0});

    r1c->fail_recv_authentication = true;
    r1.recv_message(node_id0, msg.data(), msg.size());
    require_unchanged();

    DOCTEST_INFO("The same message is acted on once it is authenticated");
    r1c->fail_recv_authentication = false;
    r1.recv_message(node_id0, msg.data(), msg.size());
    DOCTEST_REQUIRE(r1.get_view() == 5);
    DOCTEST_REQUIRE(
      r1c->count_messages_with_type(aft::raft_request_vote_response) == 1);
  }
}

DOCTEST_TEST_CASE(
  "Backup keeps the entries before one which fails to apply" *
  doctest::test_suite("multiple"))
{
  PrimaryAndBackup n;
  n.replicate(1, 2);
  n.r0.periodic(request_timeout);
  const auto header = n.take_append_entries_header();
  const auto ae = read_msg<aft::AppendEntries>(header);
  DOCTEST_REQUIRE(ae.prev_idx == 0);
  DOCTEST_REQUIRE(ae.idx == 2);

  // As in "Recv append entries logic", the host corrupts the primary's
  // ledger: entry 2 now claims a different view, so no longer matches the
  // TxID the AppendEntries gives it. The backup's store reports
  // ApplyResult::FAIL for it, after applying entry 1.
  const auto original_entry_2 = n.r0.ledger->ledger[1];
  {
    uint8_t* data = n.r0.ledger->ledger[1].data() + sizeof(size_t) +
      sizeof(bool) /* committable */;
    size_t size = sizeof(aft::Term);
    serialized::write<aft::Term>(data, size, ae.term_of_idx + 1);
  }
  const auto response = n.backup_receives(n.with_payload(header));
  n.r0.ledger->ledger[1] = original_entry_2;

  require_nack(response, 1);
  DOCTEST_REQUIRE(n.r1.get_last_idx() == 1);
  DOCTEST_REQUIRE(n.r1.ledger->ledger.size() == 1);
  DOCTEST_REQUIRE(n.r1.ledger->ledger[0] == n.r0.ledger->ledger[0]);

  DOCTEST_INFO("The primary resends only the rejected entry");
  n.primary_receives(response.value());
  n.r0.periodic(request_timeout);
  const auto retry = n.take_append_entries_header();
  DOCTEST_REQUIRE(read_msg<aft::AppendEntries>(retry).prev_idx == 1);
  require_ack(n.backup_receives(n.with_payload(retry)), 2);
  DOCTEST_REQUIRE(n.r1.ledger->ledger == n.r0.ledger->ledger);
}

DOCTEST_TEST_CASE(
  "Backup ignores a delayed AppendEntries from before its commit index" *
  doctest::test_suite("multiple"))
{
  PrimaryAndBackup n;
  n.replicate(1, 2);
  n.r0.periodic(request_timeout);
  const auto first_ae = n.with_payload(n.take_append_entries_header());
  const auto ack = n.backup_receives(first_ae);
  require_ack(ack, 2);
  n.primary_receives(ack.value());
  DOCTEST_REQUIRE(n.r0.get_committed_seqno() == 2);

  // The next heartbeat carries the primary's commit index to the backup
  n.r0.periodic(request_timeout);
  require_ack(
    n.backup_receives(n.with_payload(n.take_append_entries_header())), 2);
  DOCTEST_REQUIRE(n.r1.get_committed_seqno() == 2);

  // A duplicate of the first AppendEntries arrives late. Unlike a duplicate
  // of uncommitted entries (see "Recv append entries logic"), its entries are
  // not examined, and no response is sent.
  n.r1.ledger->reset_skip_count();
  DOCTEST_REQUIRE_FALSE(n.backup_receives(first_ae).has_value());
  DOCTEST_REQUIRE(n.r1.ledger->skip_count == 0);
  DOCTEST_REQUIRE(n.r1.get_last_idx() == 2);
  DOCTEST_REQUIRE(n.r1.get_committed_seqno() == 2);
}

DOCTEST_TEST_CASE(
  "Primary ignores stale responses from a backup" *
  doctest::test_suite("multiple"))
{
  PrimaryAndBackup n;
  n.replicate(1, 1);
  n.r0.periodic(request_timeout);
  const auto ack_1 =
    n.backup_receives(n.with_payload(n.take_append_entries_header()));
  require_ack(ack_1, 1);

  n.replicate(2, 2);
  n.r0.periodic(request_timeout);
  const auto ack_2 =
    n.backup_receives(n.with_payload(n.take_append_entries_header()));
  require_ack(ack_2, 2);

  DOCTEST_INFO("The acknowledgements arrive out of order");
  n.primary_receives(ack_2.value());
  DOCTEST_REQUIRE(n.r0.get_committed_seqno() == 2);
  n.primary_receives(ack_1.value());
  DOCTEST_REQUIRE(n.r0.get_details().acks.at(n.id1).seqno == 2);
  DOCTEST_REQUIRE(n.r0.get_committed_seqno() == 2);

  DOCTEST_INFO(
    "A late NACK below the acknowledged index does not make the primary "
    "resend acknowledged entries");
  auto nack = ack_1.value();
  nack.success = aft::AppendEntriesResponseType::FAIL;
  n.primary_receives(nack);
  DOCTEST_REQUIRE(n.r0.get_details().acks.at(n.id1).seqno == 2);
  n.replicate(3, 3);
  n.r0.periodic(request_timeout);
  DOCTEST_REQUIRE(
    read_msg<aft::AppendEntries>(n.take_append_entries_header()).prev_idx == 2);
}

DOCTEST_TEST_CASE(
  "Primary resends entries whose AppendEntries could not be sent" *
  doctest::test_suite("multiple"))
{
  PrimaryAndBackup n;
  n.replicate(1, 1);

  n.c0->fail_sends = true;
  n.r0.periodic(request_timeout);
  DOCTEST_REQUIRE(n.c0->messages.empty());

  // The failed send was not recorded as sent, so the next AppendEntries
  // starts from entry 1 again, rather than being a heartbeat after it
  n.c0->fail_sends = false;
  n.r0.periodic(request_timeout);
  const auto header = n.take_append_entries_header();
  const auto ae = read_msg<aft::AppendEntries>(header);
  DOCTEST_REQUIRE(ae.prev_idx == 0);
  DOCTEST_REQUIRE(ae.idx == 1);
  require_ack(n.backup_receives(n.with_payload(header)), 1);
}

DOCTEST_TEST_CASE(
  "Primary stops committing when a quorum acknowledges beyond its log" *
  doctest::test_suite("multiple"))
{
  ccf::NodeId node_id0 = ccf::kv::test::PrimaryNodeId;
  ccf::NodeId node_id1 = ccf::kv::test::FirstBackupNodeId;
  ccf::NodeId node_id2 = ccf::kv::test::SecondBackupNodeId;

  TestNode node0(node_id0);
  auto& r0 = node0.raft;

  aft::Configuration::Nodes config;
  config[node_id0] = {};
  config[node_id1] = {};
  config[node_id2] = {};
  r0.add_configuration(0, config);
  r0.force_become_primary();

  auto data = std::make_shared<std::vector<uint8_t>>(3, 1);
  DOCTEST_REQUIRE(
    r0.replicate(ccf::kv::BatchVector{{1, data, true, hooks}}, r0.get_view()));

  // Both backups, a quorum, claim to hold entries the primary has not
  // produced. The first claim alone commits entry 1, which the primary and
  // that backup then both (claim to) hold.
  const auto over_ack = as_bytes(aft::AppendEntriesResponse{
    .term = r0.get_view(),
    .last_log_idx = 10,
    .success = aft::AppendEntriesResponseType::OK});
  for (const auto& backup : {node_id1, node_id2})
  {
    r0.recv_message(backup, over_ack.data(), over_ack.size());
    DOCTEST_REQUIRE(r0.get_committed_seqno() == 1);
  }

  DOCTEST_INFO(
    "Their claims now put the agreed index beyond the primary's log, so it "
    "no longer commits on their word, even entries it does hold");
  DOCTEST_REQUIRE(
    r0.replicate(ccf::kv::BatchVector{{2, data, true, hooks}}, r0.get_view()));
  r0.recv_message(node_id1, over_ack.data(), over_ack.size());
  DOCTEST_REQUIRE(r0.get_last_idx() == 2);
  DOCTEST_REQUIRE(r0.get_committed_seqno() == 1);
  DOCTEST_REQUIRE(r0.is_primary());
}

DOCTEST_TEST_CASE(
  "Candidate ignores a pre-vote response carrying its new view" *
  doctest::test_suite("multiple"))
{
  ccf::NodeId node_id0 = ccf::kv::test::PrimaryNodeId;
  ccf::NodeId node_id1 = ccf::kv::test::FirstBackupNodeId;
  ccf::NodeId node_id2 = ccf::kv::test::SecondBackupNodeId;

  TestNode node0(node_id0);
  TestNode node1(node_id1);
  TestNode node2(node_id2);
  auto& r0 = node0.raft;
  auto& r1 = node1.raft;
  auto& r2 = node2.raft;

  aft::Configuration::Nodes config;
  config[node_id0] = {};
  config[node_id1] = {};
  config[node_id2] = {};
  for (auto* r : {&r0, &r1, &r2})
  {
    r->add_configuration(0, config);
  }

  // Delivers the first message of the given type from one node to another
  const auto deliver = [](TRaft& from, TRaft& to, aft::RaftMsgType type) {
    auto msg = channel_stub_proxy(from)->pop_first(type, to.id());
    DOCTEST_REQUIRE(msg.has_value());
    to.recv_message(from.id(), msg->data(), msg->size());
  };

  DOCTEST_INFO("Nodes 0 and 1 both become pre-vote candidates in view 0");
  for (auto* r : {&r0, &r1})
  {
    r->start_ticking();
    r->periodic(election_timeout * 2);
    DOCTEST_REQUIRE(
      r->get_details().leadership_state ==
      ccf::kv::LeadershipState::PreVoteCandidate);
  }

  DOCTEST_INFO("Node 1 grants node 0 a pre-vote");
  deliver(r0, r1, aft::raft_request_pre_vote);

  DOCTEST_INFO("With node 2's pre-vote, node 1 becomes a candidate in view 1");
  deliver(r1, r2, aft::raft_request_pre_vote);
  deliver(r2, r1, aft::raft_request_pre_vote_response);
  DOCTEST_REQUIRE(r1.is_candidate());
  DOCTEST_REQUIRE(r1.get_view() == 1);

  DOCTEST_INFO(
    "Node 2 votes for node 1, moving to view 1, so refuses node 0's pre-vote");
  deliver(r1, r2, aft::raft_request_vote);
  deliver(r0, r2, aft::raft_request_pre_vote);
  DOCTEST_REQUIRE(r2.get_view() == 1);

  DOCTEST_INFO("With node 1's pre-vote, node 0 becomes a candidate in view 1");
  deliver(r1, r0, aft::raft_request_pre_vote_response);
  DOCTEST_REQUIRE(r0.is_candidate());
  DOCTEST_REQUIRE(r0.get_view() == 1);
  channel_stub_proxy(r0)->messages.clear();

  DOCTEST_INFO(
    "Node 2's refusal carries node 0's new view, but node 0's pre-vote is "
    "over, so the refusal is ignored");
  deliver(r2, r0, aft::raft_request_pre_vote_response);
  DOCTEST_REQUIRE(r0.is_candidate());
  DOCTEST_REQUIRE(r0.get_view() == 1);
  DOCTEST_REQUIRE(channel_stub_proxy(r0)->messages.empty());

  DOCTEST_INFO(
    "A pre-vote grant in node 0's new view, which no correct node sends, is "
    "not counted as a vote either");
  const auto grant = as_bytes(
    aft::RequestPreVoteResponse{.term = r0.get_view(), .vote_granted = true});
  r0.recv_message(node_id2, grant.data(), grant.size());
  DOCTEST_REQUIRE(r0.is_candidate());
  DOCTEST_REQUIRE_FALSE(r0.is_primary());
}

DOCTEST_TEST_CASE(
  "Late joiner catching up only commits at a signature it holds" *
  doctest::test_suite("multiple"))
{
  ccf::NodeId node_id0 = ccf::kv::test::PrimaryNodeId;
  ccf::NodeId node_id1 = ccf::kv::test::FirstBackupNodeId;
  ccf::NodeId node_id2 = ccf::kv::test::SecondBackupNodeId;

  TestNode node0(node_id0);
  TestNode node1(node_id1);
  TestNode node2(node_id2);
  auto& r0 = node0.raft;
  auto& r1 = node1.raft;
  auto& r2 = node2.raft;

  aft::Configuration::Nodes config0;
  config0[node_id0] = {};
  config0[node_id1] = {};
  r0.add_configuration(0, config0);
  r1.add_configuration(0, config0);

  std::map<ccf::NodeId, TRaft*> nodes;
  nodes[node_id0] = &r0;
  nodes[node_id1] = &r1;

  r0.start_ticking();
  r0.periodic(election_timeout * 2);
  // Pre-vote, vote, then the initial heartbeat, and each response
  for (size_t round = 0; round < 3; ++round)
  {
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_id0));
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_id1));
  }
  DOCTEST_REQUIRE(r0.is_primary());

  // Each entry is as large as an AppendEntries, so is sent on its own. Entry
  // 1 is not a signature, entry 2 is.
  DOCTEST_REQUIRE(r0.replicate(
    ccf::kv::BatchVector{{1, make_ledger_entry(1, 1), false, hooks}}, 1));
  DOCTEST_REQUIRE(r0.replicate(
    ccf::kv::BatchVector{{2, make_ledger_entry(1, 2), true, hooks}}, 1));
  DOCTEST_REQUIRE(2 == dispatch_all(nodes, node_id0));
  DOCTEST_REQUIRE(2 == dispatch_all(nodes, node_id1));
  DOCTEST_REQUIRE(r0.get_committed_seqno() == 2);

  DOCTEST_INFO("Node 2 joins, and asks to be sent the entries it lacks");
  aft::Configuration::Nodes config1 = config0;
  config1[node_id2] = {};
  for (auto* r : {&r0, &r1, &r2})
  {
    r->add_configuration(0, config1);
  }
  nodes[node_id2] = &r2;
  DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_id0));
  DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_id2));
  r0.periodic(request_timeout);

  auto r0c = channel_stub_proxy(r0);
  const auto first = r0c->pop_first(aft::raft_append_entries, node_id2);
  DOCTEST_REQUIRE(first.has_value());
  const auto first_ae = read_msg<aft::AppendEntries>(first.value());
  DOCTEST_REQUIRE(first_ae.idx == 1);
  DOCTEST_REQUIRE(first_ae.leader_commit_idx == 2);
  receive_message(r0, r2, first.value());

  // Node 2 holds entry 1, which the primary has committed, but must not commit
  // it until it holds the signature after it
  DOCTEST_REQUIRE(r2.get_last_idx() == 1);
  DOCTEST_REQUIRE(r2.get_committed_seqno() == 0);

  const auto second = r0c->pop_first(aft::raft_append_entries, node_id2);
  DOCTEST_REQUIRE(second.has_value());
  receive_message(r0, r2, second.value());
  DOCTEST_REQUIRE(r2.get_last_idx() == 2);
  DOCTEST_REQUIRE(r2.get_committed_seqno() == 2);
}

DOCTEST_TEST_CASE(
  "Node without a configuration replicates and commits but does not tick" *
  doctest::test_suite("multiple"))
{
  // As for a joining node, which is in the primary's configuration, but has
  // not yet received the ledger entries which add it
  ccf::NodeId node_id0 = ccf::kv::test::PrimaryNodeId;
  ccf::NodeId node_id1 = ccf::kv::test::FirstBackupNodeId;

  TestNode node0(node_id0);
  TestNode node1(node_id1);
  auto& r0 = node0.raft;
  auto& r1 = node1.raft;

  aft::Configuration::Nodes config;
  config[node_id0] = {};
  config[node_id1] = {};
  r0.add_configuration(0, config);

  std::map<ccf::NodeId, TRaft*> nodes;
  nodes[node_id0] = &r0;
  nodes[node_id1] = &r1;

  r0.start_ticking();
  r0.periodic(election_timeout * 2);
  // Pre-vote, vote, then the initial heartbeat, and each response
  for (size_t round = 0; round < 3; ++round)
  {
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_id0));
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_id1));
  }
  DOCTEST_REQUIRE(r0.is_primary());

  auto data = std::make_shared<std::vector<uint8_t>>(3, 1);
  DOCTEST_REQUIRE(
    r0.replicate(ccf::kv::BatchVector{{1, data, true, hooks}}, 1));
  // Entry 1, then a heartbeat carrying its commit, and each response
  for (size_t round = 0; round < 2; ++round)
  {
    r0.periodic(request_timeout);
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_id0));
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_id1));
  }
  DOCTEST_REQUIRE(r1.get_committed_seqno() == 1);

  const auto details = r1.get_details();
  DOCTEST_REQUIRE(details.configs.empty());
  DOCTEST_REQUIRE_FALSE(details.ticking);

  DOCTEST_INFO(
    "It does not start an election, even when nudged by a retiring primary");
  auto r1c = channel_stub_proxy(r1);
  r1.periodic(election_timeout * 2);
  DOCTEST_REQUIRE(r1c->messages.empty());
  const auto msg = as_bytes(aft::ProposeRequestVote{.term = r1.get_view()});
  r1.recv_message(node_id0, msg.data(), msg.size());
  DOCTEST_REQUIRE(r1c->messages.empty());
  DOCTEST_REQUIRE(r1.is_backup());
}

DOCTEST_TEST_CASE(
  "Recovered primary and snapshot-resumed backup continue the ledger" *
  doctest::test_suite("multiple"))
{
  ccf::NodeId node_id0 = ccf::kv::test::PrimaryNodeId;
  ccf::NodeId node_id1 = ccf::kv::test::FirstBackupNodeId;

  TestNode node0(node_id0);
  TestNode node1(node_id1);
  auto& r0 = node0.raft;
  auto& r1 = node1.raft;

  aft::Configuration::Nodes config;
  config[node_id0] = {};
  config[node_id1] = {};
  r0.add_configuration(0, config);
  r1.add_configuration(0, config);

  std::map<ccf::NodeId, TRaft*> nodes;
  nodes[node_id0] = &r0;
  nodes[node_id1] = &r1;

  // Both nodes resume at seqno 7 in view 3, where views 1, 2 and 3 started at
  // seqnos 1, 4 and 6
  const aft::Index recovered_idx = 7;
  const aft::Term recovered_view = 3;
  const std::vector<aft::Index> view_history = {1, 4, 6};

  // As in node_state.h, a recovered primary's commit index is the last
  // recovered seqno
  r0.force_become_primary(
    recovered_idx, recovered_view, view_history, recovered_idx);
  // As for a joiner resuming from a snapshot at that seqno
  r1.init_as_backup(recovered_idx, recovered_view, view_history);

  DOCTEST_REQUIRE(r0.is_primary());
  DOCTEST_REQUIRE(r0.get_view() == recovered_view + aft::starting_view_change);
  DOCTEST_REQUIRE(r1.is_backup());
  DOCTEST_REQUIRE(r1.get_view() == recovered_view);
  for (auto* r : {&r0, &r1})
  {
    DOCTEST_REQUIRE(r->get_last_idx() == recovered_idx);
    DOCTEST_REQUIRE(
      r->get_committed_txid() == std::make_pair(recovered_view, recovered_idx));
    DOCTEST_REQUIRE(r->get_view(3) == 1);
    DOCTEST_REQUIRE(r->get_view(4) == 2);
    DOCTEST_REQUIRE(r->get_view(recovered_idx) == 3);
    DOCTEST_REQUIRE(
      r->get_view_history_since(2) == std::vector<aft::Index>{4, 6});
  }

  DOCTEST_INFO(
    "The primary's initial heartbeat brings the backup into its view");
  DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_id0));
  DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_id1));
  const auto new_view = r0.get_view();
  DOCTEST_REQUIRE(r1.get_view() == new_view);

  DOCTEST_INFO("Both commit the next signature, in the new view");
  const auto next_idx = recovered_idx + 1;
  auto data = std::make_shared<std::vector<uint8_t>>(3, 1);
  DOCTEST_REQUIRE(r0.replicate(
    ccf::kv::BatchVector{{next_idx, data, true, hooks}}, new_view));
  // The signature, then a heartbeat carrying its commit, and each response
  for (size_t round = 0; round < 2; ++round)
  {
    r0.periodic(request_timeout);
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_id0));
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_id1));
  }
  for (auto* r : {&r0, &r1})
  {
    DOCTEST_REQUIRE(r->get_committed_seqno() == next_idx);
    DOCTEST_REQUIRE(r->get_view(next_idx) == new_view);
    DOCTEST_REQUIRE(r->get_view(recovered_idx) == recovered_view);
  }

  DOCTEST_INFO("Leadership cannot be forced once a leader is known");
  DOCTEST_REQUIRE_THROWS_AS(r0.force_become_primary(), std::logic_error);
  DOCTEST_REQUIRE_THROWS_AS(
    r1.force_become_primary(
      recovered_idx, recovered_view, view_history, recovered_idx),
    std::logic_error);
}

DOCTEST_TEST_CASE(
  "Election attempts without a configuration are ignored" *
  doctest::test_suite("single"))
{
  ccf::NodeId node_id = ccf::kv::test::PrimaryNodeId;

  bool pre_vote_enabled = true;
  DOCTEST_SUBCASE("Pre-vote enabled")
  {
    pre_vote_enabled = true;
  }
  DOCTEST_SUBCASE("Pre-vote disabled")
  {
    pre_vote_enabled = false;
  }

  TestNode node(node_id, {.pre_vote_enabled = pre_vote_enabled});
  auto& r0 = node.raft;
  auto r0c = channel_stub_proxy(r0);

  r0.start_ticking();
  r0.periodic(election_timeout * 2);

  const auto details = r0.get_details();
  DOCTEST_REQUIRE(details.leadership_state == ccf::kv::LeadershipState::None);
  DOCTEST_REQUIRE(details.current_view == 0);
  DOCTEST_REQUIRE(r0c->messages.empty());

  DOCTEST_INFO("Once it has a configuration, the same timeout elects it");
  aft::Configuration::Nodes config;
  config[node_id] = {};
  r0.add_configuration(0, config);
  r0.periodic(election_timeout * 2);
  DOCTEST_REQUIRE(r0.is_primary());
  DOCTEST_REQUIRE(r0.get_view() == 1);
}

DOCTEST_TEST_CASE(
  "Adding a configuration identical to the latest is a no-op" *
  doctest::test_suite("single"))
{
  ccf::NodeId node_id0 = ccf::kv::test::PrimaryNodeId;
  ccf::NodeId node_id1 = ccf::kv::test::FirstBackupNodeId;

  TestNode node(node_id0);
  auto& r0 = node.raft;

  aft::Configuration::Nodes config0;
  config0[node_id0] = {};
  r0.add_configuration(0, config0);
  DOCTEST_REQUIRE(r0.get_latest_configuration() == config0);

  // For instance, after a write to the nodes table which does not change
  // membership
  r0.add_configuration(2, config0);
  DOCTEST_REQUIRE(r0.get_details().configs.size() == 1);
  DOCTEST_REQUIRE(r0.get_details().configs.front().idx == 0);

  aft::Configuration::Nodes config1 = config0;
  config1[node_id1] = {};
  r0.add_configuration(3, config1);
  DOCTEST_REQUIRE(r0.get_details().configs.size() == 2);
  DOCTEST_REQUIRE(r0.get_latest_configuration() == config1);
}

DOCTEST_TEST_CASE(
  "Newly elected primary should sign until it replicates a signature" *
  doctest::test_suite("multiple"))
{
  PrimaryAndBackup n;

  DOCTEST_INFO("A backup can neither replicate nor sign");
  DOCTEST_REQUIRE_FALSE(n.r1.can_replicate());
  DOCTEST_REQUIRE(
    n.r1.get_signature_disposition() ==
    ccf::kv::Consensus::SignatureDisposition::CANT_REPLICATE);

  DOCTEST_INFO("A newly elected primary should sign");
  DOCTEST_REQUIRE(n.r0.can_replicate());
  DOCTEST_REQUIRE(
    n.r0.get_signature_disposition() ==
    ccf::kv::Consensus::SignatureDisposition::SHOULD_SIGN);

  DOCTEST_INFO("An entry which is not committable does not change that");
  n.replicate(1, 1, false);
  DOCTEST_REQUIRE(
    n.r0.get_signature_disposition() ==
    ccf::kv::Consensus::SignatureDisposition::SHOULD_SIGN);

  DOCTEST_INFO("A committable entry does");
  n.replicate(2, 2, true);
  DOCTEST_REQUIRE(
    n.r0.get_signature_disposition() ==
    ccf::kv::Consensus::SignatureDisposition::CAN_SIGN);

  DOCTEST_INFO("A primary which steps down (CheckQuorum) can no longer sign");
  n.r0.periodic(election_timeout);
  DOCTEST_REQUIRE_FALSE(n.r0.is_primary());
  DOCTEST_REQUIRE_FALSE(n.r0.can_replicate());
  DOCTEST_REQUIRE(
    n.r0.get_signature_disposition() ==
    ccf::kv::Consensus::SignatureDisposition::CANT_REPLICATE);
}

DOCTEST_TEST_CASE(
  "Primary is at max capacity while too many entries are uncommitted" *
  doctest::test_suite("multiple"))
{
  DOCTEST_SUBCASE("A limit of 0 is no limit")
  {
    PrimaryAndBackup n;
    n.replicate(1, 5);
    DOCTEST_REQUIRE(n.r0.get_committed_seqno() == 0);
    DOCTEST_REQUIRE_FALSE(n.r0.is_at_max_capacity());
  }

  DOCTEST_SUBCASE("With a limit")
  {
    const size_t max_uncommitted_tx_count = 2;
    const ccf::consensus::Configuration settings{
      request_timeout_, election_timeout_, max_uncommitted_tx_count};
    PrimaryAndBackup n({.settings = settings}, {.settings = settings});

    n.replicate(1, 1);
    DOCTEST_REQUIRE_FALSE(n.r0.is_at_max_capacity());
    n.replicate(2, 2);
    DOCTEST_REQUIRE(n.r0.is_at_max_capacity());
    DOCTEST_REQUIRE_FALSE(n.r1.is_at_max_capacity());

    DOCTEST_INFO("Until the backup acknowledges the entries, and they commit");
    n.r0.periodic(request_timeout);
    const auto response =
      n.backup_receives(n.with_payload(n.take_append_entries_header()));
    require_ack(response, 2);
    n.primary_receives(response.value());
    DOCTEST_REQUIRE(n.r0.get_committed_seqno() == 2);
    DOCTEST_REQUIRE_FALSE(n.r0.is_at_max_capacity());
  }
}

// Records whether each call to deserialize() was for public domains only
class DomainRecordingStore : public Store
{
public:
  using Store::Store;

  std::vector<bool> public_only_requests;

  std::unique_ptr<ccf::kv::AbstractExecutionWrapper> deserialize(
    const std::vector<uint8_t>& data,
    bool public_only = false,
    const std::optional<ccf::TxID>& expected_txid = std::nullopt) override
  {
    public_only_requests.push_back(public_only);
    return Store::deserialize(data, public_only, expected_txid);
  }
};

DOCTEST_TEST_CASE(
  "Public-only consensus deserialises all domains after enable_all_domains" *
  doctest::test_suite("multiple"))
{
  // As for a node set up during recovery, which deserialises only public
  // domains until the private ledger has been recovered
  auto kv1 =
    std::make_shared<DomainRecordingStore>(ccf::kv::test::FirstBackupNodeId);
  PrimaryAndBackup n({}, {.kv = kv1, .public_only = true});

  n.replicate(1, 1);
  n.r0.periodic(request_timeout);
  auto response =
    n.backup_receives(n.with_payload(n.take_append_entries_header()));
  require_ack(response, 1);
  n.primary_receives(response.value());

  n.r1.enable_all_domains();

  n.replicate(2, 2);
  n.r0.periodic(request_timeout);
  response = n.backup_receives(n.with_payload(n.take_append_entries_header()));
  require_ack(response, 2);

  DOCTEST_REQUIRE(kv1->public_only_requests == std::vector<bool>{true, false});
}

DOCTEST_TEST_CASE(
  "Commit callbacks are invoked as entries commit" *
  doctest::test_suite("single"))
{
  ccf::NodeId node_id = ccf::kv::test::PrimaryNodeId;
  auto commit_callbacks = std::make_shared<ccf::CommitCallbackSubsystem>();
  TestNode node(node_id, {.commit_callbacks = commit_callbacks});
  auto& r0 = node.raft;

  aft::Configuration::Nodes config;
  config[node_id] = {};
  r0.add_configuration(0, config);
  r0.start_ticking();
  r0.periodic(election_timeout * 2);
  DOCTEST_REQUIRE(r0.is_primary());
  const auto view = r0.get_view();

  std::vector<std::pair<ccf::TxID, ccf::FinalTxStatus>> results;
  const auto record = [&results](ccf::TxID tx_id, ccf::FinalTxStatus status) {
    results.emplace_back(tx_id, status);
  };

  const ccf::TxID tx_1{view, 1};
  // Seqno 1 will be committed in view, so cannot also be in a later view
  const ccf::TxID tx_1_later_view{view + 1, 1};
  const ccf::TxID tx_2{view, 2};
  commit_callbacks->add_callback(tx_1, record);
  commit_callbacks->add_callback(tx_1_later_view, record);
  commit_callbacks->add_callback(tx_2, record);

  // A single node commits each committable entry as soon as it replicates it
  auto data = std::make_shared<std::vector<uint8_t>>(3, 1);
  DOCTEST_REQUIRE(
    r0.replicate(ccf::kv::BatchVector{{1, data, true, hooks}}, view));
  DOCTEST_REQUIRE(results.size() == 2);
  DOCTEST_REQUIRE(results[0].first == tx_1);
  DOCTEST_REQUIRE(results[0].second == ccf::FinalTxStatus::Committed);
  DOCTEST_REQUIRE(results[1].first == tx_1_later_view);
  DOCTEST_REQUIRE(results[1].second == ccf::FinalTxStatus::Invalid);

  DOCTEST_REQUIRE(
    r0.replicate(ccf::kv::BatchVector{{2, data, true, hooks}}, view));
  DOCTEST_REQUIRE(results.size() == 3);
  DOCTEST_REQUIRE(results[2].first == tx_2);
  DOCTEST_REQUIRE(results[2].second == ccf::FinalTxStatus::Committed);
}

DOCTEST_TEST_CASE(
  "Rollback below commit_idx is ignored" * doctest::test_suite("single"))
{
  ccf::NodeId node_id = ccf::kv::test::PrimaryNodeId;
  TestNode node(node_id);
  auto& r0 = node.raft;

  aft::Configuration::Nodes config;
  config[node_id] = {};
  r0.add_configuration(0, config);

  r0.start_ticking();
  r0.periodic(election_timeout * 2);
  DOCTEST_REQUIRE(r0.is_primary());

  for (size_t i = 1; i <= 3; ++i)
  {
    auto entry =
      std::make_shared<std::vector<uint8_t>>(std::vector<uint8_t>{1, 2, 3});
    DOCTEST_REQUIRE(
      r0.replicate(ccf::kv::BatchVector{{i, entry, true, hooks}}, 1));
  }
  DOCTEST_REQUIRE(r0.get_last_idx() == 3);
  DOCTEST_REQUIRE(r0.get_committed_seqno() == 3);

  // Attempting to roll back to an index below commit_idx must be a no-op.
  r0.rollback(1);

  DOCTEST_REQUIRE(r0.get_last_idx() == 3);
  DOCTEST_REQUIRE(r0.get_committed_seqno() == 3);
  DOCTEST_REQUIRE(r0.ledger->ledger.size() == 3);
}

DOCTEST_TEST_CASE(
  "Replicate rejects a non-consecutive index" * doctest::test_suite("single"))
{
  ccf::NodeId node_id = ccf::kv::test::PrimaryNodeId;
  TestNode node(node_id);
  auto& r0 = node.raft;

  aft::Configuration::Nodes config;
  config[node_id] = {};
  r0.add_configuration(0, config);

  r0.start_ticking();
  r0.periodic(election_timeout * 2);
  DOCTEST_REQUIRE(r0.is_primary());

  auto entry =
    std::make_shared<std::vector<uint8_t>>(std::vector<uint8_t>{1, 2, 3});

  // The very first entry must be at index 1; anything else is rejected.
  DOCTEST_REQUIRE_FALSE(
    r0.replicate(ccf::kv::BatchVector{{5, entry, true, hooks}}, 1));
  DOCTEST_REQUIRE(r0.get_last_idx() == 0);
  DOCTEST_REQUIRE(r0.ledger->ledger.size() == 0);

  DOCTEST_REQUIRE(
    r0.replicate(ccf::kv::BatchVector{{1, entry, true, hooks}}, 1));
  DOCTEST_REQUIRE(r0.get_last_idx() == 1);

  // Having replicated index 1, index 3 is non-consecutive and rejected.
  DOCTEST_REQUIRE_FALSE(
    r0.replicate(ccf::kv::BatchVector{{3, entry, true, hooks}}, 1));
  DOCTEST_REQUIRE(r0.get_last_idx() == 1);
  DOCTEST_REQUIRE(r0.ledger->ledger.size() == 1);
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