// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

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

DOCTEST_TEST_CASE(
  "Recv append entries with malformed or undeserialisable entries" *
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
    // Initial (empty) heartbeat AppendEntries
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_id0, r0c->messages));
    // Drop the follower's resulting ACK; it is not relevant to this test.
    r1c->messages.clear();
  }

  std::vector<uint8_t> first_entry = {1, 1, 1};
  auto data = std::make_shared<std::vector<uint8_t>>(first_entry);
  DOCTEST_REQUIRE(
    r0.replicate(ccf::kv::BatchVector{{1, data, true, hooks}}, 1));
  r0.periodic(request_timeout);
  DOCTEST_REQUIRE(r0c->messages.size() == 1);

  auto header = r0c->messages.front().second;
  r0c->messages.pop_front();

  DOCTEST_SUBCASE("Truncated / malformed entry payload")
  {
    // Claim an entry body far larger than the (empty) space available after
    // the size prefix, causing the ledger entry parser to throw
    // std::logic_error rather than reading out of bounds.
    std::vector<uint8_t> corrupt_payload(sizeof(size_t));
    {
      uint8_t* p = corrupt_payload.data();
      size_t s = corrupt_payload.size();
      serialized::write<size_t>(p, s, 1'000'000);
    }

    std::vector<uint8_t> msg = header;
    msg.insert(msg.end(), corrupt_payload.begin(), corrupt_payload.end());

    r1.recv_message(node_id0, msg.data(), msg.size());

    DOCTEST_REQUIRE(r1.get_last_idx() == 0);
    DOCTEST_REQUIRE(r1.ledger->ledger.size() == 0);
    DOCTEST_REQUIRE(
      1 ==
      dispatch_all_and_DOCTEST_CHECK<aft::AppendEntriesResponse>(
        nodes, node_id1, r1c->messages, [](const auto& msg) {
          DOCTEST_REQUIRE(msg.success == aft::AppendEntriesResponseType::FAIL);
        }));
  }

  DOCTEST_SUBCASE("Entry deserialises to nullptr")
  {
    // Instruct the follower's store to fail to construct an execution
    // wrapper for this entry, as though it could not be parsed at all.
    kv_store1->deserialize_fails_at = 1;

    auto ae = *(aft::AppendEntries*)header.data();
    const auto payload_opt = r0.ledger->get_append_entries_payload(ae);
    DOCTEST_REQUIRE(payload_opt.has_value());

    std::vector<uint8_t> msg = header;
    msg.insert(msg.end(), payload_opt->begin(), payload_opt->end());

    r1.recv_message(node_id0, msg.data(), msg.size());

    DOCTEST_REQUIRE(r1.get_last_idx() == 0);
    DOCTEST_REQUIRE(r1.ledger->ledger.size() == 0);
    DOCTEST_REQUIRE(
      1 ==
      dispatch_all_and_DOCTEST_CHECK<aft::AppendEntriesResponse>(
        nodes, node_id1, r1c->messages, [](const auto& msg) {
          DOCTEST_REQUIRE(msg.success == aft::AppendEntriesResponseType::FAIL);
        }));
  }
}

DOCTEST_TEST_CASE(
  "Recv append entries claiming prev_idx beyond the follower's log" *
  doctest::test_suite("multiple"))
{
  ccf::NodeId node_id0 = ccf::kv::test::PrimaryNodeId;
  ccf::NodeId node_id1 = ccf::kv::test::FirstBackupNodeId;

  auto kv_store1 = std::make_shared<Store>(node_id1);
  TRaft r1(
    raft_settings,
    std::make_unique<Adaptor>(kv_store1),
    std::make_unique<aft::LedgerStubProxy>(node_id1),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::State>(node_id1),
    nullptr);

  aft::Configuration::Nodes config;
  config[node_id0] = {};
  config[node_id1] = {};
  r1.add_configuration(0, config);

  auto r1c = channel_stub_proxy(r1);

  DOCTEST_REQUIRE(r1.get_last_idx() == 0);

  aft::AppendEntries ae{};
  ae.idx = 5;
  ae.prev_idx = 5;
  ae.term = r1.get_view();
  ae.prev_term = r1.get_view() + 1; // Deliberately not VIEW_UNKNOWN
  ae.leader_commit_idx = 0;
  ae.term_of_idx = r1.get_view();

  r1.recv_message(node_id0, reinterpret_cast<const uint8_t*>(&ae), sizeof(ae));

  DOCTEST_REQUIRE(r1.get_last_idx() == 0);
  auto response = r1c->pop_first(aft::raft_append_entries_response, node_id0);
  DOCTEST_REQUIRE(response.has_value());
  auto aer = *(aft::AppendEntriesResponse*)response->data();
  DOCTEST_REQUIRE(aer.success == aft::AppendEntriesResponseType::FAIL);
}

DOCTEST_TEST_CASE(
  "Recv truncated or unknown Raft messages" * doctest::test_suite("multiple"))
{
  ccf::NodeId node_id0 = ccf::kv::test::PrimaryNodeId;
  ccf::NodeId node_id1 = ccf::kv::test::FirstBackupNodeId;

  auto kv_store1 = std::make_shared<Store>(node_id1);
  TRaft r1(
    raft_settings,
    std::make_unique<Adaptor>(kv_store1),
    std::make_unique<aft::LedgerStubProxy>(node_id1),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::State>(node_id1),
    nullptr);

  aft::Configuration::Nodes config;
  config[node_id0] = {};
  config[node_id1] = {};
  r1.add_configuration(0, config);

  auto r1c = channel_stub_proxy(r1);

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

    // A buffer containing only the message type tag, too short for any of
    // the actual message structs, exercises the per-type size check in
    // recv_message via serialized::overlay<T>.
    std::vector<uint8_t> msg(sizeof(aft::RaftMsgType));
    {
      uint8_t* p = msg.data();
      size_t s = msg.size();
      serialized::write<aft::RaftMsgType>(p, s, type);
    }

    r1.recv_message(node_id0, msg.data(), msg.size());
    DOCTEST_REQUIRE(r1c->messages.empty());
  }

  DOCTEST_SUBCASE("Unhandled but known message type")
  {
    aft::RaftHeader<aft::raft_append_entries_signed_response> msg{};
    r1.recv_message(
      node_id0, reinterpret_cast<const uint8_t*>(&msg), sizeof(msg));
    DOCTEST_REQUIRE(r1c->messages.empty());
  }

  DOCTEST_SUBCASE("Entirely unknown message type")
  {
    auto type = static_cast<aft::RaftMsgType>(0xDEADBEEF);
    r1.recv_message(
      node_id0, reinterpret_cast<const uint8_t*>(&type), sizeof(type));
    DOCTEST_REQUIRE(r1c->messages.empty());
  }
}

DOCTEST_TEST_CASE(
  "Execute append entries ApplyResult::FAIL on follower" *
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

  r0.start_ticking();
  r0.periodic(election_timeout * 2);

  // Pre-vote
  DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_id0, r0c->messages));
  DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_id1, r1c->messages));
  // Vote
  DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_id0, r0c->messages));
  DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_id1, r1c->messages));
  DOCTEST_REQUIRE(r0.is_primary());
  // Initial (empty) heartbeat AppendEntries
  DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_id0, r0c->messages));
  // Drop the follower's resulting ACK; it is not relevant to this test.
  r1c->messages.clear();

  std::vector<uint8_t> first_entry = {1, 1, 1};
  auto data = std::make_shared<std::vector<uint8_t>>(first_entry);
  DOCTEST_REQUIRE(
    r0.replicate(ccf::kv::BatchVector{{1, data, true, hooks}}, 1));
  r0.periodic(request_timeout);
  DOCTEST_REQUIRE(r0c->messages.size() == 1);

  auto header_bytes = r0c->messages.front().second;
  r0c->messages.pop_front();

  // Tamper with the leader's claimed term_of_idx, so the follower's expected
  // TxID for this entry no longer matches the term embedded when the entry
  // was serialised. The stub store's ExecutionWrapper then reports
  // ApplyResult::FAIL, as a real store would for a genuinely conflicting
  // entry.
  auto ae = *(aft::AppendEntries*)header_bytes.data();
  ae.term_of_idx = ae.term_of_idx + 1;
  std::memcpy(header_bytes.data(), &ae, sizeof(ae));

  const auto payload_opt = r0.ledger->get_append_entries_payload(ae);
  DOCTEST_REQUIRE(payload_opt.has_value());
  std::vector<uint8_t> msg = header_bytes;
  msg.insert(msg.end(), payload_opt->begin(), payload_opt->end());

  r1.recv_message(node_id0, msg.data(), msg.size());

  DOCTEST_INFO("Follower rejected the entry and rolled back its ledger");
  DOCTEST_REQUIRE(r1.get_last_idx() == 0);
  DOCTEST_REQUIRE(r1.ledger->ledger.size() == 0);
  DOCTEST_REQUIRE(
    1 ==
    dispatch_all_and_DOCTEST_CHECK<aft::AppendEntriesResponse>(
      nodes, node_id1, r1c->messages, [](const auto& msg) {
        DOCTEST_REQUIRE(msg.success == aft::AppendEntriesResponseType::FAIL);
      }));
}

DOCTEST_TEST_CASE(
  "Rollback below commit_idx is ignored" * doctest::test_suite("single"))
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

DOCTEST_TEST_CASE("Force become primary" * doctest::test_suite("single"))
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

  DOCTEST_REQUIRE(!r0.is_primary());
  DOCTEST_REQUIRE(r0.get_view() == 0);

  DOCTEST_INFO("The recovery overload restores index, term and commit_idx");
  const aft::Index index = 42;
  const aft::Term term = 5;
  const std::vector<aft::Index> term_history = {1, 1, 1};
  const aft::Index commit_idx = 10;
  r0.force_become_primary(index, term, term_history, commit_idx);

  DOCTEST_REQUIRE(r0.is_primary());
  // become_leader() rolls back to the last committable index, which is
  // commit_idx here since no committable index above it was recorded by
  // this recovery path.
  DOCTEST_REQUIRE(r0.get_last_idx() == commit_idx);
  DOCTEST_REQUIRE(r0.get_committed_seqno() == commit_idx);
  // The term is bumped by starting_view_change (2) beyond the given term, to
  // ensure this node's term is fresher than any previous leader's.
  DOCTEST_REQUIRE(r0.get_view() == term + 2);

  DOCTEST_INFO(
    "Forcing leadership again fails, since this node already knows of a "
    "leader (itself)");
  DOCTEST_REQUIRE_THROWS_AS(r0.force_become_primary(), std::logic_error);
  DOCTEST_REQUIRE_THROWS_AS(
    r0.force_become_primary(index, term, term_history, commit_idx),
    std::logic_error);
}

DOCTEST_TEST_CASE(
  "Election attempts without a configuration are ignored" *
  doctest::test_suite("single"))
{
  ccf::NodeId node_id = ccf::kv::test::PrimaryNodeId;

  DOCTEST_SUBCASE("Pre-vote enabled (default)")
  {
    auto kv_store = std::make_shared<Store>(node_id);
    TRaft r0(
      raft_settings,
      std::make_unique<Adaptor>(kv_store),
      std::make_unique<aft::LedgerStubProxy>(node_id),
      std::make_shared<aft::ChannelStubProxy>(),
      std::make_shared<aft::State>(node_id),
      nullptr);
    auto r0c = channel_stub_proxy(r0);

    r0.start_ticking();
    r0.periodic(election_timeout * 2);

    DOCTEST_REQUIRE(r0c->messages.empty());
    DOCTEST_REQUIRE(!r0.is_primary());
  }

  DOCTEST_SUBCASE("Pre-vote disabled")
  {
    auto kv_store = std::make_shared<Store>(node_id);
    TRaft r0(
      raft_settings,
      std::make_unique<Adaptor>(kv_store),
      std::make_unique<aft::LedgerStubProxy>(node_id),
      std::make_shared<aft::ChannelStubProxy>(),
      std::make_shared<aft::State>(node_id, false),
      nullptr);
    auto r0c = channel_stub_proxy(r0);

    r0.start_ticking();
    r0.periodic(election_timeout * 2);

    DOCTEST_REQUIRE(r0c->messages.empty());
    DOCTEST_REQUIRE(!r0.is_primary());
  }
}

DOCTEST_TEST_CASE("Simple public API accessors" * doctest::test_suite("single"))
{
  ccf::NodeId node_id = ccf::kv::test::PrimaryNodeId;
  auto kv_store = std::make_shared<Store>(node_id);

  // Use a non-zero max_uncommitted_tx_count to exercise both branches of
  // is_at_max_capacity().
  const size_t max_uncommitted_tx_count = 1;
  const ccf::consensus::Configuration settings{
    request_timeout_, election_timeout_, max_uncommitted_tx_count};

  TRaft r0(
    settings,
    std::make_unique<Adaptor>(kv_store),
    std::make_unique<aft::LedgerStubProxy>(node_id),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::State>(node_id),
    nullptr);
  ccf::kv::Configuration::Nodes configuration;
  configuration.try_emplace(node_id);
  r0.add_configuration(0, configuration);

  // Not yet primary: can't replicate, at max capacity is trivially false, and
  // the signature disposition reports that replication is not possible.
  DOCTEST_REQUIRE(!r0.can_replicate());
  DOCTEST_REQUIRE(!r0.is_at_max_capacity());
  DOCTEST_REQUIRE(
    r0.get_signature_disposition() ==
    ccf::kv::Consensus::SignatureDisposition::CANT_REPLICATE);

  r0.force_become_primary();
  DOCTEST_REQUIRE(r0.is_primary());
  DOCTEST_REQUIRE(r0.can_replicate());

  // Immediately after becoming leader, should_sign is set, so a signature is
  // requested even though nothing has been replicated yet.
  DOCTEST_REQUIRE(
    r0.get_signature_disposition() ==
    ccf::kv::Consensus::SignatureDisposition::SHOULD_SIGN);

  DOCTEST_REQUIRE(!r0.is_at_max_capacity());

  auto data = std::make_shared<std::vector<uint8_t>>(1, 42);
  DOCTEST_REQUIRE(
    r0.replicate(ccf::kv::BatchVector{{1, data, true, hooks}}, r0.get_view()));

  // A committable entry has now been replicated, so a fresh signature is no
  // longer required, but the node can still sign.
  DOCTEST_REQUIRE(
    r0.get_signature_disposition() ==
    ccf::kv::Consensus::SignatureDisposition::CAN_SIGN);

  // last_idx (1) == commit_idx (1) here: for a single-node configuration,
  // replication commits immediately, so max capacity is never reached.
  DOCTEST_REQUIRE(!r0.is_at_max_capacity());

  auto [term, committed_idx] = r0.get_committed_txid();
  DOCTEST_REQUIRE(committed_idx == 1);
  DOCTEST_REQUIRE(term == r0.get_view());

  DOCTEST_REQUIRE(
    r0.get_view_history_since(1) == std::vector<aft::Index>{1, 1});

  DOCTEST_REQUIRE(r0.get_latest_configuration().size() == 1);

  // enable_all_domains() only toggles internal state; simply confirm it can
  // be called without effect on the externally-visible state.
  r0.enable_all_domains();
  DOCTEST_REQUIRE(r0.is_primary());
}

DOCTEST_TEST_CASE(
  "init_as_backup restores state" * doctest::test_suite("single"))
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

  const aft::Index index = 7;
  const aft::Term term = 3;
  const std::vector<aft::Index> term_history = {1, 1, 1, 1, 1, 1, 1};
  r0.init_as_backup(index, term, term_history);

  DOCTEST_REQUIRE(r0.get_last_idx() == index);
  DOCTEST_REQUIRE(r0.get_committed_seqno() == index);
  DOCTEST_REQUIRE(r0.get_view() == term);
  DOCTEST_REQUIRE(!r0.is_primary());
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