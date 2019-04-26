// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "../../ds/logger.h"
#include "../raft.h"
#include "logging_stub.h"

#include <chrono>
#include <doctest/doctest.h>
#include <string>

using namespace std;

using ms = std::chrono::milliseconds;
using TRaft = raft::Raft<raft::LedgerStubProxy, raft::ChannelStubProxy>;
using Store = raft::LoggingStubStore;
using Adaptor = raft::Adaptor<Store, kv::DeserialiseSuccess>;

TEST_CASE("Single node startup" * doctest::test_suite("single"))
{
  auto kv_store = std::make_shared<Store>(0);
  raft::NodeId node_id(0);
  ms election_timeout(150);

  TRaft r0(
    std::make_unique<Adaptor>(kv_store),
    std::make_unique<raft::LedgerStubProxy>(node_id),
    std::make_shared<raft::ChannelStubProxy>(),
    node_id,
    ms(10),
    election_timeout);

  std::unordered_set<raft::NodeId> config = {node_id};
  r0.add_configuration(0, config);

  INFO("REQUIRE Initial State");

  REQUIRE(!r0.is_leader());
  REQUIRE(r0.leader() == raft::NoNode);
  REQUIRE(r0.get_term() == 0);
  REQUIRE(r0.get_commit_idx() == 0);

  INFO("In the absence of other nodes, become leader after election timeout");

  r0.periodic(ms(0));
  REQUIRE(!r0.is_leader());

  r0.periodic(election_timeout * 2);
  REQUIRE(r0.is_leader());
  REQUIRE(r0.leader() == node_id);
}

TEST_CASE("Single node commit" * doctest::test_suite("single"))
{
  auto kv_store = std::make_shared<Store>(0);
  raft::NodeId node_id(0);
  ms election_timeout(150);

  TRaft r0(
    std::make_unique<Adaptor>(kv_store),
    std::make_unique<raft::LedgerStubProxy>(node_id),
    std::make_shared<raft::ChannelStubProxy>(),
    node_id,
    ms(10),
    election_timeout);

  std::unordered_set<raft::NodeId> config = {node_id};
  r0.add_configuration(0, config);

  INFO("Become leader after election timeout");

  r0.periodic(election_timeout * 2);
  REQUIRE(r0.is_leader());

  INFO("Observe that data is committed on replicate immediately");

  for (size_t i = 1; i <= 5; ++i)
  {
    r0.replicate({{i, {1, 2, 3}, true}});
    REQUIRE(r0.get_last_idx() == i);
    REQUIRE(r0.get_commit_idx() == i);
  }
}

TEST_CASE(
  "Multiple nodes startup and election" * doctest::test_suite("multiple"))
{
  auto kv_store0 = std::make_shared<Store>(0);
  auto kv_store1 = std::make_shared<Store>(1);
  auto kv_store2 = std::make_shared<Store>(2);

  raft::NodeId node_id0(0);
  raft::NodeId node_id1(1);
  raft::NodeId node_id2(2);

  ms request_timeout(10);

  TRaft r0(
    std::make_unique<Adaptor>(kv_store0),
    std::make_unique<raft::LedgerStubProxy>(node_id0),
    std::make_shared<raft::ChannelStubProxy>(),
    node_id0,
    request_timeout,
    ms(20));
  TRaft r1(
    std::make_unique<Adaptor>(kv_store1),
    std::make_unique<raft::LedgerStubProxy>(node_id1),
    std::make_shared<raft::ChannelStubProxy>(),
    node_id1,
    request_timeout,
    ms(100));
  TRaft r2(
    std::make_unique<Adaptor>(kv_store2),
    std::make_unique<raft::LedgerStubProxy>(node_id2),
    std::make_shared<raft::ChannelStubProxy>(),
    node_id2,
    request_timeout,
    ms(50));

  std::unordered_set<raft::NodeId> config = {node_id0, node_id1, node_id2};
  r0.add_configuration(0, config);
  r1.add_configuration(0, config);
  r2.add_configuration(0, config);

  auto by_0 = [](auto const& lhs, auto const& rhs) -> bool {
    return get<0>(lhs) < get<0>(rhs);
  };

  INFO("Node 0 exceeds its election timeout and starts an election");

  r0.periodic(std::chrono::milliseconds(200));
  REQUIRE(r0.channels->sent_request_vote.size() == 2);
  r0.channels->sent_request_vote.sort(by_0);

  INFO("Node 1 receives the request");

  auto rv = r0.channels->sent_request_vote.front();
  r0.channels->sent_request_vote.pop_front();
  REQUIRE(get<0>(rv) == node_id1);
  auto rvc = get<1>(rv);
  REQUIRE(rvc.term == 1);
  REQUIRE(rvc.last_log_idx == 0);
  REQUIRE(rvc.last_log_term == 0);

  r1.recv_message(reinterpret_cast<uint8_t*>(&rvc), sizeof(rvc));

  INFO("Node 2 receives the request");

  rv = r0.channels->sent_request_vote.front();
  r0.channels->sent_request_vote.pop_front();
  REQUIRE(get<0>(rv) == node_id2);
  rvc = get<1>(rv);
  REQUIRE(rvc.term == 1);
  REQUIRE(rvc.last_log_idx == 0);
  REQUIRE(rvc.last_log_term == 0);

  r2.recv_message(reinterpret_cast<uint8_t*>(&rvc), sizeof(rvc));

  INFO("Node 1 votes for Node 0");

  REQUIRE(r1.channels->sent_request_vote_response.size() == 1);
  auto rvr = r1.channels->sent_request_vote_response.front();
  r1.channels->sent_request_vote_response.pop_front();

  REQUIRE(get<0>(rvr) == node_id0);
  auto rvrc = get<1>(rvr);
  REQUIRE(rvrc.term == 1);
  REQUIRE(rvrc.vote_granted);

  r0.recv_message(reinterpret_cast<uint8_t*>(&rvrc), sizeof(rvrc));

  INFO("Node 2 votes for Node 0");

  REQUIRE(r2.channels->sent_request_vote_response.size() == 1);
  rvr = r2.channels->sent_request_vote_response.front();
  r2.channels->sent_request_vote_response.pop_front();

  REQUIRE(get<0>(rvr) == node_id0);
  rvrc = get<1>(rvr);
  REQUIRE(rvrc.term == 1);
  REQUIRE(rvrc.vote_granted);

  r0.recv_message(reinterpret_cast<uint8_t*>(&rvrc), sizeof(rvrc));

  INFO("Node 0 is now leader, and sends empty append entries to other nodes");

  REQUIRE(r0.is_leader());
  REQUIRE(r0.channels->sent_append_entries.size() == 2);
  r0.channels->sent_append_entries.sort(by_0);

  auto ae = r0.channels->sent_append_entries.front();
  r0.channels->sent_append_entries.pop_front();
  REQUIRE(get<0>(ae) == node_id1);
  auto aec = get<1>(ae);
  REQUIRE(aec.idx == 0);
  REQUIRE(aec.term == 1);
  REQUIRE(aec.prev_idx == 0);
  REQUIRE(aec.prev_term == 0);
  REQUIRE(aec.leader_commit_idx == 0);

  ae = r0.channels->sent_append_entries.front();
  r0.channels->sent_append_entries.pop_front();
  REQUIRE(get<0>(ae) == node_id2);
  aec = get<1>(ae);
  REQUIRE(aec.idx == 0);
  REQUIRE(aec.term == 1);
  REQUIRE(aec.prev_idx == 0);
  REQUIRE(aec.prev_term == 0);
  REQUIRE(aec.leader_commit_idx == 0);
}

template <class NodeMap, class Messages>
static size_t dispatch_all(NodeMap& nodes, Messages& messages)
{
  size_t count = 0;
  while (messages.size())
  {
    auto message = messages.front();
    messages.pop_front();
    auto tgt_node_id = get<0>(message);
    auto contents = get<1>(message);
    nodes[tgt_node_id]->recv_message(
      reinterpret_cast<uint8_t*>(&contents), sizeof(contents));
    count++;
  }
  return count;
}

template <class NodeMap, class Messages, class Assertion>
static size_t dispatch_all_and_check(
  NodeMap& nodes, Messages& messages, const Assertion& assertion)
{
  size_t count = 0;
  while (messages.size())
  {
    auto message = messages.front();
    messages.pop_front();
    auto tgt_node_id = get<0>(message);
    auto contents = get<1>(message);
    assertion(contents);
    nodes[tgt_node_id]->recv_message(
      reinterpret_cast<uint8_t*>(&contents), sizeof(contents));
    count++;
  }
  return count;
}

TEST_CASE("Multiple nodes append entries" * doctest::test_suite("multiple"))
{
  auto kv_store0 = std::make_shared<Store>(0);
  auto kv_store1 = std::make_shared<Store>(1);
  auto kv_store2 = std::make_shared<Store>(2);

  raft::NodeId node_id0(0);
  raft::NodeId node_id1(1);
  raft::NodeId node_id2(2);

  ms request_timeout(10);

  TRaft r0(
    std::make_unique<Adaptor>(kv_store0),
    std::make_unique<raft::LedgerStubProxy>(node_id0),
    std::make_shared<raft::ChannelStubProxy>(),
    node_id0,
    request_timeout,
    ms(20));
  TRaft r1(
    std::make_unique<Adaptor>(kv_store1),
    std::make_unique<raft::LedgerStubProxy>(node_id1),
    std::make_shared<raft::ChannelStubProxy>(),
    node_id1,
    request_timeout,
    ms(100));
  TRaft r2(
    std::make_unique<Adaptor>(kv_store2),
    std::make_unique<raft::LedgerStubProxy>(node_id2),
    std::make_shared<raft::ChannelStubProxy>(),
    node_id2,
    request_timeout,
    ms(50));

  std::unordered_set<raft::NodeId> config = {node_id0, node_id1, node_id2};
  r0.add_configuration(0, config);
  r1.add_configuration(0, config);
  r2.add_configuration(0, config);

  map<raft::NodeId, TRaft*> nodes;
  nodes[node_id0] = &r0;
  nodes[node_id1] = &r1;
  nodes[node_id2] = &r2;

  r0.periodic(std::chrono::milliseconds(200));

  INFO("Send request_votes to other nodes");
  REQUIRE(2 == dispatch_all(nodes, r0.channels->sent_request_vote));

  INFO("Send request_vote_reponses back");
  REQUIRE(1 == dispatch_all(nodes, r1.channels->sent_request_vote_response));
  REQUIRE(1 == dispatch_all(nodes, r2.channels->sent_request_vote_response));

  INFO("Send empty append_entries to other nodes");
  REQUIRE(2 == dispatch_all(nodes, r0.channels->sent_append_entries));

  INFO("Send append_entries_reponses back");
  REQUIRE(
    1 ==
    dispatch_all_and_check(
      nodes, r1.channels->sent_append_entries_response, [](const auto& msg) {
        REQUIRE(msg.last_log_idx == 0);
        REQUIRE(msg.success);
      }));
  REQUIRE(
    1 ==
    dispatch_all_and_check(
      nodes, r2.channels->sent_append_entries_response, [](const auto& msg) {
        REQUIRE(msg.last_log_idx == 0);
        REQUIRE(msg.success);
      }));

  INFO("There ought to be no messages pending anywhere now");
  REQUIRE(r0.channels->sent_msg_count() == 0);
  REQUIRE(r1.channels->sent_msg_count() == 0);
  REQUIRE(r2.channels->sent_msg_count() == 0);

  INFO("Try to replicate on a follower, and fail");
  REQUIRE_FALSE(r1.replicate({{1, {1, 2, 3}, true}}));

  INFO("Tell the leader to replicate a message");
  std::vector<uint8_t> entry = {1, 2, 3};
  REQUIRE(r0.replicate({{1, entry, true}}));
  REQUIRE(r0.ledger->ledger.size() == 1);
  REQUIRE(*r0.ledger->ledger.front() == entry);
  INFO("The other nodes are not told about this yet");
  REQUIRE(r0.channels->sent_msg_count() == 0);

  r0.periodic(ms(10));

  INFO("Now the other nodes are sent append_entries");
  REQUIRE(
    2 ==
    dispatch_all_and_check(
      nodes, r0.channels->sent_append_entries, [](const auto& msg) {
        REQUIRE(msg.idx == 1);
        REQUIRE(msg.term == 1);
        REQUIRE(msg.prev_idx == 0);
        REQUIRE(msg.prev_term == 0);
        REQUIRE(msg.leader_commit_idx == 0);
      }));

  INFO("Which they acknowledge correctly");
  REQUIRE(
    1 ==
    dispatch_all_and_check(
      nodes, r1.channels->sent_append_entries_response, [](const auto& msg) {
        REQUIRE(msg.last_log_idx == 1);
        REQUIRE(msg.success);
      }));
  REQUIRE(
    1 ==
    dispatch_all_and_check(
      nodes, r2.channels->sent_append_entries_response, [](const auto& msg) {
        REQUIRE(msg.last_log_idx == 1);
        REQUIRE(msg.success);
      }));
}

TEST_CASE("Multiple nodes, late join" * doctest::test_suite("multiple"))
{
  auto kv_store0 = std::make_shared<Store>(0);
  auto kv_store1 = std::make_shared<Store>(1);
  auto kv_store2 = std::make_shared<Store>(2);

  raft::NodeId node_id0(0);
  raft::NodeId node_id1(1);
  raft::NodeId node_id2(2);

  ms request_timeout(10);

  TRaft r0(
    std::make_unique<Adaptor>(kv_store0),
    std::make_unique<raft::LedgerStubProxy>(node_id0),
    std::make_shared<raft::ChannelStubProxy>(),
    node_id0,
    request_timeout,
    ms(20));
  TRaft r1(
    std::make_unique<Adaptor>(kv_store1),
    std::make_unique<raft::LedgerStubProxy>(node_id1),
    std::make_shared<raft::ChannelStubProxy>(),
    node_id1,
    request_timeout,
    ms(100));
  TRaft r2(
    std::make_unique<Adaptor>(kv_store2),
    std::make_unique<raft::LedgerStubProxy>(node_id2),
    std::make_shared<raft::ChannelStubProxy>(),
    node_id2,
    request_timeout,
    ms(50));

  std::unordered_set<raft::NodeId> config0 = {node_id0, node_id1};
  r0.add_configuration(0, config0);
  r1.add_configuration(0, config0);

  map<raft::NodeId, TRaft*> nodes;
  nodes[node_id0] = &r0;
  nodes[node_id1] = &r1;

  r0.periodic(std::chrono::milliseconds(200));

  REQUIRE(1 == dispatch_all(nodes, r0.channels->sent_request_vote));
  REQUIRE(1 == dispatch_all(nodes, r1.channels->sent_request_vote_response));
  REQUIRE(1 == dispatch_all(nodes, r0.channels->sent_append_entries));

  REQUIRE(
    1 ==
    dispatch_all_and_check(
      nodes, r1.channels->sent_append_entries_response, [](const auto& msg) {
        REQUIRE(msg.last_log_idx == 0);
        REQUIRE(msg.success);
      }));

  REQUIRE(r0.channels->sent_msg_count() == 0);
  REQUIRE(r1.channels->sent_msg_count() == 0);

  REQUIRE(r0.replicate({{1, {1, 2, 3}, true}}));
  r0.periodic(ms(10));

  REQUIRE(
    1 ==
    dispatch_all_and_check(
      nodes, r0.channels->sent_append_entries, [](const auto& msg) {
        REQUIRE(msg.idx == 1);
        REQUIRE(msg.term == 1);
        REQUIRE(msg.prev_idx == 0);
        REQUIRE(msg.prev_term == 0);
        REQUIRE(msg.leader_commit_idx == 0);
      }));

  REQUIRE(
    1 ==
    dispatch_all_and_check(
      nodes, r1.channels->sent_append_entries_response, [](const auto& msg) {
        REQUIRE(msg.last_log_idx == 1);
        REQUIRE(msg.success);
      }));

  INFO("Node 2 joins the ensemble");

  std::unordered_set<raft::NodeId> config1 = {node_id0, node_id1, node_id2};
  r0.add_configuration(1, config1);
  r1.add_configuration(1, config1);
  r2.add_configuration(1, config1);

  nodes[node_id2] = &r2;

  INFO("Node 0 sends Node 2 what it's missed by joining late");
  REQUIRE(r2.channels->sent_msg_count() == 0);
  REQUIRE(r1.channels->sent_msg_count() == 0);

  REQUIRE(
    1 ==
    dispatch_all_and_check(
      nodes, r0.channels->sent_append_entries, [](const auto& msg) {
        REQUIRE(msg.idx == 1);
        REQUIRE(msg.term == 1);
        REQUIRE(msg.prev_idx == 1);
        REQUIRE(msg.prev_term == 1);
        REQUIRE(msg.leader_commit_idx == 1);
      }));
}

TEST_CASE("Recv append entries logic" * doctest::test_suite("multiple"))
{
  auto kv_store0 = std::make_shared<Store>(0);
  auto kv_store1 = std::make_shared<Store>(1);

  raft::NodeId node_id0(0);
  raft::NodeId node_id1(1);

  ms request_timeout(10);

  TRaft r0(
    std::make_unique<Adaptor>(kv_store0),
    std::make_unique<raft::LedgerStubProxy>(node_id0),
    std::make_shared<raft::ChannelStubProxy>(),
    node_id0,
    request_timeout,
    ms(20));
  TRaft r1(
    std::make_unique<Adaptor>(kv_store1),
    std::make_unique<raft::LedgerStubProxy>(node_id1),
    std::make_shared<raft::ChannelStubProxy>(),
    node_id1,
    request_timeout,
    ms(100));

  std::unordered_set<raft::NodeId> config0 = {node_id0, node_id1};
  r0.add_configuration(0, config0);
  r1.add_configuration(0, config0);

  map<raft::NodeId, TRaft*> nodes;
  nodes[node_id0] = &r0;
  nodes[node_id1] = &r1;

  r0.periodic(std::chrono::milliseconds(200));

  INFO("Initial election");
  {
    REQUIRE(1 == dispatch_all(nodes, r0.channels->sent_request_vote));
    REQUIRE(1 == dispatch_all(nodes, r1.channels->sent_request_vote_response));

    REQUIRE(r0.is_leader());
    REQUIRE(r0.channels->sent_append_entries.size() == 1);
    REQUIRE(1 == dispatch_all(nodes, r0.channels->sent_append_entries));
    REQUIRE(r0.channels->sent_append_entries.size() == 0);
  }

  raft::AppendEntries ae_idx_2; // To save for later use

  INFO("Replicate two entries");
  {
    std::vector<uint8_t> first_entry = {1, 1, 1};
    std::vector<uint8_t> second_entry = {2, 2, 2};
    REQUIRE(r0.replicate({{1, first_entry, true}}));
    REQUIRE(r0.replicate({{2, second_entry, true}}));
    REQUIRE(r0.ledger->ledger.size() == 2);
    r0.periodic(ms(10));
    REQUIRE(r0.channels->sent_append_entries.size() == 1);

    // Receive append entries (idx: 2, prev_idx: 0)
    ae_idx_2 = r0.channels->sent_append_entries.front().second;
    r1.recv_message(reinterpret_cast<uint8_t*>(&ae_idx_2), sizeof(ae_idx_2));
    REQUIRE(r1.ledger->ledger.size() == 2);
  }

  INFO("Receiving same append entries has no effect");
  {
    REQUIRE(1 == dispatch_all(nodes, r0.channels->sent_append_entries));
    REQUIRE(r1.ledger->ledger.size() == 2);
  }

  INFO("Replicate one more entry but send AE all entries");
  {
    std::vector<uint8_t> third_entry = {3, 3, 3};
    REQUIRE(r0.replicate({{3, third_entry, true}}));
    REQUIRE(r0.ledger->ledger.size() == 3);

    // Simulate that the append entries was not deserialised successfully
    // This ensures that r0 re-sends an AE with prev_idx = 0 next time
    auto aer = r1.channels->sent_append_entries_response.front().second;
    r1.channels->sent_append_entries_response.pop_front();
    aer.success = false;
    r0.recv_message(reinterpret_cast<uint8_t*>(&aer), sizeof(aer));
    REQUIRE(r0.channels->sent_append_entries.size() == 1);

    // Only the third entry is deserialised
    r1.ledger->reset_skip_count();
    REQUIRE(1 == dispatch_all(nodes, r0.channels->sent_append_entries));
    REQUIRE(r0.ledger->ledger.size() == 3);
    REQUIRE(r1.ledger->skip_count == 2);
    r1.ledger->reset_skip_count();
  }

  INFO("Receiving stale append entries has no effect");
  {
    r1.recv_message(reinterpret_cast<uint8_t*>(&ae_idx_2), sizeof(ae_idx_2));
    REQUIRE(r1.ledger->ledger.size() == 3);
  }

  INFO("Replicate one more entry (normal behaviour)");
  {
    std::vector<uint8_t> fourth_entry = {4, 4, 4};
    REQUIRE(r0.replicate({{4, fourth_entry, true}}));
    REQUIRE(r0.ledger->ledger.size() == 4);
    r0.periodic(ms(10));
    REQUIRE(r0.channels->sent_append_entries.size() == 1);
    REQUIRE(1 == dispatch_all(nodes, r0.channels->sent_append_entries));
    REQUIRE(r1.ledger->ledger.size() == 4);
  }

  INFO("Replicate one more entry without AE response from previous entry");
  {
    std::vector<uint8_t> fifth_entry = {5, 5, 5};
    REQUIRE(r0.replicate({{5, fifth_entry, true}}));
    REQUIRE(r0.ledger->ledger.size() == 5);
    r0.periodic(ms(10));
    REQUIRE(r0.channels->sent_append_entries.size() == 1);
    r0.channels->sent_append_entries.pop_front();

    // Simulate that the append entries was not deserialised successfully
    // This ensures that r0 re-sends an AE with prev_idx = 3 next time
    auto aer = r1.channels->sent_append_entries_response.front().second;
    r1.channels->sent_append_entries_response.pop_front();
    aer.success = false;
    r0.recv_message(reinterpret_cast<uint8_t*>(&aer), sizeof(aer));
    REQUIRE(r0.channels->sent_append_entries.size() == 1);

    // Receive append entries (idx: 5, prev_idx: 3)
    r1.ledger->reset_skip_count();
    REQUIRE(1 == dispatch_all(nodes, r0.channels->sent_append_entries));
    REQUIRE(r1.ledger->ledger.size() == 5);
    REQUIRE(r1.ledger->skip_count == 2);
  }
}
