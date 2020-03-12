// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "consensus/raft/raft.h"
#include "ds/logger.h"
#include "logging_stub.h"

#define DOCTEST_CONFIG_NO_SHORT_MACRO_NAMES

#include <chrono>
#include <doctest/doctest.h>
#include <string>

using namespace std;

using ms = std::chrono::milliseconds;
using TRaft = raft::Raft<raft::LedgerStubProxy, raft::ChannelStubProxy>;
using Store = raft::LoggingStubStore;
using StoreSig = raft::LoggingStubStoreSig;
using Adaptor = raft::Adaptor<Store, kv::DeserialiseSuccess>;

DOCTEST_TEST_CASE("Single node startup" * doctest::test_suite("single"))
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

  DOCTEST_INFO("DOCTEST_REQUIRE Initial State");

  DOCTEST_REQUIRE(!r0.is_leader());
  DOCTEST_REQUIRE(r0.leader() == raft::NoNode);
  DOCTEST_REQUIRE(r0.get_term() == 0);
  DOCTEST_REQUIRE(r0.get_commit_idx() == 0);

  DOCTEST_INFO(
    "In the absence of other nodes, become leader after election timeout");

  r0.periodic(ms(0));
  DOCTEST_REQUIRE(!r0.is_leader());

  r0.periodic(election_timeout * 2);
  DOCTEST_REQUIRE(r0.is_leader());
  DOCTEST_REQUIRE(r0.leader() == node_id);
}

DOCTEST_TEST_CASE("Single node commit" * doctest::test_suite("single"))
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

  DOCTEST_INFO("Become leader after election timeout");

  r0.periodic(election_timeout * 2);
  DOCTEST_REQUIRE(r0.is_leader());

  DOCTEST_INFO("Observe that data is committed on replicate immediately");

  for (size_t i = 1; i <= 5; ++i)
  {
    auto entry = std::make_shared<std::vector<uint8_t>>();
    entry->push_back(1);
    entry->push_back(2);
    entry->push_back(3);

    r0.replicate(kv::BatchVector{{i, entry, true}});
    DOCTEST_REQUIRE(r0.get_last_idx() == i);
    DOCTEST_REQUIRE(r0.get_commit_idx() == i);
  }
}

DOCTEST_TEST_CASE(
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

  DOCTEST_INFO("Node 0 exceeds its election timeout and starts an election");

  r0.periodic(std::chrono::milliseconds(200));
  DOCTEST_REQUIRE(r0.channels->sent_request_vote.size() == 2);
  r0.channels->sent_request_vote.sort(by_0);

  DOCTEST_INFO("Node 1 receives the request");

  auto rv = r0.channels->sent_request_vote.front();
  r0.channels->sent_request_vote.pop_front();
  DOCTEST_REQUIRE(get<0>(rv) == node_id1);
  auto rvc = get<1>(rv);
  DOCTEST_REQUIRE(rvc.term == 1);
  DOCTEST_REQUIRE(rvc.last_commit_idx == 0);
  DOCTEST_REQUIRE(rvc.last_commit_term == 0);

  r1.recv_message(reinterpret_cast<uint8_t*>(&rvc), sizeof(rvc));

  DOCTEST_INFO("Node 2 receives the request");

  rv = r0.channels->sent_request_vote.front();
  r0.channels->sent_request_vote.pop_front();
  DOCTEST_REQUIRE(get<0>(rv) == node_id2);
  rvc = get<1>(rv);
  DOCTEST_REQUIRE(rvc.term == 1);
  DOCTEST_REQUIRE(rvc.last_commit_idx == 0);
  DOCTEST_REQUIRE(rvc.last_commit_term == 0);

  r2.recv_message(reinterpret_cast<uint8_t*>(&rvc), sizeof(rvc));

  DOCTEST_INFO("Node 1 votes for Node 0");

  DOCTEST_REQUIRE(r1.channels->sent_request_vote_response.size() == 1);
  auto rvr = r1.channels->sent_request_vote_response.front();
  r1.channels->sent_request_vote_response.pop_front();

  DOCTEST_REQUIRE(get<0>(rvr) == node_id0);
  auto rvrc = get<1>(rvr);
  DOCTEST_REQUIRE(rvrc.term == 1);
  DOCTEST_REQUIRE(rvrc.vote_granted);

  r0.recv_message(reinterpret_cast<uint8_t*>(&rvrc), sizeof(rvrc));

  DOCTEST_INFO("Node 2 votes for Node 0");

  DOCTEST_REQUIRE(r2.channels->sent_request_vote_response.size() == 1);
  rvr = r2.channels->sent_request_vote_response.front();
  r2.channels->sent_request_vote_response.pop_front();

  DOCTEST_REQUIRE(get<0>(rvr) == node_id0);
  rvrc = get<1>(rvr);
  DOCTEST_REQUIRE(rvrc.term == 1);
  DOCTEST_REQUIRE(rvrc.vote_granted);

  r0.recv_message(reinterpret_cast<uint8_t*>(&rvrc), sizeof(rvrc));

  DOCTEST_INFO(
    "Node 0 is now leader, and sends empty append entries to other nodes");

  DOCTEST_REQUIRE(r0.is_leader());
  DOCTEST_REQUIRE(r0.channels->sent_append_entries.size() == 2);
  r0.channels->sent_append_entries.sort(by_0);

  auto ae = r0.channels->sent_append_entries.front();
  r0.channels->sent_append_entries.pop_front();
  DOCTEST_REQUIRE(get<0>(ae) == node_id1);
  auto aec = get<1>(ae);
  DOCTEST_REQUIRE(aec.idx == 0);
  DOCTEST_REQUIRE(aec.term == 1);
  DOCTEST_REQUIRE(aec.prev_idx == 0);
  DOCTEST_REQUIRE(aec.prev_term == 0);
  DOCTEST_REQUIRE(aec.leader_commit_idx == 0);

  ae = r0.channels->sent_append_entries.front();
  r0.channels->sent_append_entries.pop_front();
  DOCTEST_REQUIRE(get<0>(ae) == node_id2);
  aec = get<1>(ae);
  DOCTEST_REQUIRE(aec.idx == 0);
  DOCTEST_REQUIRE(aec.term == 1);
  DOCTEST_REQUIRE(aec.prev_idx == 0);
  DOCTEST_REQUIRE(aec.prev_term == 0);
  DOCTEST_REQUIRE(aec.leader_commit_idx == 0);
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
static size_t dispatch_all_and_DOCTEST_CHECK(
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

DOCTEST_TEST_CASE(
  "Multiple nodes append entries" * doctest::test_suite("multiple"))
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

  DOCTEST_INFO("Send request_votes to other nodes");
  DOCTEST_REQUIRE(2 == dispatch_all(nodes, r0.channels->sent_request_vote));

  DOCTEST_INFO("Send request_vote_reponses back");
  DOCTEST_REQUIRE(
    1 == dispatch_all(nodes, r1.channels->sent_request_vote_response));
  DOCTEST_REQUIRE(
    1 == dispatch_all(nodes, r2.channels->sent_request_vote_response));

  DOCTEST_INFO("Send empty append_entries to other nodes");
  DOCTEST_REQUIRE(2 == dispatch_all(nodes, r0.channels->sent_append_entries));

  DOCTEST_INFO("Send append_entries_reponses back");
  DOCTEST_REQUIRE(
    1 ==
    dispatch_all_and_DOCTEST_CHECK(
      nodes, r1.channels->sent_append_entries_response, [](const auto& msg) {
        DOCTEST_REQUIRE(msg.last_log_idx == 0);
        DOCTEST_REQUIRE(msg.success);
      }));
  DOCTEST_REQUIRE(
    1 ==
    dispatch_all_and_DOCTEST_CHECK(
      nodes, r2.channels->sent_append_entries_response, [](const auto& msg) {
        DOCTEST_REQUIRE(msg.last_log_idx == 0);
        DOCTEST_REQUIRE(msg.success);
      }));

  DOCTEST_INFO("There ought to be no messages pending anywhere now");
  DOCTEST_REQUIRE(r0.channels->sent_msg_count() == 0);
  DOCTEST_REQUIRE(r1.channels->sent_msg_count() == 0);
  DOCTEST_REQUIRE(r2.channels->sent_msg_count() == 0);

  DOCTEST_INFO("Try to replicate on a follower, and fail");
  std::vector<uint8_t> entry = {1, 2, 3};
  auto data = std::make_shared<std::vector<uint8_t>>(entry);
  DOCTEST_REQUIRE_FALSE(r1.replicate(kv::BatchVector{{1, data, true}}));

  DOCTEST_INFO("Tell the leader to replicate a message");
  DOCTEST_REQUIRE(r0.replicate(kv::BatchVector{{1, data, true}}));
  DOCTEST_REQUIRE(r0.ledger->ledger.size() == 1);
  DOCTEST_REQUIRE(*r0.ledger->ledger.front() == entry);
  DOCTEST_INFO("The other nodes are not told about this yet");
  DOCTEST_REQUIRE(r0.channels->sent_msg_count() == 0);

  r0.periodic(ms(10));

  DOCTEST_INFO("Now the other nodes are sent append_entries");
  DOCTEST_REQUIRE(
    2 ==
    dispatch_all_and_DOCTEST_CHECK(
      nodes, r0.channels->sent_append_entries, [](const auto& msg) {
        DOCTEST_REQUIRE(msg.idx == 1);
        DOCTEST_REQUIRE(msg.term == 1);
        DOCTEST_REQUIRE(msg.prev_idx == 0);
        DOCTEST_REQUIRE(msg.prev_term == 0);
        DOCTEST_REQUIRE(msg.leader_commit_idx == 0);
      }));

  DOCTEST_INFO("Which they acknowledge correctly");
  DOCTEST_REQUIRE(
    1 ==
    dispatch_all_and_DOCTEST_CHECK(
      nodes, r1.channels->sent_append_entries_response, [](const auto& msg) {
        DOCTEST_REQUIRE(msg.last_log_idx == 1);
        DOCTEST_REQUIRE(msg.success);
      }));
  DOCTEST_REQUIRE(
    1 ==
    dispatch_all_and_DOCTEST_CHECK(
      nodes, r2.channels->sent_append_entries_response, [](const auto& msg) {
        DOCTEST_REQUIRE(msg.last_log_idx == 1);
        DOCTEST_REQUIRE(msg.success);
      }));
}

DOCTEST_TEST_CASE("Multiple nodes late join" * doctest::test_suite("multiple"))
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

  DOCTEST_REQUIRE(1 == dispatch_all(nodes, r0.channels->sent_request_vote));
  DOCTEST_REQUIRE(
    1 == dispatch_all(nodes, r1.channels->sent_request_vote_response));
  DOCTEST_REQUIRE(1 == dispatch_all(nodes, r0.channels->sent_append_entries));

  DOCTEST_REQUIRE(
    1 ==
    dispatch_all_and_DOCTEST_CHECK(
      nodes, r1.channels->sent_append_entries_response, [](const auto& msg) {
        DOCTEST_REQUIRE(msg.last_log_idx == 0);
        DOCTEST_REQUIRE(msg.success);
      }));

  DOCTEST_REQUIRE(r0.channels->sent_msg_count() == 0);
  DOCTEST_REQUIRE(r1.channels->sent_msg_count() == 0);

  std::vector<uint8_t> first_entry = {1, 2, 3};
  auto data = std::make_shared<std::vector<uint8_t>>(first_entry);
  DOCTEST_REQUIRE(r0.replicate(kv::BatchVector{{1, data, true}}));
  r0.periodic(ms(10));

  DOCTEST_REQUIRE(
    1 ==
    dispatch_all_and_DOCTEST_CHECK(
      nodes, r0.channels->sent_append_entries, [](const auto& msg) {
        DOCTEST_REQUIRE(msg.idx == 1);
        DOCTEST_REQUIRE(msg.term == 1);
        DOCTEST_REQUIRE(msg.prev_idx == 0);
        DOCTEST_REQUIRE(msg.prev_term == 0);
        DOCTEST_REQUIRE(msg.leader_commit_idx == 0);
      }));

  DOCTEST_REQUIRE(
    1 ==
    dispatch_all_and_DOCTEST_CHECK(
      nodes, r1.channels->sent_append_entries_response, [](const auto& msg) {
        DOCTEST_REQUIRE(msg.last_log_idx == 1);
        DOCTEST_REQUIRE(msg.success);
      }));

  DOCTEST_INFO("Node 2 joins the ensemble");

  std::unordered_set<raft::NodeId> config1 = {node_id0, node_id1, node_id2};
  r0.add_configuration(1, config1);
  r1.add_configuration(1, config1);
  r2.add_configuration(1, config1);

  nodes[node_id2] = &r2;

  DOCTEST_INFO("Node 0 sends Node 2 what it's missed by joining late");
  DOCTEST_REQUIRE(r2.channels->sent_msg_count() == 0);
  DOCTEST_REQUIRE(r1.channels->sent_msg_count() == 0);

  DOCTEST_REQUIRE(
    1 ==
    dispatch_all_and_DOCTEST_CHECK(
      nodes, r0.channels->sent_append_entries, [](const auto& msg) {
        DOCTEST_REQUIRE(msg.idx == 1);
        DOCTEST_REQUIRE(msg.term == 1);
        DOCTEST_REQUIRE(msg.prev_idx == 1);
        DOCTEST_REQUIRE(msg.prev_term == 1);
        DOCTEST_REQUIRE(msg.leader_commit_idx == 1);
      }));
}

DOCTEST_TEST_CASE("Recv append entries logic" * doctest::test_suite("multiple"))
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

  DOCTEST_INFO("Initial election");
  {
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, r0.channels->sent_request_vote));
    DOCTEST_REQUIRE(
      1 == dispatch_all(nodes, r1.channels->sent_request_vote_response));

    DOCTEST_REQUIRE(r0.is_leader());
    DOCTEST_REQUIRE(r0.channels->sent_append_entries.size() == 1);
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, r0.channels->sent_append_entries));
    DOCTEST_REQUIRE(r0.channels->sent_append_entries.size() == 0);
  }

  raft::AppendEntries ae_idx_2; // To save for later use

  DOCTEST_INFO("Replicate two entries");
  {
    std::vector<uint8_t> first_entry = {1, 1, 1};
    auto data_1 = std::make_shared<std::vector<uint8_t>>(first_entry);
    std::vector<uint8_t> second_entry = {2, 2, 2};
    auto data_2 = std::make_shared<std::vector<uint8_t>>(second_entry);

    DOCTEST_REQUIRE(r0.replicate(kv::BatchVector{{1, data_1, true}}));
    DOCTEST_REQUIRE(r0.replicate(kv::BatchVector{{2, data_2, true}}));
    DOCTEST_REQUIRE(r0.ledger->ledger.size() == 2);
    r0.periodic(ms(10));
    DOCTEST_REQUIRE(r0.channels->sent_append_entries.size() == 1);

    // Receive append entries (idx: 2, prev_idx: 0)
    ae_idx_2 = r0.channels->sent_append_entries.front().second;
    r1.recv_message(reinterpret_cast<uint8_t*>(&ae_idx_2), sizeof(ae_idx_2));
    DOCTEST_REQUIRE(r1.ledger->ledger.size() == 2);
  }

  DOCTEST_INFO("Receiving same append entries has no effect");
  {
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, r0.channels->sent_append_entries));
    DOCTEST_REQUIRE(r1.ledger->ledger.size() == 2);
  }

  DOCTEST_INFO("Replicate one more entry but send AE all entries");
  {
    std::vector<uint8_t> third_entry = {3, 3, 3};
    auto data = std::make_shared<std::vector<uint8_t>>(third_entry);
    DOCTEST_REQUIRE(r0.replicate(kv::BatchVector{{3, data, true}}));
    DOCTEST_REQUIRE(r0.ledger->ledger.size() == 3);

    // Simulate that the append entries was not deserialised successfully
    // This ensures that r0 re-sends an AE with prev_idx = 0 next time
    auto aer = r1.channels->sent_append_entries_response.front().second;
    r1.channels->sent_append_entries_response.pop_front();
    aer.success = false;
    r0.recv_message(reinterpret_cast<uint8_t*>(&aer), sizeof(aer));
    DOCTEST_REQUIRE(r0.channels->sent_append_entries.size() == 1);

    // Only the third entry is deserialised
    r1.ledger->reset_skip_count();
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, r0.channels->sent_append_entries));
    DOCTEST_REQUIRE(r0.ledger->ledger.size() == 3);
    DOCTEST_REQUIRE(r1.ledger->skip_count == 2);
    r1.ledger->reset_skip_count();
  }

  DOCTEST_INFO("Receiving stale append entries has no effect");
  {
    r1.recv_message(reinterpret_cast<uint8_t*>(&ae_idx_2), sizeof(ae_idx_2));
    DOCTEST_REQUIRE(r1.ledger->ledger.size() == 3);
  }

  DOCTEST_INFO("Replicate one more entry (normal behaviour)");
  {
    std::vector<uint8_t> fourth_entry = {4, 4, 4};
    auto data = std::make_shared<std::vector<uint8_t>>(fourth_entry);
    DOCTEST_REQUIRE(r0.replicate(kv::BatchVector{{4, data, true}}));
    DOCTEST_REQUIRE(r0.ledger->ledger.size() == 4);
    r0.periodic(ms(10));
    DOCTEST_REQUIRE(r0.channels->sent_append_entries.size() == 1);
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, r0.channels->sent_append_entries));
    DOCTEST_REQUIRE(r1.ledger->ledger.size() == 4);
  }

  DOCTEST_INFO(
    "Replicate one more entry without AE response from previous entry");
  {
    std::vector<uint8_t> fifth_entry = {5, 5, 5};
    auto data = std::make_shared<std::vector<uint8_t>>(fifth_entry);
    DOCTEST_REQUIRE(r0.replicate(kv::BatchVector{{5, data, true}}));
    DOCTEST_REQUIRE(r0.ledger->ledger.size() == 5);
    r0.periodic(ms(10));
    DOCTEST_REQUIRE(r0.channels->sent_append_entries.size() == 1);
    r0.channels->sent_append_entries.pop_front();

    // Simulate that the append entries was not deserialised successfully
    // This ensures that r0 re-sends an AE with prev_idx = 3 next time
    auto aer = r1.channels->sent_append_entries_response.front().second;
    r1.channels->sent_append_entries_response.pop_front();
    aer.success = false;
    r0.recv_message(reinterpret_cast<uint8_t*>(&aer), sizeof(aer));
    DOCTEST_REQUIRE(r0.channels->sent_append_entries.size() == 1);

    // Receive append entries (idx: 5, prev_idx: 3)
    r1.ledger->reset_skip_count();
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, r0.channels->sent_append_entries));
    DOCTEST_REQUIRE(r1.ledger->ledger.size() == 5);
    DOCTEST_REQUIRE(r1.ledger->skip_count == 2);
  }
}

DOCTEST_TEST_CASE("Exceed append entries limit")
{
  logger::config::level() = logger::INFO;

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

  DOCTEST_REQUIRE(1 == dispatch_all(nodes, r0.channels->sent_request_vote));
  DOCTEST_REQUIRE(
    1 == dispatch_all(nodes, r1.channels->sent_request_vote_response));
  DOCTEST_REQUIRE(1 == dispatch_all(nodes, r0.channels->sent_append_entries));

  DOCTEST_REQUIRE(
    1 ==
    dispatch_all_and_DOCTEST_CHECK(
      nodes, r1.channels->sent_append_entries_response, [](const auto& msg) {
        DOCTEST_REQUIRE(msg.last_log_idx == 0);
        DOCTEST_REQUIRE(msg.success);
      }));

  DOCTEST_REQUIRE(r0.channels->sent_msg_count() == 0);
  DOCTEST_REQUIRE(r1.channels->sent_msg_count() == 0);

  // large entries of size (append_entries_size_limit / 2), so 2nd and 4th entry
  // will exceed append entries limit size which means that 2nd and 4th entries
  // will trigger send_append_entries()
  auto data =
    std::make_shared<::vector<uint8_t>>((r0.append_entries_size_limit / 2), 1);
  // I want to get ~500 messages sent over 1mill entries
  auto individual_entries = 1000000;
  auto num_small_entries_sent = 500;
  auto num_big_entries = 4;

  // send_append_entries() triggered or not
  bool msg_response = false;

  for (size_t i = 1; i <= num_big_entries; ++i)
  {
    DOCTEST_REQUIRE(r0.replicate(kv::BatchVector{{i, data, true}}));
    DOCTEST_REQUIRE(
      msg_response ==
      dispatch_all_and_DOCTEST_CHECK(
        nodes, r0.channels->sent_append_entries, [&i](const auto& msg) {
          DOCTEST_REQUIRE(msg.idx == i);
          DOCTEST_REQUIRE(msg.term == 1);
          DOCTEST_REQUIRE(msg.prev_idx == ((i <= 2) ? 0 : 2));
        }));
    msg_response = !msg_response;
  }

  int data_size = (num_small_entries_sent * r0.append_entries_size_limit) /
    (individual_entries - num_big_entries);
  auto smaller_data = std::make_shared<std::vector<uint8_t>>(data_size, 1);

  for (size_t i = num_big_entries + 1; i <= individual_entries; ++i)
  {
    DOCTEST_REQUIRE(r0.replicate(kv::BatchVector{{i, smaller_data, true}}));
    dispatch_all(nodes, r0.channels->sent_append_entries);
  }

  DOCTEST_INFO("Node 2 joins the ensemble");

  std::unordered_set<raft::NodeId> config1 = {node_id0, node_id1, node_id2};
  r0.add_configuration(1, config1);
  r1.add_configuration(1, config1);
  r2.add_configuration(1, config1);

  nodes[node_id2] = &r2;

  DOCTEST_INFO("Node 0 sends Node 2 what it's missed by joining late");
  DOCTEST_REQUIRE(r2.channels->sent_msg_count() == 0);

  DOCTEST_REQUIRE(
    1 ==
    dispatch_all_and_DOCTEST_CHECK(
      nodes,
      r0.channels->sent_append_entries,
      [&individual_entries](const auto& msg) {
        DOCTEST_REQUIRE(msg.idx == individual_entries);
        DOCTEST_REQUIRE(msg.term == 1);
        DOCTEST_REQUIRE(msg.prev_idx == individual_entries);
      }));

  DOCTEST_REQUIRE(r2.ledger->ledger.size() == 0);
  DOCTEST_REQUIRE(r0.ledger->ledger.size() == individual_entries);

  DOCTEST_INFO("Node 2 asks for Node 0 to send all the data up to now");
  DOCTEST_REQUIRE(r2.channels->sent_append_entries_response.size() == 1);
  auto aer = r2.channels->sent_append_entries_response.front().second;
  r2.channels->sent_append_entries_response.pop_front();
  r0.recv_message(reinterpret_cast<uint8_t*>(&aer), sizeof(aer));

  DOCTEST_REQUIRE(
    (r0.channels->sent_append_entries.size() > num_small_entries_sent &&
     r0.channels->sent_append_entries.size() <=
       num_small_entries_sent + num_big_entries));
  auto sent_entries = dispatch_all(nodes, r0.channels->sent_append_entries);
  DOCTEST_REQUIRE(
    (sent_entries > num_small_entries_sent &&
     sent_entries <= num_small_entries_sent + num_big_entries));
  DOCTEST_REQUIRE(r2.ledger->ledger.size() == individual_entries);
}

// Reproduces issue described here: https://github.com/microsoft/CCF/issues/521
// Once this is fixed test will need to be modified since right now it
// DOCTEST_CHECKs that the issue stands
DOCTEST_TEST_CASE(
  "Primary gets invalidated if it compacts right before a term change that it "
  "doesn't participate in")
{
  auto kv_store0 = std::make_shared<StoreSig>(0);
  auto kv_store1 = std::make_shared<StoreSig>(1);
  auto kv_store2 = std::make_shared<StoreSig>(2);

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

  std::unordered_set<raft::NodeId> config0 = {node_id0, node_id1, node_id2};
  r0.add_configuration(0, config0);
  r1.add_configuration(0, config0);
  r2.add_configuration(0, config0);

  map<raft::NodeId, TRaft*> nodes;
  nodes[node_id0] = &r0;
  nodes[node_id1] = &r1;
  nodes[node_id2] = &r2;

  r0.periodic(std::chrono::milliseconds(200));

  DOCTEST_INFO("Initial election for Node 0");
  {
    DOCTEST_REQUIRE(2 == dispatch_all(nodes, r0.channels->sent_request_vote));
    DOCTEST_REQUIRE(
      1 == dispatch_all(nodes, r1.channels->sent_request_vote_response));

    DOCTEST_REQUIRE(r0.is_leader());
    DOCTEST_REQUIRE(r0.channels->sent_append_entries.size() == 2);
    DOCTEST_REQUIRE(2 == dispatch_all(nodes, r0.channels->sent_append_entries));
    DOCTEST_REQUIRE(r0.channels->sent_append_entries.size() == 0);
  }

  r1.channels->sent_append_entries_response.clear();
  r2.channels->sent_append_entries_response.clear();

  auto first_entry = std::make_shared<std::vector<uint8_t>>();
  for (auto i = 0; i < 3; ++i)
  {
    first_entry->push_back(1);
  }
  auto second_entry = std::make_shared<std::vector<uint8_t>>();
  for (auto i = 0; i < 3; ++i)
  {
    second_entry->push_back(2);
  }

  auto third_entry = std::make_shared<std::vector<uint8_t>>();
  for (auto i = 0; i < 3; ++i)
  {
    third_entry->push_back(3);
  }

  DOCTEST_INFO("Node 0 compacts twice but Nodes 1 and 2 only once");
  {
    DOCTEST_REQUIRE(r0.replicate(kv::BatchVector{{1, first_entry, true}}));
    DOCTEST_REQUIRE(r0.ledger->ledger.size() == 1);
    r0.periodic(ms(10));
    DOCTEST_REQUIRE(r0.channels->sent_append_entries.size() == 2);

    // Nodes 1 and 2 receive append entries and respond
    DOCTEST_REQUIRE(2 == dispatch_all(nodes, r0.channels->sent_append_entries));
    DOCTEST_REQUIRE(r0.channels->sent_append_entries.size() == 0);

    DOCTEST_REQUIRE(
      1 == dispatch_all(nodes, r1.channels->sent_append_entries_response));
    DOCTEST_REQUIRE(
      1 == dispatch_all(nodes, r2.channels->sent_append_entries_response));

    DOCTEST_REQUIRE(r0.replicate(kv::BatchVector{{2, second_entry, true}}));
    DOCTEST_REQUIRE(r0.ledger->ledger.size() == 2);
    r0.periodic(ms(10));
    DOCTEST_REQUIRE(r0.channels->sent_append_entries.size() == 2);

    // Nodes 1 and 2 receive append entries and respond
    // Node 0 will compact again and be ahead of Node 1 and 2
    DOCTEST_REQUIRE(2 == dispatch_all(nodes, r0.channels->sent_append_entries));
    DOCTEST_REQUIRE(r0.channels->sent_append_entries.size() == 0);

    DOCTEST_REQUIRE(
      1 == dispatch_all(nodes, r1.channels->sent_append_entries_response));
    DOCTEST_REQUIRE(
      1 == dispatch_all(nodes, r2.channels->sent_append_entries_response));

    DOCTEST_CHECK(r0.get_term() == 1);
    DOCTEST_CHECK(r0.get_commit_idx() == 2);
    DOCTEST_CHECK(r0.get_last_idx() == 2);

    DOCTEST_CHECK(r1.get_term() == 1);
    DOCTEST_CHECK(r1.get_commit_idx() == 1);
    DOCTEST_CHECK(r1.get_last_idx() == 2);

    DOCTEST_CHECK(r2.get_term() == 1);
    DOCTEST_CHECK(r2.get_commit_idx() == 1);
    DOCTEST_CHECK(r2.get_last_idx() == 2);

    // clean up
    r2.channels->sent_request_vote_response.clear();

    DOCTEST_REQUIRE(r0.channels->sent_msg_count() == 0);
    DOCTEST_REQUIRE(r1.channels->sent_msg_count() == 0);
    DOCTEST_REQUIRE(r2.channels->sent_msg_count() == 0);
  }

  DOCTEST_INFO("Node 1 exceeds its election timeout and starts an election");
  {
    auto by_0 = [](auto const& lhs, auto const& rhs) -> bool {
      return get<0>(lhs) < get<0>(rhs);
    };

    r1.periodic(std::chrono::milliseconds(200));
    DOCTEST_REQUIRE(r1.channels->sent_request_vote.size() == 2);
    r1.channels->sent_request_vote.sort(by_0);

    DOCTEST_INFO("Node 2 receives the vote request");
    // pop for first node (node 0) so that it doesn't participate in the
    // election
    auto vote_req_from_1_to_0 = r1.channels->sent_request_vote.front();
    r1.channels->sent_request_vote.pop_front();

    DOCTEST_REQUIRE(
      1 ==
      dispatch_all_and_DOCTEST_CHECK(
        nodes, r1.channels->sent_request_vote, [](const auto& msg) {
          DOCTEST_REQUIRE(msg.term == 2);
          DOCTEST_REQUIRE(msg.last_commit_idx == 1);
          DOCTEST_REQUIRE(msg.last_commit_term == 1);
        }));

    DOCTEST_INFO("Node 2 votes for Node 1, Node 0 is suspended");
    DOCTEST_REQUIRE(
      1 ==
      dispatch_all_and_DOCTEST_CHECK(
        nodes, r2.channels->sent_request_vote_response, [](const auto& msg) {
          DOCTEST_REQUIRE(msg.term == 2);
          DOCTEST_REQUIRE(msg.vote_granted);
        }));

    DOCTEST_INFO("Node 1 is now leader");
    DOCTEST_REQUIRE(r1.is_leader());
    // pop Node 0's append entries
    r1.channels->sent_append_entries.pop_front();
    DOCTEST_REQUIRE(
      1 ==
      dispatch_all_and_DOCTEST_CHECK(
        nodes, r1.channels->sent_append_entries, [](const auto& msg) {
          DOCTEST_REQUIRE(msg.idx == 1);
          DOCTEST_REQUIRE(msg.term == 2);
          DOCTEST_REQUIRE(msg.prev_idx == 1);
          DOCTEST_REQUIRE(msg.prev_term == 1);
          DOCTEST_REQUIRE(msg.leader_commit_idx == 1);
        }));
    DOCTEST_REQUIRE(r1.channels->sent_append_entries.size() == 0);

    DOCTEST_REQUIRE(
      1 == dispatch_all(nodes, r2.channels->sent_append_entries_response));
  }

  DOCTEST_INFO(
    "Node 1 and Node 2 proceed to compact at idx 2, where Node 0 has "
    "compacted for a previous term");
  {
    DOCTEST_REQUIRE(r1.replicate(kv::BatchVector{{2, second_entry, true}}));
    DOCTEST_REQUIRE(r1.ledger->ledger.size() == 2);
    r1.periodic(ms(10));
    DOCTEST_REQUIRE(r1.channels->sent_append_entries.size() == 2);

    // Nodes 0 and 2 receive append entries and respond
    DOCTEST_REQUIRE(2 == dispatch_all(nodes, r1.channels->sent_append_entries));
    DOCTEST_REQUIRE(r1.channels->sent_append_entries.size() == 0);

    DOCTEST_REQUIRE(
      1 == dispatch_all(nodes, r2.channels->sent_append_entries_response));

    // Node 0 will not respond here since it received an append entries it can
    // not process [prev_idex (1) < commit_idx (2)]
    DOCTEST_REQUIRE(r0.channels->sent_append_entries_response.size() == 0);

    DOCTEST_INFO("Another entry from Node 1 so that Node 2 can also compact");
    DOCTEST_REQUIRE(r1.replicate(kv::BatchVector{{3, third_entry, true}}));
    DOCTEST_REQUIRE(r1.ledger->ledger.size() == 3);
    r1.periodic(ms(10));
    DOCTEST_REQUIRE(r1.channels->sent_append_entries.size() == 2);

    // Nodes 0 and 2 receive append entries
    DOCTEST_REQUIRE(2 == dispatch_all(nodes, r1.channels->sent_append_entries));
    DOCTEST_REQUIRE(r1.channels->sent_append_entries.size() == 0);

    // Node 0 will now have an ae response which will return false because
    // its log for index 2 has the wrong term (ours: 1, theirs: 2)
    DOCTEST_REQUIRE(r0.channels->sent_append_entries_response.size() == 1);
    DOCTEST_REQUIRE(
      1 ==
      dispatch_all_and_DOCTEST_CHECK(
        nodes, r0.channels->sent_append_entries_response, [](const auto& msg) {
          DOCTEST_REQUIRE(msg.last_log_idx == 2);
          DOCTEST_REQUIRE(!msg.success);
        }));

    DOCTEST_REQUIRE(r1.ledger->ledger.size() == 3);
    DOCTEST_REQUIRE(r2.ledger->ledger.size() == 3);

    DOCTEST_CHECK(r1.get_term() == 2);
    DOCTEST_CHECK(r1.get_commit_idx() == 2);
    DOCTEST_CHECK(r1.get_last_idx() == 3);

    DOCTEST_CHECK(r2.get_term() == 2);
    DOCTEST_CHECK(r2.get_commit_idx() == 2);
    DOCTEST_CHECK(r2.get_last_idx() == 3);
  }
}