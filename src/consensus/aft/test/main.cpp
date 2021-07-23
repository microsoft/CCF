// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "consensus/aft/raft.h"
#include "ds/logger.h"
#include "kv/test/stub_consensus.h"
#include "logging_stub.h"

#define DOCTEST_CONFIG_NO_SHORT_MACRO_NAMES

#include <chrono>
#include <doctest/doctest.h>
#include <string>

using namespace std;

using ms = std::chrono::milliseconds;
using TRaft =
  aft::Aft<aft::LedgerStubProxy, aft::ChannelStubProxy, aft::StubSnapshotter>;
using Store = aft::LoggingStubStore;
using Adaptor = aft::Adaptor<Store>;

threading::ThreadMessaging threading::ThreadMessaging::thread_messaging;
std::atomic<uint16_t> threading::ThreadMessaging::thread_count = 1;

std::vector<uint8_t> cert;

const auto request_timeout = ms(10);

aft::ChannelStubProxy* channel_stub_proxy(const TRaft& r)
{
  return (aft::ChannelStubProxy*)r.channels.get();
}

void receive_message(
  TRaft& sender, TRaft& receiver, std::vector<uint8_t> contents)
{
  bool should_send = true;

  {
    // If this is AppendEntries, then append the serialised ledger entries to
    // the message before transmitting
    const uint8_t* data = contents.data();
    auto size = contents.size();
    auto msg_type = serialized::peek<aft::RaftMsgType>(data, size);
    if (msg_type == aft::raft_append_entries)
    {
      // Parse the indices to be sent to the recipient.
      auto ae = *(aft::AppendEntries*)data;

      TRaft* ps = &sender;
      const auto payload_opt =
        sender.ledger->get_append_entries_payload(ae, ps);
      if (payload_opt.has_value())
      {
        contents.insert(
          contents.end(), payload_opt->begin(), payload_opt->end());
      }
      else
      {
        should_send = false;
      }
    }
  }

  if (should_send)
  {
    receiver.recv_message(sender.id(), contents.data(), contents.size());
  }
}

DOCTEST_TEST_CASE("Single node startup" * doctest::test_suite("single"))
{
  ccf::NodeId node_id = kv::test::PrimaryNodeId;
  auto kv_store = std::make_shared<Store>(node_id);
  ms election_timeout(150);

  TRaft r0(
    ConsensusType::CFT,
    std::make_unique<Adaptor>(kv_store),
    std::make_unique<aft::LedgerStubProxy>(node_id),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::StubSnapshotter>(),
    nullptr,
    nullptr,
    cert,
    std::make_shared<aft::State>(node_id),
    nullptr,
    nullptr,
    nullptr,
    request_timeout,
    election_timeout,
    ms(1000));

  kv::Configuration::Nodes config;
  config.try_emplace(node_id);
  r0.add_configuration(0, config);

  DOCTEST_INFO("DOCTEST_REQUIRE Initial State");

  DOCTEST_REQUIRE(!r0.is_primary());
  DOCTEST_REQUIRE(!r0.leader().has_value());
  DOCTEST_REQUIRE(r0.get_term() == 0);
  DOCTEST_REQUIRE(r0.get_commit_idx() == 0);

  DOCTEST_INFO(
    "In the absence of other nodes, become leader after election timeout");

  r0.periodic(ms(0));
  DOCTEST_REQUIRE(!r0.is_primary());

  r0.periodic(election_timeout * 2);
  DOCTEST_REQUIRE(r0.is_primary());
  DOCTEST_REQUIRE(r0.leader() == node_id);
}

DOCTEST_TEST_CASE("Single node commit" * doctest::test_suite("single"))
{
  ccf::NodeId node_id = kv::test::PrimaryNodeId;
  auto kv_store = std::make_shared<Store>(node_id);
  ms election_timeout(150);

  TRaft r0(
    ConsensusType::CFT,
    std::make_unique<Adaptor>(kv_store),
    std::make_unique<aft::LedgerStubProxy>(node_id),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::StubSnapshotter>(),
    nullptr,
    nullptr,
    cert,
    std::make_shared<aft::State>(node_id),
    nullptr,
    nullptr,
    nullptr,
    request_timeout,
    election_timeout,
    ms(1000));

  aft::Configuration::Nodes config;
  config[node_id] = {};
  r0.add_configuration(0, config);

  DOCTEST_INFO("Become leader after election timeout");

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
    DOCTEST_REQUIRE(r0.get_commit_idx() == i);
  }
}

DOCTEST_TEST_CASE(
  "Multiple nodes startup and election" * doctest::test_suite("multiple"))
{
  ccf::NodeId node_id0 = kv::test::PrimaryNodeId;
  ccf::NodeId node_id1 = kv::test::FirstBackupNodeId;
  ccf::NodeId node_id2 = kv::test::SecondBackupNodeId;

  auto kv_store0 = std::make_shared<Store>(node_id0);
  auto kv_store1 = std::make_shared<Store>(node_id1);
  auto kv_store2 = std::make_shared<Store>(node_id2);

  ms request_timeout(10);

  TRaft r0(
    ConsensusType::CFT,
    std::make_unique<Adaptor>(kv_store0),
    std::make_unique<aft::LedgerStubProxy>(node_id0),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::StubSnapshotter>(),
    nullptr,
    nullptr,
    cert,
    std::make_shared<aft::State>(node_id0),
    nullptr,
    nullptr,
    nullptr,
    request_timeout,
    ms(20),
    ms(1000));
  TRaft r1(
    ConsensusType::CFT,
    std::make_unique<Adaptor>(kv_store1),
    std::make_unique<aft::LedgerStubProxy>(node_id1),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::StubSnapshotter>(),
    nullptr,
    nullptr,
    cert,
    std::make_shared<aft::State>(node_id1),
    nullptr,
    nullptr,
    nullptr,
    request_timeout,
    ms(100),
    ms(1000));
  TRaft r2(
    ConsensusType::CFT,
    std::make_unique<Adaptor>(kv_store2),
    std::make_unique<aft::LedgerStubProxy>(node_id2),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::StubSnapshotter>(),
    nullptr,
    nullptr,
    cert,
    std::make_shared<aft::State>(node_id2),
    nullptr,
    nullptr,
    nullptr,
    request_timeout,
    ms(50),
    ms(1000));

  aft::Configuration::Nodes config;
  config[node_id0] = {};
  config[node_id1] = {};
  config[node_id2] = {};
  r0.add_configuration(0, config);
  r1.add_configuration(0, config);
  r2.add_configuration(0, config);

  auto r0c = channel_stub_proxy(r0);
  auto r1c = channel_stub_proxy(r1);
  auto r2c = channel_stub_proxy(r2);

  DOCTEST_INFO("Node 0 exceeds its election timeout and starts an election");

  r0.periodic(std::chrono::milliseconds(200));
  DOCTEST_REQUIRE(
    r0c->count_messages_with_type(aft::RaftMsgType::raft_request_vote) == 2);

  DOCTEST_INFO("Node 1 receives the request");

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

  DOCTEST_INFO("Node 2 receives the request");

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
    r0c->count_messages_with_type(aft::RaftMsgType::raft_append_entries) == 2);

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
}

template <typename AssertionArg, class NodeMap, class Assertion>
static size_t dispatch_all_and_DOCTEST_CHECK(
  NodeMap& nodes,
  const ccf::NodeId& from,
  aft::ChannelStubProxy::MessageList& messages,
  const Assertion& assertion)
{
  size_t count = 0;
  while (messages.size())
  {
    auto [tgt_node_id, contents] = messages.front();
    messages.pop_front();

    {
      AssertionArg arg = *(AssertionArg*)contents.data();
      assertion(arg);
    }

    receive_message(*nodes[from], *nodes[tgt_node_id], contents);

    count++;
  }
  return count;
}

template <class NodeMap>
static size_t dispatch_all(
  NodeMap& nodes,
  const ccf::NodeId& from,
  aft::ChannelStubProxy::MessageList& messages)
{
  return dispatch_all_and_DOCTEST_CHECK<bool>(
    nodes, from, messages, [](const auto&) {
      // Pass
    });
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

  ms request_timeout(10);

  TRaft r0(
    ConsensusType::CFT,
    std::make_unique<Adaptor>(kv_store0),
    std::make_unique<aft::LedgerStubProxy>(node_id0),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::StubSnapshotter>(),
    nullptr,
    nullptr,
    cert,
    std::make_shared<aft::State>(node_id0),
    nullptr,
    nullptr,
    nullptr,
    request_timeout,
    ms(20),
    ms(1000));
  TRaft r1(
    ConsensusType::CFT,
    std::make_unique<Adaptor>(kv_store1),
    std::make_unique<aft::LedgerStubProxy>(node_id1),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::StubSnapshotter>(),
    nullptr,
    nullptr,
    cert,
    std::make_shared<aft::State>(node_id1),
    nullptr,
    nullptr,
    nullptr,
    request_timeout,
    ms(100),
    ms(1000));
  TRaft r2(
    ConsensusType::CFT,
    std::make_unique<Adaptor>(kv_store2),
    std::make_unique<aft::LedgerStubProxy>(node_id2),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::StubSnapshotter>(),
    nullptr,
    nullptr,
    cert,
    std::make_shared<aft::State>(node_id2),
    nullptr,
    nullptr,
    nullptr,
    request_timeout,
    ms(50),
    ms(1000));

  aft::Configuration::Nodes config;
  config[node_id0] = {};
  config[node_id1] = {};
  config[node_id2] = {};
  r0.add_configuration(0, config);
  r1.add_configuration(0, config);
  r2.add_configuration(0, config);

  map<ccf::NodeId, TRaft*> nodes;
  nodes[node_id0] = &r0;
  nodes[node_id1] = &r1;
  nodes[node_id2] = &r2;

  auto r0c = channel_stub_proxy(r0);
  auto r1c = channel_stub_proxy(r1);
  auto r2c = channel_stub_proxy(r2);

  r0.periodic(std::chrono::milliseconds(200));

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
  DOCTEST_REQUIRE(r0.ledger->ledger.front() == entry);
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

  ms request_timeout(10);

  TRaft r0(
    ConsensusType::CFT,
    std::make_unique<Adaptor>(kv_store0),
    std::make_unique<aft::LedgerStubProxy>(node_id0),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::StubSnapshotter>(),
    nullptr,
    nullptr,
    cert,
    std::make_shared<aft::State>(node_id0),
    nullptr,
    nullptr,
    nullptr,
    request_timeout,
    ms(20),
    ms(1000));
  TRaft r1(
    ConsensusType::CFT,
    std::make_unique<Adaptor>(kv_store1),
    std::make_unique<aft::LedgerStubProxy>(node_id1),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::StubSnapshotter>(),
    nullptr,
    nullptr,
    cert,
    std::make_shared<aft::State>(node_id1),
    nullptr,
    nullptr,
    nullptr,
    request_timeout,
    ms(100),
    ms(1000));
  TRaft r2(
    ConsensusType::CFT,
    std::make_unique<Adaptor>(kv_store2),
    std::make_unique<aft::LedgerStubProxy>(node_id2),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::StubSnapshotter>(),
    nullptr,
    nullptr,
    cert,
    std::make_shared<aft::State>(node_id2),
    nullptr,
    nullptr,
    nullptr,
    request_timeout,
    ms(50),
    ms(1000));

  aft::Configuration::Nodes config;
  config[node_id0] = {};
  config[node_id1] = {};
  r0.add_configuration(0, config);
  r1.add_configuration(0, config);

  map<ccf::NodeId, TRaft*> nodes;
  nodes[node_id0] = &r0;
  nodes[node_id1] = &r1;

  auto r0c = channel_stub_proxy(r0);
  auto r1c = channel_stub_proxy(r1);
  auto r2c = channel_stub_proxy(r2);

  r0.periodic(std::chrono::milliseconds(200));

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

  auto kv_store0 = std::make_shared<Store>(node_id0);
  auto kv_store1 = std::make_shared<Store>(node_id1);

  ms request_timeout(10);

  TRaft r0(
    ConsensusType::CFT,
    std::make_unique<Adaptor>(kv_store0),
    std::make_unique<aft::LedgerStubProxy>(node_id0),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::StubSnapshotter>(),
    nullptr,
    nullptr,
    cert,
    std::make_shared<aft::State>(node_id0),
    nullptr,
    nullptr,
    nullptr,
    request_timeout,
    ms(20),
    ms(1000));
  TRaft r1(
    ConsensusType::CFT,
    std::make_unique<Adaptor>(kv_store1),
    std::make_unique<aft::LedgerStubProxy>(node_id1),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::StubSnapshotter>(),
    nullptr,
    nullptr,
    cert,
    std::make_shared<aft::State>(node_id1),
    nullptr,
    nullptr,
    nullptr,
    request_timeout,
    ms(100),
    ms(1000));

  aft::Configuration::Nodes config0;
  config0[node_id0] = {};
  config0[node_id1] = {};
  r0.add_configuration(0, config0);
  r1.add_configuration(0, config0);

  map<ccf::NodeId, TRaft*> nodes;
  nodes[node_id0] = &r0;
  nodes[node_id1] = &r1;

  auto r0c = channel_stub_proxy(r0);
  auto r1c = channel_stub_proxy(r1);

  r0.periodic(std::chrono::milliseconds(200));

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
    auto hooks = std::make_shared<kv::ConsensusHookPtrs>();

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
    auto hooks = std::make_shared<kv::ConsensusHookPtrs>();
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
    auto hooks = std::make_shared<kv::ConsensusHookPtrs>();
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
    auto hooks = std::make_shared<kv::ConsensusHookPtrs>();
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
    DOCTEST_REQUIRE(r0c->messages.size() == 1);

    // Receive append entries (idx: 5, prev_idx: 3)
    r1.ledger->reset_skip_count();
    DOCTEST_REQUIRE(1 == dispatch_all(nodes, node_id0, r0c->messages));
    DOCTEST_REQUIRE(r1.ledger->ledger.size() == 5);
    DOCTEST_REQUIRE(r1.ledger->skip_count == 2);
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

  ms request_timeout(10);

  TRaft r0(
    ConsensusType::CFT,
    std::make_unique<Adaptor>(kv_store0),
    std::make_unique<aft::LedgerStubProxy>(node_id0),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::StubSnapshotter>(),
    nullptr,
    nullptr,
    cert,
    std::make_shared<aft::State>(node_id0),
    nullptr,
    nullptr,
    nullptr,
    request_timeout,
    ms(20),
    ms(1000));
  TRaft r1(
    ConsensusType::CFT,
    std::make_unique<Adaptor>(kv_store1),
    std::make_unique<aft::LedgerStubProxy>(node_id1),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::StubSnapshotter>(),
    nullptr,
    nullptr,
    cert,
    std::make_shared<aft::State>(node_id1),
    nullptr,
    nullptr,
    nullptr,
    request_timeout,
    ms(100),
    ms(1000));
  TRaft r2(
    ConsensusType::CFT,
    std::make_unique<Adaptor>(kv_store2),
    std::make_unique<aft::LedgerStubProxy>(node_id2),
    std::make_shared<aft::ChannelStubProxy>(),
    std::make_shared<aft::StubSnapshotter>(),
    nullptr,
    nullptr,
    cert,
    std::make_shared<aft::State>(node_id2),
    nullptr,
    nullptr,
    nullptr,
    request_timeout,
    ms(50),
    ms(1000));

  aft::Configuration::Nodes config0;
  config0[node_id0] = {};
  config0[node_id1] = {};
  r0.add_configuration(0, config0);
  r1.add_configuration(0, config0);

  map<ccf::NodeId, TRaft*> nodes;
  nodes[node_id0] = &r0;
  nodes[node_id1] = &r1;

  auto r0c = channel_stub_proxy(r0);
  auto r1c = channel_stub_proxy(r1);

  r0.periodic(std::chrono::milliseconds(200));

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
  bool msg_response = false;

  for (size_t i = 1; i <= num_big_entries; ++i)
  {
    auto hooks = std::make_shared<kv::ConsensusHookPtrs>();
    DOCTEST_REQUIRE(r0.replicate(kv::BatchVector{{i, data, true, hooks}}, 1));
    DOCTEST_REQUIRE(
      msg_response ==
      dispatch_all_and_DOCTEST_CHECK<aft::AppendEntries>(
        nodes, node_id0, r0c->messages, [&i](const auto& msg) {
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

  DOCTEST_REQUIRE(r0c->messages.size() > num_small_entries_sent);
  DOCTEST_REQUIRE(
    r0c->messages.size() <= num_small_entries_sent + num_big_entries);
  auto sent_entries = dispatch_all(nodes, node_id0, r0c->messages);
  DOCTEST_REQUIRE(sent_entries > num_small_entries_sent);
  DOCTEST_REQUIRE(sent_entries <= num_small_entries_sent + num_big_entries);
  DOCTEST_REQUIRE(r2.ledger->ledger.size() == individual_entries);
}

DOCTEST_TEST_CASE("Test Asynchronous Execution Coordinator")
{
  DOCTEST_INFO("With 1 thread");
  {
    aft::AsyncExecutor aec(1);
    for (uint32_t i = 0; i < 20; ++i)
    {
      DOCTEST_REQUIRE(aec.should_exec_next_append_entry(i % 2, 10));
      DOCTEST_REQUIRE(
        aec.execution_status() == aft::AsyncSchedulingResult::DONE);
    }
  }

  DOCTEST_INFO("multithreaded run upto max specified tx");
  {
    aft::AsyncExecutor aec(2);
    aec.execute_as_far_as_possible(5);
    for (uint32_t i = 0; i < 5; ++i)
    {
      DOCTEST_REQUIRE(aec.should_exec_next_append_entry(true, i));
      aec.increment_pending();
      DOCTEST_REQUIRE(
        aec.execution_status() == aft::AsyncSchedulingResult::SYNCH_POINT);
    }
    DOCTEST_REQUIRE(aec.should_exec_next_append_entry(true, 5) == false);
  }

  DOCTEST_INFO("multithreaded run upto sync point");
  {
    aft::AsyncExecutor aec(2);
    aec.execute_as_far_as_possible(10);
    for (uint32_t i = 0; i < 5; ++i)
    {
      DOCTEST_REQUIRE(aec.should_exec_next_append_entry(true, i));
      aec.increment_pending();
      DOCTEST_REQUIRE(
        aec.execution_status() == aft::AsyncSchedulingResult::SYNCH_POINT);
    }

    {
      // execute a transaction that does not support async execution
      DOCTEST_REQUIRE(aec.should_exec_next_append_entry(false, 5) == false);
      aec.increment_pending();
    }

    // Reset for next round of execution
    aec.execute_as_far_as_possible(10);
    for (uint32_t i = 5; i < 10; ++i)
    {
      DOCTEST_REQUIRE(aec.should_exec_next_append_entry(true, i));
      aec.increment_pending();
      DOCTEST_REQUIRE(
        aec.execution_status() == aft::AsyncSchedulingResult::SYNCH_POINT);
    }
  }

  DOCTEST_INFO("test first tx does not allow async execution");
  {
    aft::AsyncExecutor aec(2);
    aec.execute_as_far_as_possible(5);

    DOCTEST_REQUIRE(aec.should_exec_next_append_entry(false, 0));

    // As the first execution did not support async it should have been executed
    // inline as no other transaction was pending. therefore is is safe to run
    // the next transaction.
    DOCTEST_REQUIRE(aec.should_exec_next_append_entry(true, 1));
  }
}