// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/aft/raft.h"
#include "ds/framework_logger.h"
#include "kv/test/stub_consensus.h"
#include "logging_stub.h"

#include <chrono>
#include <string>

using TRaft = aft::Aft<aft::LedgerStubProxy>;
using Store = aft::LoggingStubStore;
using Adaptor = aft::Adaptor<Store>;

static std::vector<uint8_t> cert;

static const ccf::ds::TimeString request_timeout_ = {"10ms"};
static const ccf::ds::TimeString election_timeout_ = {"100ms"};
static const size_t max_uncommitted_tx_count_ = 0;

static const std::chrono::milliseconds request_timeout = request_timeout_;
static const std::chrono::milliseconds election_timeout = election_timeout_;

static const ccf::consensus::Configuration raft_settings{
  request_timeout_, election_timeout_, max_uncommitted_tx_count_};

static auto hooks = std::make_shared<ccf::kv::ConsensusHookPtrs>();

static aft::ChannelStubProxy* channel_stub_proxy(const TRaft& r)
{
  return (aft::ChannelStubProxy*)r.channels.get();
}

static void receive_message(
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

      const auto payload_opt = sender.ledger->get_append_entries_payload(ae);
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

    if constexpr (!std::is_same_v<AssertionArg, void>)
    {
      AssertionArg arg = *(AssertionArg*)contents.data();
      assertion(arg);
    }

    receive_message(*nodes[from], *nodes[tgt_node_id], contents);

    count++;
  }
  return count;
}

template <typename AssertionArg, class NodeMap, class Assertion>
static size_t dispatch_all_and_DOCTEST_CHECK(
  NodeMap& nodes, const ccf::NodeId& from, const Assertion& assertion)
{
  auto& messages = channel_stub_proxy(*nodes.at(from))->messages;
  return dispatch_all_and_DOCTEST_CHECK<AssertionArg>(
    nodes, from, messages, assertion);
}

template <class NodeMap>
static size_t dispatch_all(
  NodeMap& nodes,
  const ccf::NodeId& from,
  aft::ChannelStubProxy::MessageList& messages)
{
  return dispatch_all_and_DOCTEST_CHECK<void>(
    nodes, from, messages, [](const auto&) {
      // Pass
    });
}

template <class NodeMap>
static size_t dispatch_all(NodeMap& nodes, const ccf::NodeId& from)
{
  auto& messages = channel_stub_proxy(*nodes.at(from))->messages;
  return dispatch_all(nodes, from, messages);
}

static std::shared_ptr<std::vector<uint8_t>> make_ledger_entry(
  const aft::Term term, const aft::Index idx)
{
  const auto s = fmt::format("Ledger entry @{}.{}", term, idx);
  auto e = std::make_shared<std::vector<uint8_t>>(s.begin(), s.end());

  // Each entry is so large that it produces a single AppendEntries, there are
  // never multiple combined into a single AppendEntries
  e->resize(TRaft::append_entries_size_limit);

  return e;
}