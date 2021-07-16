// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/aft/raft.h"
#include "ds/logger.h"
#include "logging_stub.h"

#include <chrono>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>

#define RAFT_DRIVER_OUT std::cout << "<RaftDriver>"

std::string stringify(const std::vector<uint8_t>& v, size_t max_size = 15ul)
{
  auto size = std::min(v.size(), max_size);
  return fmt::format(
    "[{} bytes] {}", v.size(), std::string(v.begin(), v.begin() + size));
}

struct LedgerStubProxy_WithLogging : public aft::LedgerStubProxy
{
  using LedgerStubProxy::LedgerStubProxy;

  void put_entry(
    const std::vector<uint8_t>& data,
    bool globally_committable,
    bool force_chunk) override
  {
    RAFT_DRIVER_OUT << "  Node" << _id << "->>Node" << _id
                    << ": ledger put s: " << stringify(data) << std::endl;
    aft::LedgerStubProxy::put_entry(data, globally_committable, force_chunk);
  }

  void truncate(aft::Index idx) override
  {
    RAFT_DRIVER_OUT << "  Node" << _id << "->>Node" << _id
                    << ": truncate i: " << idx << std::endl;
    aft::LedgerStubProxy::truncate(idx);
  }
};

using ms = std::chrono::milliseconds;
using TRaft = aft::
  Aft<LedgerStubProxy_WithLogging, aft::ChannelStubProxy, aft::StubSnapshotter>;
using Store = aft::LoggingStubStore;
using Adaptor = aft::Adaptor<Store>;

std::vector<uint8_t> cert;

aft::ChannelStubProxy* channel_stub_proxy(const TRaft& r)
{
  return (aft::ChannelStubProxy*)r.channels.get();
}

class RaftDriver
{
private:
  struct NodeDriver
  {
    std::shared_ptr<Store> kv;
    std::shared_ptr<TRaft> raft;
  };

  std::unordered_map<ccf::NodeId, NodeDriver> _nodes;
  std::set<std::pair<ccf::NodeId, ccf::NodeId>> _connections;

public:
  RaftDriver(size_t number_of_nodes)
  {
    kv::Configuration::Nodes configuration;

    for (size_t i = 0; i < number_of_nodes; ++i)
    {
      ccf::NodeId node_id = std::to_string(i);

      auto kv = std::make_shared<Store>(node_id);
      auto raft = std::make_shared<TRaft>(
        ConsensusType::CFT,
        std::make_unique<Adaptor>(kv),
        std::make_unique<LedgerStubProxy_WithLogging>(node_id),
        std::make_shared<aft::ChannelStubProxy>(),
        std::make_shared<aft::StubSnapshotter>(),
        nullptr,
        nullptr,
        cert,
        std::make_shared<aft::State>(node_id),
        nullptr,
        std::make_shared<aft::RequestTracker>(),
        nullptr,
        ms(10),
        ms(100),
        ms(100));

      _nodes.emplace(node_id, NodeDriver{kv, raft});
      configuration.try_emplace(node_id);
    }

    for (auto& node : _nodes)
    {
      node.second.raft->add_configuration(0, configuration);
    }
  }

  void log(ccf::NodeId first, ccf::NodeId second, const std::string& message)
  {
    RAFT_DRIVER_OUT << "  Node" << first << "->>"
                    << "Node" << second << ": " << message << std::endl;
  }

  void rlog(ccf::NodeId first, ccf::NodeId second, const std::string& message)
  {
    RAFT_DRIVER_OUT << "  Node" << first << "-->>"
                    << "Node" << second << ": " << message << std::endl;
  }

  void log_msg_details(
    ccf::NodeId node_id, ccf::NodeId tgt_node_id, aft::RequestVote rv)
  {
    std::ostringstream s;
    s << "request_vote t: " << rv.term << ", lci: " << rv.last_committable_idx
      << ", tolci: " << rv.term_of_last_committable_idx;
    log(node_id, tgt_node_id, s.str());
  }

  void log_msg_details(
    ccf::NodeId node_id, ccf::NodeId tgt_node_id, aft::RequestVoteResponse rv)
  {
    std::ostringstream s;
    s << "request_vote_response t: " << rv.term << ", vg: " << rv.vote_granted;
    rlog(node_id, tgt_node_id, s.str());
  }

  void log_msg_details(
    ccf::NodeId node_id, ccf::NodeId tgt_node_id, aft::AppendEntries ae)
  {
    std::ostringstream s;
    s << "append_entries i: " << ae.idx << ", t: " << ae.term
      << ", pi: " << ae.prev_idx << ", pt: " << ae.prev_term
      << ", lci: " << ae.leader_commit_idx;
    log(node_id, tgt_node_id, s.str());
  }

  void log_msg_details(
    ccf::NodeId node_id,
    ccf::NodeId tgt_node_id,
    aft::AppendEntriesResponse aer)
  {
    std::ostringstream s;
    char const* success = "UNHANDLED";
    switch (aer.success)
    {
      case (aft::AppendEntriesResponseType::OK):
      {
        success = "Y";
        break;
      }
      case (aft::AppendEntriesResponseType::FAIL):
      {
        success = "N";
        break;
      }
      case (aft::AppendEntriesResponseType::REQUIRE_EVIDENCE):
      {
        success = "E";
        break;
      }
    }
    s << "append_entries_response t: " << aer.term
      << ", lli: " << aer.last_log_idx << ", s: " << success;
    rlog(node_id, tgt_node_id, s.str());
  }

  void log_msg_details(
    ccf::NodeId node_id,
    ccf::NodeId tgt_node_id,
    const std::vector<uint8_t>& contents)
  {
    const uint8_t* data = contents.data();
    size_t size = contents.size();

    const auto msg_type = serialized::peek<aft::RaftMsgType>(data, size);
    switch (msg_type)
    {
      case (aft::RaftMsgType::raft_request_vote):
      {
        auto rv = *(aft::RequestVote*)data;
        log_msg_details(node_id, tgt_node_id, rv);
        break;
      }
      case (aft::RaftMsgType::raft_request_vote_response):
      {
        auto rvr = *(aft::RequestVoteResponse*)data;
        log_msg_details(node_id, tgt_node_id, rvr);
        break;
      }
      case (aft::RaftMsgType::raft_append_entries):
      {
        auto ae = *(aft::AppendEntries*)data;
        log_msg_details(node_id, tgt_node_id, ae);
        break;
      }
      case (aft::RaftMsgType::raft_append_entries_response):
      {
        auto aer = *(aft::AppendEntriesResponse*)data;
        log_msg_details(node_id, tgt_node_id, aer);
        break;
      }
      default:
      {
        throw std::runtime_error(
          fmt::format("Unhandled RaftMsgType: {}", msg_type));
      }
    }
  }

  void connect(ccf::NodeId first, ccf::NodeId second)
  {
    RAFT_DRIVER_OUT << "  Node" << first << "-->Node" << second << ": connect"
                    << std::endl;
    _connections.insert(std::make_pair(first, second));
    _connections.insert(std::make_pair(second, first));
  }

  void periodic_one(ccf::NodeId node_id, ms ms_)
  {
    std::ostringstream s;
    s << "periodic for " << std::to_string(ms_.count()) << " ms";
    log(node_id, node_id, s.str());
    _nodes.at(node_id).raft->periodic(ms_);
  }

  void periodic_all(ms ms_)
  {
    for (auto& node : _nodes)
    {
      periodic_one(node.first, ms_);
    }
  }

  void state_one(ccf::NodeId node_id)
  {
    auto raft = _nodes.at(node_id).raft;
    RAFT_DRIVER_OUT << "  Note right of Node" << node_id << ": "
                    << (raft->is_primary() ? "L " : "")
                    << " t: " << raft->get_term()
                    << ", li: " << raft->get_last_idx()
                    << ", ci: " << raft->get_commit_idx() << std::endl;
  }

  void state_all()
  {
    for (auto& node : _nodes)
    {
      state_one(node.first);
    }
  }

  void shuffle_messages_one(ccf::NodeId node_id)
  {
    auto raft = _nodes.at(node_id).raft;
    auto& messages = channel_stub_proxy(*raft)->messages;

    std::random_device rd;
    std::mt19937 g(rd());
    std::shuffle(messages.begin(), messages.end(), g);
  }

  void shuffle_messages_all()
  {
    for (auto& node : _nodes)
    {
      shuffle_messages_one(node.first);
    }
  }

  template <class Messages>
  size_t dispatch_one_queue(ccf::NodeId node_id, Messages& messages)
  {
    size_t count = 0;

    while (messages.size())
    {
      auto [tgt_node_id, contents] = messages.front();
      messages.pop_front();

      if (
        _connections.find(std::make_pair(node_id, tgt_node_id)) !=
        _connections.end())
      {
        // If this is an AppendEntries, then append the corresponding entry from
        // the sender's ledger
        const uint8_t* data = contents.data();
        auto size = contents.size();
        auto msg_type = serialized::peek<aft::RaftMsgType>(data, size);
        if (msg_type == aft::raft_append_entries)
        {
          // Parse the indices to be sent to the recipient.
          auto ae = *(aft::AppendEntries*)data;

          auto& sender_ledger = _nodes.at(node_id).raft->ledger;
          for (auto idx = ae.prev_idx + 1; idx <= ae.idx; ++idx)
          {
            const auto entry = sender_ledger->get_entry_by_idx(idx);
            contents.insert(contents.end(), entry.begin(), entry.end());
          }
        }

        log_msg_details(node_id, tgt_node_id, contents);
        _nodes.at(tgt_node_id)
          .raft->recv_message(node_id, contents.data(), contents.size());
        count++;
      }
    }

    return count;
  }

  void dispatch_one(ccf::NodeId node_id)
  {
    auto raft = _nodes.at(node_id).raft;
    dispatch_one_queue(node_id, channel_stub_proxy(*raft)->messages);
  }

  void dispatch_all_once()
  {
    for (auto& node : _nodes)
    {
      dispatch_one(node.first);
    }
  }

  void dispatch_all()
  {
    size_t iterations = 0;
    while (std::accumulate(
             _nodes.begin(),
             _nodes.end(),
             0,
             [](int acc, auto& node) {
               return channel_stub_proxy(*node.second.raft)->messages.size() +
                 acc;
             }) &&
           iterations++ < 5)
    {
      dispatch_all_once();
    }
  }

  ccf::NodeId find_primary_in_term(aft::Term term)
  {
    for (const auto& [node_id, node_driver] : _nodes)
    {
      if (
        node_driver.raft->get_term() == term && node_driver.raft->is_primary())
      {
        return node_id;
      }
    }

    throw std::runtime_error(fmt::format("Found no primary in term {}", term));
  }

  void replicate(aft::Term term, std::shared_ptr<std::vector<uint8_t>> data)
  {
    const auto node_id = find_primary_in_term(term);
    auto& raft = _nodes.at(node_id).raft;
    const auto idx = raft->get_last_idx() + 1;
    RAFT_DRIVER_OUT << fmt::format(
                         "  Node{}->>Node{}: replicate {}.{} = {}",
                         node_id,
                         node_id,
                         term,
                         idx,
                         stringify(*data))
                    << std::endl;
    auto hooks = std::make_shared<kv::ConsensusHookPtrs>();
    // True means all these entries are committable
    raft->replicate(kv::BatchVector{{idx, data, true, hooks}}, 1);
  }

  void disconnect(ccf::NodeId left, ccf::NodeId right)
  {
    bool noop = true;
    auto ltr = std::make_pair(left, right);
    auto rtl = std::make_pair(right, left);
    if (_connections.find(ltr) != _connections.end())
    {
      _connections.erase(ltr);
      noop = false;
    }
    if (_connections.find(rtl) != _connections.end())
    {
      _connections.erase(rtl);
      noop = false;
    }
    if (!noop)
    {
      RAFT_DRIVER_OUT << "  Node" << left << "-->Node" << right
                      << ": disconnect" << std::endl;
    }
  }

  void disconnect_node(ccf::NodeId node_id)
  {
    for (auto& node : _nodes)
    {
      if (node.first != node_id)
      {
        disconnect(node_id, node.first);
      }
    }
  }

  void reconnect(ccf::NodeId left, ccf::NodeId right)
  {
    RAFT_DRIVER_OUT << "  Node" << left << "-->Node" << right << ": reconnect"
                    << std::endl;
    _connections.insert(std::make_pair(left, right));
    _connections.insert(std::make_pair(right, left));
  }

  void reconnect_node(ccf::NodeId node_id)
  {
    for (auto& node : _nodes)
    {
      if (node.first != node_id)
      {
        reconnect(node_id, node.first);
      }
    }
  }

  void assert_state_sync()
  {
    auto [_, nd] = *_nodes.begin();
    auto& target_raft = nd.raft;
    const auto target_term = target_raft->get_term();
    const auto target_last_idx = target_raft->get_last_idx();
    const auto target_commit_idx = target_raft->get_commit_idx();

    const auto target_final_entry = target_raft->ledger->get_entry_by_idx(target_last_idx);

    for (auto it = std::next(_nodes.begin()); it != _nodes.end(); ++it)
    {
      auto& raft = it->second.raft;

      assert(raft->get_term() == target_term);
      assert(raft->get_last_idx() == target_last_idx);
      assert(raft->get_commit_idx() == target_commit_idx);

      // Check that the final entries are the same, assume prior entries also match
      assert(raft->ledger->get_entry_by_idx(target_last_idx) == target_final_entry);
    }
  }
};
