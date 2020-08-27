// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/aft/raft.h"
#include "ds/logger.h"

#include <chrono>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>

#define STUB_LOG 1
#include "logging_stub.h"

using ms = std::chrono::milliseconds;
using TRaft =
  aft::Aft<aft::LedgerStubProxy, aft::ChannelStubProxy, aft::StubSnapshotter>;
using Store = aft::LoggingStubStore;
using Adaptor = aft::Adaptor<Store, kv::DeserialiseSuccess>;

std::vector<uint8_t> cert;
kv::Map<size_t, pbft::Request> request_map(
  nullptr, "test", kv::SecurityDomain::PUBLIC, true);

class RaftDriver
{
private:
  struct NodeDriver
  {
    std::shared_ptr<Store> kv;
    std::shared_ptr<TRaft> raft;
  };

  std::unordered_map<aft::NodeId, NodeDriver> _nodes;
  std::set<std::pair<aft::NodeId, aft::NodeId>> _connections;

public:
  RaftDriver(size_t number_of_nodes)
  {
    kv::Consensus::Configuration::Nodes configuration;

    for (size_t i = 0; i < number_of_nodes; ++i)
    {
      aft::NodeId node_id = i;

      auto kv = std::make_shared<Store>(node_id);
      auto raft = std::make_shared<TRaft>(
        ConsensusType::RAFT,
        std::make_unique<Adaptor>(kv),
        std::make_unique<aft::LedgerStubProxy>(node_id),
        std::make_shared<aft::ChannelStubProxy>(),
        std::make_shared<aft::StubSnapshotter>(),
        nullptr,
        nullptr,
        cert,
        request_map,
        std::make_shared<aft::ServiceState>(node_id),
        nullptr,
        ms(10),
        ms(i * 100));

      _nodes.emplace(node_id, NodeDriver{kv, raft});
      configuration.try_emplace(node_id);
    }

    for (auto& node : _nodes)
    {
      node.second.raft->add_configuration(0, configuration);
    }
  }

  void log(aft::NodeId first, aft::NodeId second, const std::string& message)
  {
    std::cout << "  Node" << first << "->>"
              << "Node" << second << ": " << message << std::endl;
  }

  void rlog(aft::NodeId first, aft::NodeId second, const std::string& message)
  {
    std::cout << "  Node" << first << "-->>"
              << "Node" << second << ": " << message << std::endl;
  }

  void log_msg_details(
    aft::NodeId node_id, aft::NodeId tgt_node_id, aft::RequestVote rv)
  {
    std::ostringstream s;
    s << "request_vote t: " << rv.term << ", lli: " << rv.last_commit_idx
      << ", llt: " << rv.last_commit_term;
    log(node_id, tgt_node_id, s.str());
  }

  void log_msg_details(
    aft::NodeId node_id, aft::NodeId tgt_node_id, aft::RequestVoteResponse rv)
  {
    std::ostringstream s;
    s << "request_vote_response t: " << rv.term << ", vg: " << rv.vote_granted;
    rlog(node_id, tgt_node_id, s.str());
  }

  void log_msg_details(
    aft::NodeId node_id, aft::NodeId tgt_node_id, aft::AppendEntries ae)
  {
    std::ostringstream s;
    s << "append_entries i: " << ae.idx << ", t: " << ae.term
      << ", pi: " << ae.prev_idx << ", pt: " << ae.prev_term
      << ", lci: " << ae.leader_commit_idx;
    log(node_id, tgt_node_id, s.str());
  }

  void log_msg_details(
    aft::NodeId node_id,
    aft::NodeId tgt_node_id,
    aft::AppendEntriesResponse aer)
  {
    std::ostringstream s;
    s << "append_entries_response t: " << aer.term
      << ", lli: " << aer.last_log_idx << ", s: " << aer.success;
    rlog(node_id, tgt_node_id, s.str());
  }

  void connect(aft::NodeId first, aft::NodeId second)
  {
    std::cout << "  Node" << first << "-->Node" << second << ": connect"
              << std::endl;
    _connections.insert(std::make_pair(first, second));
    _connections.insert(std::make_pair(second, first));
  }

  void periodic_one(aft::NodeId node_id, ms ms_)
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

  void state_one(aft::NodeId node_id)
  {
    std::cout << "  Note right of Node" << node_id << ": ";
    auto raft = _nodes.at(node_id).raft;

    if (raft->is_leader())
      std::cout << "L ";

    std::cout << " t: " << raft->get_term() << ", li: " << raft->get_last_idx()
              << ", ci: " << raft->get_commit_idx() << std::endl;
  }

  void state_all()
  {
    for (auto& node : _nodes)
    {
      state_one(node.first);
    }
  }

  template <class Messages>
  size_t dispatch_one_queue(aft::NodeId node_id, Messages& messages)
  {
    size_t count = 0;

    while (messages.size())
    {
      auto message = messages.front();
      messages.pop_front();
      auto tgt_node_id = std::get<0>(message);

      if (
        _connections.find(std::make_pair(node_id, tgt_node_id)) !=
        _connections.end())
      {
        auto contents = std::get<1>(message);
        log_msg_details(node_id, tgt_node_id, contents);
        _nodes.at(tgt_node_id)
          .raft->recv_message(
            reinterpret_cast<uint8_t*>(&contents), sizeof(contents));
        count++;
      }
    }

    return count;
  }

  void dispatch_one(aft::NodeId node_id)
  {
    auto raft = _nodes.at(node_id).raft;
    dispatch_one_queue(
      node_id,
      ((aft::ChannelStubProxy*)raft->channels.get())->sent_request_vote);
    dispatch_one_queue(
      node_id,
      ((aft::ChannelStubProxy*)raft->channels.get())
        ->sent_request_vote_response);
    dispatch_one_queue(
      node_id,
      ((aft::ChannelStubProxy*)raft->channels.get())->sent_append_entries);
    dispatch_one_queue(
      node_id,
      ((aft::ChannelStubProxy*)raft->channels.get())
        ->sent_append_entries_response);
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
               return ((aft::ChannelStubProxy*)node.second.raft->channels.get())
                        ->sent_msg_count() +
                 acc;
             }) &&
           iterations++ < 5)
    {
      dispatch_all_once();
    }
  }

  void replicate(
    aft::NodeId node_id,
    aft::Index idx,
    std::shared_ptr<std::vector<uint8_t>> data)
  {
    std::cout << "  KV" << node_id << "->>Node" << node_id
              << ": replicate idx: " << idx << std::endl;
    _nodes.at(node_id).raft->replicate(kv::BatchVector{{idx, data, true}}, 1);
  }

  void disconnect(aft::NodeId left, aft::NodeId right)
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
      std::cout << "  Node" << left << "-->Node" << right << ": disconnect"
                << std::endl;
    }
  }

  void disconnect_node(aft::NodeId node_id)
  {
    for (auto& node : _nodes)
    {
      if (node.first != node_id)
      {
        disconnect(node_id, node.first);
      }
    }
  }

  void reconnect(aft::NodeId left, aft::NodeId right)
  {
    std::cout << "  Node" << left << "-->Node" << right << ": reconnect"
              << std::endl;
    _connections.insert(std::make_pair(left, right));
    _connections.insert(std::make_pair(right, left));
  }

  void reconnect_node(aft::NodeId node_id)
  {
    for (auto& node : _nodes)
    {
      if (node.first != node_id)
      {
        reconnect(node_id, node.first);
      }
    }
  }
};
