// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/logger.h"
#include "consensus/aft/raft.h"
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

std::string stringify(const std::optional<std::vector<uint8_t>>& o)
{
  if (o.has_value())
  {
    return stringify(*o);
  }

  return "MISSING";
}

struct LedgerStubProxy_Mermaid : public aft::LedgerStubProxy
{
  using LedgerStubProxy::LedgerStubProxy;

  void put_entry(
    const std::vector<uint8_t>& data,
    bool globally_committable,
    kv::Term term,
    kv::Version index) override
  {
    RAFT_DRIVER_OUT << fmt::format(
                         "  {}->>{}: [ledger] appending: {}.{}={}",
                         _id,
                         _id,
                         term,
                         index,
                         stringify(data))
                    << std::endl;
    aft::LedgerStubProxy::put_entry(data, globally_committable, term, index);
  }

  void truncate(aft::Index idx) override
  {
    RAFT_DRIVER_OUT << fmt::format(
                         "  {}->>{}: [ledger] truncating to {}", _id, _id, idx)
                    << std::endl;
    aft::LedgerStubProxy::truncate(idx);
  }
};

struct LoggingStubStoreSig_Mermaid : public aft::LoggingStubStoreSigConfig
{
  using LoggingStubStoreSigConfig::LoggingStubStoreSigConfig;

  void compact(aft::Index idx) override
  {
    RAFT_DRIVER_OUT << fmt::format(
                         "  {}->>{}: [KV] compacting to {}", _id, _id, idx)
                    << std::endl;
    aft::LoggingStubStoreSigConfig::compact(idx);
  }

  void rollback(const kv::TxID& tx_id, aft::Term t) override
  {
    RAFT_DRIVER_OUT << fmt::format(
                         "  {}->>{}: [KV] rolling back to {}.{}, in term {}",
                         _id,
                         _id,
                         tx_id.term,
                         tx_id.version,
                         t)
                    << std::endl;
    aft::LoggingStubStoreSigConfig::rollback(tx_id, t);
  }

  void initialise_term(aft::Term t) override
  {
    RAFT_DRIVER_OUT << fmt::format(
                         "  {}->>{}: [KV] initialising in term {}", _id, _id, t)
                    << std::endl;
    aft::LoggingStubStoreSigConfig::initialise_term(t);
  }
};

using ms = std::chrono::milliseconds;
using TRaft = aft::Aft<LedgerStubProxy_Mermaid>;
using Store = LoggingStubStoreSig_Mermaid;
using Adaptor = aft::Adaptor<Store>;

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

  std::map<ccf::NodeId, NodeDriver> _nodes;
  std::set<std::pair<ccf::NodeId, ccf::NodeId>> _connections;

  void _replicate(
    const std::string& term_s,
    std::vector<uint8_t> data,
    const size_t lineno,
    const std::optional<kv::Configuration::Nodes>& configuration = std::nullopt)
  {
    const auto opt = find_primary_in_term(term_s, lineno);
    if (!opt.has_value())
    {
      RAFT_DRIVER_OUT << fmt::format(
                           "  Note left of {}: No primary to replicate {}",
                           _nodes.begin()->first,
                           stringify(data))
                      << std::endl;
      return;
    }
    const auto& [term, node_id] = *opt;
    auto& raft = _nodes.at(node_id).raft;
    const auto idx = raft->get_last_idx() + 1;
    RAFT_DRIVER_OUT << fmt::format(
                         "  {}->>{}: replicate {}.{} = {} [{}]",
                         node_id,
                         node_id,
                         term_s,
                         idx,
                         stringify(data),
                         configuration.has_value() ? "reconfiguration" : "raw")
                    << std::endl;

    aft::ReplicatedDataType type = aft::ReplicatedDataType::raw;
    auto hooks = std::make_shared<kv::ConsensusHookPtrs>();
    if (configuration.has_value())
    {
      auto hook = std::make_unique<aft::ConfigurationChangeHook>(
        configuration.value(), idx);
      hooks->push_back(std::move(hook));
      type = aft::ReplicatedDataType::reconfiguration;
      auto c = nlohmann::json(configuration).dump();

      // If the entry is a reconfiguration, the replicated data is overwritten
      // with the serialised configuration
      data = std::vector<uint8_t>(c.begin(), c.end());
    }

    auto s = nlohmann::json(aft::ReplicatedData{type, data}).dump();
    auto d = std::make_shared<std::vector<uint8_t>>(s.begin(), s.end());
    // True means all these entries are committable
    raft->replicate(kv::BatchVector{{idx, d, true, hooks}}, term);
  }

  void add_node(ccf::NodeId node_id)
  {
    auto kv = std::make_shared<Store>(node_id);
    const consensus::Configuration settings{
      ConsensusType::CFT, {"10ms"}, {"100ms"}};
    auto raft = std::make_shared<TRaft>(
      settings,
      std::make_unique<Adaptor>(kv),
      std::make_unique<LedgerStubProxy_Mermaid>(node_id),
      std::make_shared<aft::ChannelStubProxy>(),
      std::make_shared<aft::State>(node_id),
      nullptr,
      nullptr);
    raft->start_ticking();

    if (_nodes.find(node_id) != _nodes.end())
    {
      throw std::logic_error(fmt::format("Node {} already exists", node_id));
    }

    _nodes.emplace(node_id, NodeDriver{kv, raft});
  }

public:
  RaftDriver() = default;

  void create_new_nodes(std::vector<std::string> node_ids)
  {
    // Opinionated way to create network. Initial configuration is automatically
    // added to all nodes.
    kv::Configuration::Nodes configuration;
    for (auto const& n : node_ids)
    {
      add_node(n);
      configuration.try_emplace(n);
    }

    for (auto& node : _nodes)
    {
      node.second.raft->add_configuration(0, configuration);
    }
  }

  void create_new_node(std::string node_id_s)
  {
    ccf::NodeId node_id(node_id_s);
    add_node(node_id);
    RAFT_DRIVER_OUT << fmt::format(
                         "  Note over {}: Node {} created", node_id, node_id)
                    << std::endl;
  }

  void replicate_new_configuration(
    const std::string& term_s,
    std::vector<std::string> node_ids,
    const size_t lineno)
  {
    kv::Configuration::Nodes configuration;
    for (const auto& node_id_s : node_ids)
    {
      ccf::NodeId node_id(node_id_s);

      if (_nodes.find(node_id) == _nodes.end())
      {
        throw std::runtime_error(fmt::format(
          "Node {} does not exist yet. Use \"create_new_node, <node_id>\"",
          node_id));
      }

      configuration.try_emplace(node_id);
    }

    _replicate(term_s, {}, lineno, configuration);
  }

  void log(
    ccf::NodeId first,
    ccf::NodeId second,
    const std::string& message,
    bool dropped = false)
  {
    RAFT_DRIVER_OUT << "  " << first << "-" << (dropped ? "X" : ">>") << second
                    << ": " << message << std::endl;
  }

  void rlog(
    ccf::NodeId first,
    ccf::NodeId second,
    const std::string& message,
    bool dropped = false)
  {
    RAFT_DRIVER_OUT << "  " << first << "--" << (dropped ? "X" : ">>") << second
                    << ": " << message << std::endl;
  }

  void log_msg_details(
    ccf::NodeId node_id,
    ccf::NodeId tgt_node_id,
    aft::RequestVote rv,
    bool dropped)
  {
    const auto s = fmt::format(
      "request_vote for term {}, at tx {}.{}",
      rv.term,
      rv.term_of_last_committable_idx,
      rv.last_committable_idx);
    log(node_id, tgt_node_id, s, dropped);
  }

  void log_msg_details(
    ccf::NodeId node_id,
    ccf::NodeId tgt_node_id,
    aft::RequestVoteResponse rv,
    bool dropped)
  {
    const auto s = fmt::format(
      "request_vote_response for term {} = {}",
      rv.term,
      (rv.vote_granted ? "Y" : "N"));
    rlog(node_id, tgt_node_id, s, dropped);
  }

  void log_msg_details(
    ccf::NodeId node_id,
    ccf::NodeId tgt_node_id,
    aft::AppendEntries ae,
    bool dropped)
  {
    const auto s = fmt::format(
      "append_entries ({}.{}, {}.{}] (term {}, commit {})",
      ae.prev_term,
      ae.prev_idx,
      ae.term_of_idx,
      ae.idx,
      ae.term,
      ae.leader_commit_idx);
    log(node_id, tgt_node_id, s, dropped);
  }

  void log_msg_details(
    ccf::NodeId node_id,
    ccf::NodeId tgt_node_id,
    aft::AppendEntriesResponse aer,
    bool dropped)
  {
    char const* success = "UNHANDLED";
    switch (aer.success)
    {
      case (aft::AppendEntriesResponseType::OK):
      {
        success = "ACK";
        break;
      }
      case (aft::AppendEntriesResponseType::FAIL):
      {
        success = "NACK";
        break;
      }
      case (aft::AppendEntriesResponseType::REQUIRE_EVIDENCE):
      {
        success = "REQUIRE EVIDENCE";
        break;
      }
    }
    const auto s = fmt::format(
      "append_entries_response {} for {}.{}",
      success,
      aer.term,
      aer.last_log_idx);
    rlog(node_id, tgt_node_id, s, dropped);
  }

  void log_msg_details(
    ccf::NodeId node_id,
    ccf::NodeId tgt_node_id,
    const std::vector<uint8_t>& contents,
    bool dropped = false)
  {
    const uint8_t* data = contents.data();
    size_t size = contents.size();

    const auto msg_type = serialized::peek<aft::RaftMsgType>(data, size);
    switch (msg_type)
    {
      case (aft::RaftMsgType::raft_request_vote):
      {
        auto rv = *(aft::RequestVote*)data;
        log_msg_details(node_id, tgt_node_id, rv, dropped);
        break;
      }
      case (aft::RaftMsgType::raft_request_vote_response):
      {
        auto rvr = *(aft::RequestVoteResponse*)data;
        log_msg_details(node_id, tgt_node_id, rvr, dropped);
        break;
      }
      case (aft::RaftMsgType::raft_append_entries):
      {
        auto ae = *(aft::AppendEntries*)data;
        log_msg_details(node_id, tgt_node_id, ae, dropped);
        break;
      }
      case (aft::RaftMsgType::raft_append_entries_response):
      {
        auto aer = *(aft::AppendEntriesResponse*)data;
        log_msg_details(node_id, tgt_node_id, aer, dropped);
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
    RAFT_DRIVER_OUT << "  " << first << "-->" << second << ": connect"
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
    RAFT_DRIVER_OUT << fmt::format(
                         "  Note right of {}: {} @{}.{} (committed {})",
                         node_id,
                         raft->is_primary() ? "P" :
                                              (raft->is_backup() ? "F" : "C"),
                         raft->get_view(),
                         raft->get_last_idx(),
                         raft->get_committed_seqno())
                    << std::endl;
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
  size_t dispatch_one_queue(
    ccf::NodeId node_id,
    Messages& messages,
    const std::optional<size_t>& max_count = std::nullopt)
  {
    size_t count = 0;

    while (messages.size() && (!max_count.has_value() || count < *max_count))
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
        bool should_send = true;
        if (msg_type == aft::raft_append_entries)
        {
          // Parse the indices to be sent to the recipient.
          auto ae = *(aft::AppendEntries*)data;

          auto& sender_raft = _nodes.at(node_id).raft;
          const auto payload_opt =
            sender_raft->ledger->get_append_entries_payload(ae);

          if (!payload_opt.has_value())
          {
            // While trying to construct an AppendEntries, we asked for an
            // entry that doesn't exist. This is a valid situation - we queued
            // the AppendEntries, but rolled back before it was dispatched!
            // We abandon this operation here.
            // We could log this in Mermaid with the line below, but since
            // this does not occur in a real node it is silently ignored. In a
            // real node, the AppendEntries and truncate messages are ordered
            // and processed by the host in that order. All AppendEntries
            // referencing a specific index will be processed before any
            // truncation that removes that index.
            // RAFT_DRIVER_OUT
            //   << fmt::format(
            //        "  Note right of {}: Abandoning AppendEntries"
            //        "containing {} - no longer in ledger",
            //        node_id,
            //        idx)
            //   << std::endl;
            should_send = false;
          }
          else
          {
            contents.insert(
              contents.end(), payload_opt->begin(), payload_opt->end());
          }
        }

        if (should_send)
        {
          log_msg_details(node_id, tgt_node_id, contents);
          _nodes.at(tgt_node_id)
            .raft->recv_message(node_id, contents.data(), contents.size());
          count++;
        }
      }
    }

    return count;
  }

  void dispatch_one(
    ccf::NodeId node_id, const std::optional<size_t>& max_count = std::nullopt)
  {
    auto raft = _nodes.at(node_id).raft;
    dispatch_one_queue(node_id, channel_stub_proxy(*raft)->messages, max_count);
  }

  void dispatch_all_once()
  {
    // The intent is to dispatch all _current_ messages, but no new ones. If we
    // simply iterated, then we may dispatch new messages that are produced on
    // later nodes, in response to messages from earlier-processed nodes. To
    // avoid that, we count how many messages are present initially, and cap to
    // only processing that many
    std::map<ccf::NodeId, size_t> initial_message_counts;
    for (auto& [node_id, driver] : _nodes)
    {
      initial_message_counts[node_id] =
        channel_stub_proxy(*driver.raft)->messages.size();
    }

    for (auto& node : _nodes)
    {
      dispatch_one(node.first, initial_message_counts[node.first]);
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

  std::optional<std::pair<aft::Term, ccf::NodeId>> find_primary_in_term(
    const std::string& term_s, const size_t lineno)
  {
    std::vector<std::pair<aft::Term, ccf::NodeId>> primaries;
    for (const auto& [node_id, node_driver] : _nodes)
    {
      if (node_driver.raft->is_primary())
      {
        primaries.emplace_back(node_driver.raft->get_view(), node_id);
      }
    }

    if (term_s == "latest")
    {
      if (!primaries.empty())
      {
        std::sort(primaries.begin(), primaries.end());
        return primaries.back();
      }
      else
      {
        // Having no 'latest' term is valid, and may result in scenario steps
        // being ignored
        return std::nullopt;
      }
    }
    else
    {
      const auto desired_term = atoi(term_s.c_str());
      for (const auto& pair : primaries)
      {
        if (pair.first == desired_term)
        {
          return pair;
        }
      }
    }

    throw std::runtime_error(fmt::format(
      "Found no primary in term {} on line {}",
      term_s,
      std::to_string((int)lineno)));
  }

  void replicate(
    const std::string& term_s,
    std::shared_ptr<std::vector<uint8_t>> data,
    const size_t lineno)
  {
    _replicate(term_s, *data, lineno);
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
      RAFT_DRIVER_OUT << "  " << left << "-->" << right << ": disconnect"
                      << std::endl;
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
    RAFT_DRIVER_OUT << "  " << left << "-->" << right << ": reconnect"
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

  void drop_pending_to(ccf::NodeId from, ccf::NodeId to)
  {
    auto from_raft = _nodes.at(from).raft;
    auto& messages = channel_stub_proxy(*from_raft)->messages;
    auto it = messages.begin();
    while (it != messages.end())
    {
      if (it->first == to)
      {
        log_msg_details(from, to, it->second, true);
        it = messages.erase(it);
      }
      else
      {
        ++it;
      }
    }
  }

  void drop_pending(ccf::NodeId from)
  {
    for (auto& [to, _] : _nodes)
    {
      drop_pending_to(from, to);
    }
  }

  void assert_is_backup(ccf::NodeId node_id, const size_t lineno)
  {
    if (!_nodes.at(node_id).raft->is_backup())
    {
      RAFT_DRIVER_OUT
        << fmt::format(
             "  Note over {}: Node is not in expected state: backup", node_id)
        << std::endl;
      throw std::runtime_error(fmt::format(
        "Node not in expected state backup on line {}",
        std::to_string((int)lineno)));
    }
  }

  void assert_is_primary(ccf::NodeId node_id, const size_t lineno)
  {
    if (!_nodes.at(node_id).raft->is_primary())
    {
      RAFT_DRIVER_OUT
        << fmt::format(
             "  Note over {}: Node is not in expected state: primary", node_id)
        << std::endl;
      throw std::runtime_error(fmt::format(
        "Node not in expected state primary on line {}",
        std::to_string((int)lineno)));
    }
  }

  void assert_is_candidate(ccf::NodeId node_id, const size_t lineno)
  {
    if (!_nodes.at(node_id).raft->is_candidate())
    {
      RAFT_DRIVER_OUT
        << fmt::format(
             "  Note over {}: Node is not in expected state: candidate",
             node_id)
        << std::endl;
      throw std::runtime_error(fmt::format(
        "Node not in expected state candidate on line {}",
        std::to_string((int)lineno)));
    }
  }

  void assert_is_retiring(ccf::NodeId node_id, const size_t lineno)
  {
    if (!_nodes.at(node_id).raft->is_retiring())
    {
      RAFT_DRIVER_OUT
        << fmt::format(
             "  Note over {}: Node is not in expected state: retiring", node_id)
        << std::endl;
      throw std::runtime_error(fmt::format(
        "Node not in expected state retiring on line {}",
        std::to_string((int)lineno)));
    }
  }

  void assert_is_retired(ccf::NodeId node_id, const size_t lineno)
  {
    if (!_nodes.at(node_id).raft->is_retired())
    {
      RAFT_DRIVER_OUT
        << fmt::format(
             "  Note over {}: Node is not in expected state: retired", node_id)
        << std::endl;
      throw std::runtime_error(fmt::format(
        "Node not in expected state retired on line {}",
        std::to_string((int)lineno)));
    }
  }

  void assert_state_sync(const size_t lineno)
  {
    auto [target_id, nd] = *_nodes.begin();
    auto& target_raft = nd.raft;
    const auto target_term = target_raft->get_view();
    const auto target_last_idx = target_raft->get_last_idx();
    const auto target_commit_idx = target_raft->get_committed_seqno();

    const auto target_final_entry =
      target_raft->ledger->get_entry_by_idx(target_last_idx);

    bool all_match = true;
    for (auto it = std::next(_nodes.begin()); it != _nodes.end(); ++it)
    {
      const auto& node_id = it->first;
      auto& raft = it->second.raft;

      if (raft->get_view() != target_term)
      {
        RAFT_DRIVER_OUT
          << fmt::format(
               "  Note over {}: Term {} doesn't match term {} on {}",
               node_id,
               raft->get_view(),
               target_term,
               target_id)
          << std::endl;
        all_match = false;
      }

      if (raft->get_last_idx() != target_last_idx)
      {
        RAFT_DRIVER_OUT << fmt::format(
                             "  Note over {}: Last index {} doesn't match "
                             "last index {} on {}",
                             node_id,
                             raft->get_last_idx(),
                             target_last_idx,
                             target_id)
                        << std::endl;
        all_match = false;
      }
      else
      {
        // Check that the final entries are the same, assume prior entries also
        // match
        const auto final_entry =
          raft->ledger->get_entry_by_idx(target_last_idx);

        if (final_entry != target_final_entry)
        {
          RAFT_DRIVER_OUT << fmt::format(
                               "  Note over {}: Final entry at index {} "
                               "doesn't match entry on {}: {} != {}",
                               node_id,
                               target_last_idx,
                               target_id,
                               stringify(final_entry),
                               stringify(target_final_entry))
                          << std::endl;
          all_match = false;
        }
      }

      if (raft->get_committed_seqno() != target_commit_idx)
      {
        RAFT_DRIVER_OUT << fmt::format(
                             "  Note over {}: Commit index {} doesn't "
                             "match commit index {} on {}",
                             node_id,
                             raft->get_committed_seqno(),
                             target_commit_idx,
                             target_id)
                        << std::endl;
        all_match = false;
      }
    }

    if (!all_match)
    {
      throw std::runtime_error(fmt::format(
        "States not in sync on line {}", std::to_string((int)lineno)));
    }
  }

  void assert_commit_idx(
    ccf::NodeId node_id, const std::string& idx_s, const size_t lineno)
  {
    auto idx = std::stol(idx_s);
    if (_nodes.at(node_id).raft->get_committed_seqno() != idx)
    {
      RAFT_DRIVER_OUT
        << fmt::format(
             "  Note over {}: Node is not at expected commit idx {}",
             node_id,
             idx)
        << std::endl;
      throw std::runtime_error(fmt::format(
        "Node not at expected commit idx on line {}",
        std::to_string((int)lineno)));
    }
  }
};
