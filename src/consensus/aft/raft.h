// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/logger.h"
#include "ds/serialized.h"
#include "ds/spin_lock.h"
#include "impl/aft_state.h"
#include "impl/execution_utilities.h"
#include "impl/request_message.h"
#include "impl/state_machine.h"
#include "kv/kv_types.h"
#include "kv/tx.h"
#include "node/node_types.h"
#include "node/rpc/tx_status.h"
#include "raft_types.h"

#include <algorithm>
#include <deque>
#include <list>
#include <random>
#include <unordered_map>
#include <vector>

namespace aft
{
  using Configuration = kv::Consensus::Configuration;

  std::unique_ptr<StateMachine> create_bft_state_machine(
    std::shared_ptr<ServiceState> service_state,
    std::shared_ptr<ccf::NodeToNode> channels,
    pbft::RequestsMap& requests_map,
    Store<kv::DeserialiseSuccess>& store,
    std::shared_ptr<enclave::RPCMap> rpc_map,
    const std::vector<uint8_t>& cert);

  template <class LedgerProxy, class ChannelProxy, class SnapshotterProxy>
  class Aft
  {
  private:
    enum State
    {
      Leader,
      Follower,
      Candidate,
      Retired
    };

    struct NodeState
    {
      Configuration::NodeInfo node_info;

      // the highest index sent to the node
      Index sent_idx;

      // the highest matching index with the node that was confirmed
      Index match_idx;

      NodeState() = default;

      NodeState(
        const Configuration::NodeInfo& node_info_,
        Index sent_idx_,
        Index match_idx_ = 0) :
        node_info(node_info_),
        sent_idx(sent_idx_),
        match_idx(match_idx_)
      {}
    };

    ConsensusType consensus_type;
    std::unique_ptr<Store<kv::DeserialiseSuccess>> store;
    std::unique_ptr<StateMachine> bft_state_machine;

    // Persistent
    NodeId voted_for;

    // Volatile
    NodeId leader_id;
    std::unordered_set<NodeId> votes_for_me;

    State state;
    std::chrono::milliseconds timeout_elapsed;

    // BFT
    pbft::RequestsMap& pbft_requests_map;
    std::shared_ptr<ServiceState> service_state;
    std::shared_ptr<ExecutionUtilities> execution_utilities;

    // Timeouts
    std::chrono::milliseconds request_timeout;
    std::chrono::milliseconds election_timeout;

    // Configurations
    std::list<Configuration> configurations;
    std::unordered_map<NodeId, NodeState> nodes;

    size_t entry_size_not_limited = 0;
    size_t entry_count = 0;
    Index entries_batch_size = 1;
    static constexpr int batch_window_size = 100;
    int batch_window_sum = 0;

    // Indices that are eligible for global commit, from a Node's perspective
    std::deque<Index> committable_indices;

    // When this is set, only public domain is deserialised when receving append
    // entries
    bool public_only = false;

    // Randomness
    std::uniform_int_distribution<int> distrib;
    std::default_random_engine rand;

  public:
    static constexpr size_t append_entries_size_limit = 20000;
    std::unique_ptr<LedgerProxy> ledger;
    std::shared_ptr<ccf::NodeToNode> channels;
    std::shared_ptr<SnapshotterProxy> snapshotter;
    std::shared_ptr<enclave::RPCSessions> rpc_sessions;
    std::shared_ptr<enclave::RPCMap> rpc_map;

  public:
    Aft(
      ConsensusType consensus_type_,
      std::unique_ptr<Store<kv::DeserialiseSuccess>> store_,
      std::unique_ptr<LedgerProxy> ledger_,
      std::shared_ptr<ccf::NodeToNode> channels_,
      std::shared_ptr<SnapshotterProxy> snapshotter_,
      std::shared_ptr<enclave::RPCSessions> rpc_sessions_,
      std::shared_ptr<enclave::RPCMap> rpc_map_,
      const std::vector<uint8_t>& /*cert*/,
      pbft::RequestsMap& requests_map,
      std::shared_ptr<aft::ServiceState> service_state_,
      std::shared_ptr<ExecutionUtilities> execution_utilities_,
      std::chrono::milliseconds request_timeout_,
      std::chrono::milliseconds election_timeout_,
      bool public_only_ = false) :
      consensus_type(consensus_type_),
      store(std::move(store_)),
      voted_for(NoNode),

      state(Follower),
      timeout_elapsed(0),

      pbft_requests_map(requests_map),
      service_state(service_state_),
      execution_utilities(execution_utilities_),

      request_timeout(request_timeout_),
      election_timeout(election_timeout_),
      public_only(public_only_),

      distrib(0, (int)election_timeout_.count() / 2),
      rand((int)(uintptr_t)this),

      ledger(std::move(ledger_)),
      channels(channels_),
      snapshotter(snapshotter_),
      rpc_sessions(rpc_sessions_),
      rpc_map(rpc_map_)

    {
      /*
            if (consensus_type == ConsensusType::PBFT)
            {
              leader_id = 0;
              bft_state_machine = create_bft_state_machine(
                service_state,
                channels_,
                requests_map,
                *store.get(),
                rpc_map_,
                cert);
            }
            else
      */
      {
        leader_id = NoNode;
        LOG_DEBUG_FMT("ZZZZZ leader is NoNode");
      }
    }

    NodeId leader()
    {
      return leader_id;
    }

    NodeId id()
    {
      return service_state->my_node_id;
    }

    bool is_leader()
    {
      return state == Leader;
    }

    bool is_follower()
    {
      return state == Follower;
    }

    void enable_all_domains()
    {
      // When receiving append entries as a follower, all security domains will
      // be deserialised
      std::lock_guard<SpinLock> guard(service_state->lock);
      public_only = false;
    }

    void force_become_leader()
    {
      // This is unsafe and should only be called when the node is certain
      // there is no leader and no other node will attempt to force leadership.
      if (leader_id != NoNode)
      {
        throw std::logic_error(
          "Can't force leadership if there is already a leader");
      }

      std::lock_guard<SpinLock> guard(service_state->lock);
      service_state->current_view += 2;
      become_leader();
    }

    void force_become_leader(Index index, Term term, Index commit_idx_)
    {
      // This is unsafe and should only be called when the node is certain
      // there is no leader and no other node will attempt to force leadership.
      if (leader_id != NoNode)
        throw std::logic_error(
          "Can't force leadership if there is already a leader");

      std::lock_guard<SpinLock> guard(service_state->lock);
      service_state->current_view = term;
      service_state->last_idx = index;
      service_state->commit_idx = commit_idx_;
      service_state->view_history.update(index, term);
      service_state->current_view += 2;
      become_leader();
    }

    void force_become_leader(
      Index index,
      Term term,
      const std::vector<Index>& terms,
      Index commit_idx_)
    {
      // This is unsafe and should only be called when the node is certain
      // there is no leader and no other node will attempt to force leadership.
      if (leader_id != NoNode)
        throw std::logic_error(
          "Can't force leadership if there is already a leader");
      std::lock_guard<SpinLock> guard(service_state->lock);
      service_state->current_view = term;
      service_state->last_idx = index;
      service_state->commit_idx = commit_idx_;
      service_state->view_history.initialise(terms);
      service_state->view_history.update(index, term);
      service_state->current_view += 2;
      become_leader();
    }

    void init_as_follower(Index index, Term term)
    {
      // This should only be called when the node resumes from a snapshot and
      // before it has received any append entries.
      std::lock_guard<SpinLock> guard(shared_state->lock);

      shared_state->last_idx = index;
      shared_state->commit_idx = index;

      shared_state->view_history.update(index, term);

      ledger->init(index);
      snapshotter->set_last_snapshot_idx(index);

      become_follower(term);
    }

    Index get_last_idx()
    {
      return service_state->last_idx;
    }

    Index get_commit_idx()
    {
      if (consensus_type == ConsensusType::PBFT && is_follower())
      {
        return service_state->commit_idx;
      }
      std::lock_guard<SpinLock> guard(service_state->lock);
      return service_state->commit_idx;
    }

    Term get_term()
    {
      if (consensus_type == ConsensusType::PBFT && is_follower())
      {
        return service_state->current_view;
      }
      std::lock_guard<SpinLock> guard(service_state->lock);
      return service_state->current_view;
    }

    std::pair<Term, Index> get_commit_term_and_idx()
    {
      std::lock_guard<SpinLock> guard(service_state->lock);
      return {get_term_internal(service_state->commit_idx), service_state->commit_idx};
    }

    Term get_term(Index idx)
    {
      if (consensus_type == ConsensusType::PBFT && is_follower())
      {
        return get_term_internal(idx);
      }
      std::lock_guard<SpinLock> guard(service_state->lock);
      return get_term_internal(idx);
    }

    // TODO: this needs to be moved to the bft state machine
    void add_configuration(Index idx, const Configuration::Nodes& conf)
    {
      /*
      if (consensus_type == ConsensusType::PBFT)
      {
        if (conf.size() != 1)
        {
          throw std::logic_error(
            "PBFT configuration should add one node at a time");
        }

        auto new_node_id = conf.begin()->first;
        auto new_node_info = conf.begin()->second;

        if (new_node_id == service_state->my_node_id)
        {
          return;
        }

        bft_state_machine->add_node(new_node_id, new_node_info.cert.raw());
        return;
      }
      */

      // This should only be called when the spin lock is held.
      configurations.push_back({idx, std::move(conf)});
      create_and_remove_node_state();
    }

    Configuration::Nodes get_latest_configuration() const
    {
      if (configurations.empty())
      {
        return {};
      }

      return configurations.back().nodes;
    }

    template <typename T>
    bool replicate(
      const std::vector<std::tuple<Index, T, bool>>& entries, Term term)
    {
      if (consensus_type == ConsensusType::PBFT && is_follower())
      {
        for (auto& [index, data, globally_committable] : entries)
        {
          ledger->put_entry(*data, globally_committable, false);
        }
        return true;
      }

      std::lock_guard<SpinLock> guard(service_state->lock);

/*
      if (state != Leader)
      {
        LOG_FAIL_FMT(
          "Failed to replicate {} items: not leader", entries.size());
        rollback(service_state->last_idx);
        return false;
      }
*/

      if (term != service_state->current_view)
      {
        LOG_FAIL_FMT(
          "Failed to replicate {} items at term {}, current term is {}",
          entries.size(),
          term,
          service_state->current_view);
        return false;
      }

      LOG_DEBUG_FMT("Replicating {} entries", entries.size());

      for (auto& [index, data, is_globally_committable] : entries)
      {
        bool globally_committable =
          is_globally_committable || consensus_type == ConsensusType::PBFT;

        if (index != service_state->last_idx + 1)
          return false;

        LOG_DEBUG_FMT(
          "Replicated on leader {}: {}{}",
          service_state->my_node_id,
          index,
          (globally_committable ? " committable" : ""));

        bool force_ledger_chunk = false;
        if (globally_committable)
        {
          committable_indices.push_back(index);

          // Only if globally committable, a snapshot requires a new ledger
          // chunk to be created
          force_ledger_chunk = snapshotter->requires_snapshot(index);
        }

        service_state->last_idx = index;
        ledger->put_entry(*data, globally_committable, force_ledger_chunk);
        entry_size_not_limited += data->size();
        entry_count++;

        service_state->view_history.update(index, service_state->current_view);
        if (entry_size_not_limited >= append_entries_size_limit)
        {
          update_batch_size();
          entry_count = 0;
          entry_size_not_limited = 0;
          for (const auto& it : nodes)
          {
            LOG_DEBUG_FMT("Sending updates to follower {}", it.first);
            send_append_entries(it.first, it.second.sent_idx + 1);
          }
        }
      }

      // If we are the only node, attempt to commit immediately.
      if (nodes.size() == 0)
      {
        update_commit();
      }

      return true;
    }
    void recv_message(const uint8_t* data, size_t size)
    {
      recv_message(OArray({data, data + size}));
    }

    void recv_message(OArray&& d)
    {
      const uint8_t* data = d.data();
      size_t size = d.size();
      // The host does a CALLIN to this when a Aft message
      // is received. Invalid or malformed messages are ignored
      // without informing the host. Messages are idempotent,
      // so it is not necessary to defend against replay attacks.
      switch (serialized::peek<RaftMsgType>(data, size))
      {
        case raft_append_entries:
          recv_append_entries(data, size);
          break;

        case raft_append_entries_response:
          recv_append_entries_response(data, size);
          break;

        case raft_request_vote:
          recv_request_vote(data, size);
          break;

        case raft_request_vote_response:
          recv_request_vote_response(data, size);
          break;

        default:
          bft_state_machine->receive_message(std::move(d));
          break;
      }
    }

    void periodic(std::chrono::milliseconds elapsed)
    {
      std::lock_guard<SpinLock> guard(service_state->lock);
      timeout_elapsed += elapsed;

      if (state == Leader)
      {
        if (timeout_elapsed >= request_timeout)
        {
          using namespace std::chrono_literals;
          timeout_elapsed = 0ms;

          update_batch_size();
          // Send newly available entries to all nodes.
          for (const auto& it : nodes)
          {
            send_append_entries(it.first, it.second.sent_idx + 1);
          }
        }
      }
      else
      {
        if (state != Retired && timeout_elapsed >= election_timeout)
        {
          // Start an election.
          become_candidate();
        }
      }
    }

    bool is_first_request = true;

    bool on_request(const kv::TxHistory::RequestCallbackArgs& args)
    {
      auto request = execution_utilities->create_request_message(args);
      /*
      bft_state_machine->receive_request(std::move(request));
      return true;
      */

      /*kv::Version version = */execution_utilities->execute_request(std::move(request), is_first_request);
      is_first_request = false;

      /*
      store->compact(version);
      {
        std::lock_guard<SpinLock> guard(service_state->lock);
        if (version > service_state->commit_idx)
        {
          service_state->commit_idx = version;
          service_state->last_idx = version;
        }
      }
      */
      return true;
    }

  private:
    inline void update_batch_size()
    {
      auto avg_entry_size = (entry_count == 0) ?
        append_entries_size_limit :
        entry_size_not_limited / entry_count;

      auto batch_size = (avg_entry_size == 0) ?
        append_entries_size_limit / 2 :
        append_entries_size_limit / avg_entry_size;

      auto batch_avg = batch_window_sum / batch_window_size;
      // balance out total batch size across batch window
      batch_window_sum += (batch_size - batch_avg);
      entries_batch_size = std::max((batch_window_sum / batch_window_size), 1);
    }

    Term get_term_internal(Index idx)
    {
      if (idx > service_state->last_idx)
        return ccf::VIEW_UNKNOWN;

      return service_state->view_history.term_at(idx);
    }

    void send_append_entries(NodeId to, Index start_idx)
    {
      Index end_idx = (service_state->last_idx == 0) ?
        0 :
        std::min(start_idx + entries_batch_size, service_state->last_idx);

      for (Index i = end_idx; i < service_state->last_idx; i += entries_batch_size)
      {
        send_append_entries_range(to, start_idx, i);
        start_idx = std::min(i + 1, service_state->last_idx);
      }

      if (service_state->last_idx == 0 || end_idx <= service_state->last_idx)
      {
        send_append_entries_range(to, start_idx, service_state->last_idx);
      }
    }

    void send_append_entries_range(NodeId to, Index start_idx, Index end_idx)
    {
      const auto prev_idx = start_idx - 1;
      const auto prev_term = get_term_internal(prev_idx);
      const auto term_of_idx = get_term_internal(end_idx);

      LOG_DEBUG_FMT(
        "Send append entries from {} to {}: {} to {} ({}), prev_term {}",
        service_state->my_node_id,
        to,
        start_idx,
        end_idx,
        service_state->commit_idx,
        prev_term);

      AppendEntries ae = {{raft_append_entries, service_state->my_node_id},
                          {end_idx, prev_idx},
                          service_state->current_view,
                          prev_term,
                          service_state->commit_idx,
                          term_of_idx};

      auto& node = nodes.at(to);

      // The host will append log entries to this message when it is
      // sent to the destination node.
      if (!channels->send_authenticated(
            ccf::NodeMsgType::consensus_msg, to, ae))
      {
        return;
      }

      // Record the most recent index we have sent to this node.
      node.sent_idx = end_idx;
    }

    void recv_append_entries(const uint8_t* data, size_t size)
    {
      std::lock_guard<SpinLock> guard(service_state->lock);
      AppendEntries r;
      bool is_first_entry = true; // Indicates first entry in batch

      try
      {
        r = channels->template recv_authenticated<AppendEntries>(data, size);
      }
      catch (const std::logic_error& err)
      {
        LOG_FAIL_FMT(err.what());
        return;
      }

      LOG_DEBUG_FMT(
        "Received pt: {} pi: {} t: {} i: {}",
        r.prev_term,
        r.prev_idx,
        r.term,
        r.idx);

      // Don't check that the sender node ID is valid. Accept anything that
      // passes the integrity check. This way, entries containing dynamic
      // topology changes that include adding this new leader can be accepted.

      if (service_state->current_view == r.term && state == Candidate)
      {
        // Become a follower in this term.
        become_follower(r.term);
      }
      else if (service_state->current_view < r.term)
      {
        // Become a follower in the new term.
        become_follower(r.term);
      }
      else if (service_state->current_view > r.term)
      {
        // Reply false, since our term is later than the received term.
        LOG_DEBUG_FMT(
          "Recv append entries to {} from {} but our term is later ({} > {})",
          service_state->my_node_id,
          r.from_node,
          service_state->current_view,
          r.term);
        send_append_entries_response(r.from_node, false);
        return;
      }

      const auto prev_term = get_term_internal(r.prev_idx);

      if (prev_term != r.prev_term)
      {
        LOG_DEBUG_FMT(
          "Previous term for {} should be {}", r.prev_idx, prev_term);

        // Reply false if the log doesn't contain an entry at r.prev_idx
        // whose term is r.prev_term.
        if (prev_term == 0)
        {
          LOG_DEBUG_FMT(
            "Recv append entries to {} from {} but our log does not yet "
            "contain index {}",
            service_state->my_node_id,
            r.from_node,
            r.prev_idx);
        }
        else
        {
          LOG_DEBUG_FMT(
            "Recv append entries to {} from {} but our log at {} has the wrong "
            "term (ours: {}, theirs: {})",
            service_state->my_node_id,
            r.from_node,
            r.prev_idx,
            prev_term,
            r.prev_term);
        }
        send_append_entries_response(r.from_node, false);
        return;
      }

      restart_election_timeout();

      if (r.prev_idx < service_state->commit_idx)
      {
        LOG_DEBUG_FMT(
          "Recv append entries to {} from {} but prev_idx ({}) < commit_idx "
          "({})",
          service_state->my_node_id,
          r.from_node,
          r.prev_idx,
          service_state->commit_idx);
        return;
      }

      LOG_DEBUG_FMT(
        "Recv append entries to {} from {} for index {} and previous index {}",
        service_state->my_node_id,
        r.from_node,
        r.idx,
        r.prev_idx);

      for (Index i = r.prev_idx + 1; i <= r.idx; i++)
      {
        if (i <= service_state->last_idx)
        {
          // If the current entry has already been deserialised, skip the
          // payload for that entry
          ledger->skip_entry(data, size);
          continue;
        }

        LOG_DEBUG_FMT("Replicating on follower {}: {}", service_state->my_node_id, i);

        service_state->last_idx = i;
        is_first_entry = false;
        std::vector<uint8_t> entry;

        try
        {
          entry = ledger->get_entry(data, size);
        }
        catch (const std::logic_error& e)
        {
          // This should only fail if there is malformed data.
          LOG_FAIL_FMT(
            "Recv append entries to {} from {} but the data is malformed: {}",
            service_state->my_node_id,
            r.from_node,
            e.what());
          service_state->last_idx = r.prev_idx;
          send_append_entries_response(r.from_node, false);
          return;
        }

        Term sig_term = 0;
        kv::Tx tx;
        kv::DeserialiseSuccess deserialise_success;
        if (consensus_type == ConsensusType::PBFT)
        {
          deserialise_success =
            store->deserialise_views(entry, public_only, &sig_term, &tx);
        }
        else
        {
          deserialise_success =
            store->deserialise(entry, public_only, &sig_term);
        }

        bool globally_committable =
          (deserialise_success == kv::DeserialiseSuccess::PASS_SIGNATURE);
        bool force_ledger_chunk = false;
        if (globally_committable)
        {
          force_ledger_chunk = snapshotter->requires_snapshot(i);
        }

        ledger->put_entry(entry, globally_committable, force_ledger_chunk);

        switch (deserialise_success)
        {
          case kv::DeserialiseSuccess::FAILED:
          {
            throw std::logic_error(
              "Follower failed to apply log entry " + std::to_string(i));
            break;
          }

          case kv::DeserialiseSuccess::PASS_SIGNATURE:
          {
            LOG_DEBUG_FMT("Deserialising signature at {}", i);
            committable_indices.push_back(i);

            if (sig_term)
            {
              service_state->view_history.update(service_state->commit_idx + 1, sig_term);
              commit_if_possible(r.leader_commit_idx);
            }
            break;
          }

          case kv::DeserialiseSuccess::PASS:
          {
            if (consensus_type != ConsensusType::PBFT)
            {
              return;
            }
            //CCF_ASSERT(consensus_type == ConsensusType::PBFT, "wrong consensus type");
            LOG_INFO_FMT("AAAAAAAAAAA, primary {}", leader_id);
            service_state->last_idx = execution_utilities->commit_replayed_request(tx);
            LOG_INFO_FMT("BBBBBBBBBBB");
            // Update the current leader because we accepted entries.
            /*
            if (leader_id != r.from_node)
            {
              leader_id = r.from_node;
              LOG_DEBUG_FMT(
                "ZZZZZ Node {} thinks leader is {}",
                service_state->my_node_id,
                leader_id);
            }

            send_append_entries_response(r.from_node, true);
            LOG_INFO_FMT("CCCCCCCCCCC");
            return;*/
            break;
          }

          default:
          {
            throw std::logic_error("Unknown DeserialiseSuccess value");
          }
        }
      }

      // Update the current leader because we accepted entries.
      if (leader_id != r.from_node)
      {
        leader_id = r.from_node;
        LOG_DEBUG_FMT("ZZZZZ Node {} thinks leader is {}", service_state->my_node_id, leader_id);
      }

      send_append_entries_response(r.from_node, true);
      if (consensus_type == ConsensusType::PBFT && is_follower())
      {
        LOG_INFO_FMT("CCCCCCCCCCC");
        store->compact(service_state->last_idx);
        LOG_INFO_FMT("DDDDDDDDDDD");
      }
      else
      {
        commit_if_possible(r.leader_commit_idx);
      }

      service_state->view_history.update(service_state->commit_idx + 1, r.term_of_idx);
    }

    void send_append_entries_response(NodeId to, bool answer)
    {
      LOG_DEBUG_FMT(
        "Send append entries response from {} to {} for index {}: {}",
        service_state->my_node_id,
        to,
        service_state->last_idx,
        answer);

      AppendEntriesResponse response = {
        {raft_append_entries_response, service_state->my_node_id},
        service_state->current_view,
        service_state->last_idx,
        answer};

      channels->send_authenticated(
        ccf::NodeMsgType::consensus_msg, to, response);
    }

    void recv_append_entries_response(const uint8_t* data, size_t size)
    {
      std::lock_guard<SpinLock> guard(service_state->lock);
      // Ignore if we're not the leader.
      if (state != Leader)
        return;

      AppendEntriesResponse r;

      try
      {
        r = channels->template recv_authenticated<AppendEntriesResponse>(
          data, size);
      }
      catch (const std::logic_error& err)
      {
        LOG_FAIL_FMT(err.what());
        return;
      }

      auto node = nodes.find(r.from_node);
      if (node == nodes.end())
      {
        // Ignore if we don't recognise the node.
        LOG_FAIL_FMT(
          "Recv append entries response to {} from {}: unknown node",
          service_state->my_node_id,
          r.from_node);
        return;
      }
      else if (service_state->current_view < r.term)
      {
        // We are behind, convert to a follower.
        LOG_DEBUG_FMT(
          "Recv append entries response to {} from {}: more recent term",
          service_state->my_node_id,
          r.from_node);
        become_follower(r.term);
        return;
      }
      else if (service_state->current_view != r.term)
      {
        // Stale response, discard if success.
        // Otherwise reset sent_idx and try again.
        LOG_DEBUG_FMT(
          "Recv append entries response to {} from {}: stale term",
          service_state->my_node_id,
          r.from_node);
        if (r.success)
          return;
      }
      else if (r.last_log_idx < node->second.match_idx)
      {
        // Stale response, discard if success.
        // Otherwise reset sent_idx and try again.
        LOG_DEBUG_FMT(
          "Recv append entries response to {} from {}: stale idx",
          service_state->my_node_id,
          r.from_node);
        if (r.success)
          return;
      }

      // Update next and match for the responding node.
      node->second.match_idx = std::min(r.last_log_idx, service_state->last_idx);

      if (!r.success)
      {
        // Failed due to log inconsistency. Reset sent_idx and try again.
        LOG_DEBUG_FMT(
          "Recv append entries response to {} from {}: failed",
          service_state->my_node_id,
          r.from_node);
        send_append_entries(r.from_node, node->second.match_idx + 1);
        return;
      }

      LOG_DEBUG_FMT(
        "Recv append entries response to {} from {} for index {}: success",
        service_state->my_node_id,
        r.from_node,
        r.last_log_idx);
      update_commit();
    }

    void send_request_vote(NodeId to)
    {
      LOG_INFO_FMT("Send request vote from {} to {}", service_state->my_node_id, to);

      RequestVote rv = {{raft_request_vote, service_state->my_node_id},
                        service_state->current_view,
                        service_state->commit_idx,
                        get_term_internal(service_state->commit_idx)};

      channels->send_authenticated(ccf::NodeMsgType::consensus_msg, to, rv);
    }

    void recv_request_vote(const uint8_t* data, size_t size)
    {
      std::lock_guard<SpinLock> guard(service_state->lock);
      RequestVote r;

      try
      {
        r = channels->template recv_authenticated<RequestVote>(data, size);
      }
      catch (const std::logic_error& err)
      {
        LOG_FAIL_FMT(err.what());
        return;
      }

      // Ignore if we don't recognise the node.
      auto node = nodes.find(r.from_node);
      if (node == nodes.end())
      {
        LOG_FAIL_FMT(
          "Recv request vote to {} from {}: unknown node",
          service_state->my_node_id,
          r.from_node);
        return;
      }

      if (service_state->current_view > r.term)
      {
        // Reply false, since our term is later than the received term.
        LOG_DEBUG_FMT(
          "Recv request vote to {} from {}: our term is later ({} > {})",
          service_state->my_node_id,
          r.from_node,
          service_state->current_view,
          r.term);
        send_request_vote_response(r.from_node, false);
        return;
      }
      else if (service_state->current_view < r.term)
      {
        // Become a follower in the new term.
        LOG_DEBUG_FMT(
          "Recv request vote to {} from {}: their term is later ({} < {})",
          service_state->my_node_id,
          r.from_node,
          service_state->current_view,
          r.term);
        become_follower(r.term);
      }

      if ((voted_for != NoNode) && (voted_for != r.from_node))
      {
        // Reply false, since we already voted for someone else.
        LOG_DEBUG_FMT(
          "Recv request vote to {} from {}: already voted for {}",
          service_state->my_node_id,
          r.from_node,
          voted_for);
        send_request_vote_response(r.from_node, false);
        return;
      }

      // If the candidate's log is at least as up-to-date as ours, vote yes
      auto last_commit_term = get_term_internal(service_state->commit_idx);

      auto answer = (r.last_commit_term > last_commit_term) ||
        ((r.last_commit_term == last_commit_term) &&
         (r.last_commit_idx >= service_state->commit_idx));

      if (answer)
      {
        // If we grant our vote, we also acknowledge that an election is in
        // progress.
        restart_election_timeout();
        leader_id = NoNode;
        LOG_DEBUG_FMT("ZZZZZ leader is NoNode");
        voted_for = r.from_node;
      }

      send_request_vote_response(r.from_node, answer);
    }

    void send_request_vote_response(NodeId to, bool answer)
    {
      LOG_INFO_FMT(
        "Send request vote response from {} to {}: {}", service_state->my_node_id, to, answer);

      RequestVoteResponse response = {
        {raft_request_vote_response, service_state->my_node_id}, service_state->current_view, answer};

      channels->send_authenticated(
        ccf::NodeMsgType::consensus_msg, to, response);
    }

    void recv_request_vote_response(const uint8_t* data, size_t size)
    {
      std::lock_guard<SpinLock> guard(service_state->lock);
      if (state != Candidate)
      {
        LOG_INFO_FMT(
          "Recv request vote response to {}: we aren't a candidate", service_state->my_node_id);
        return;
      }

      RequestVoteResponse r;

      try
      {
        r = channels->template recv_authenticated<RequestVoteResponse>(
          data, size);
      }
      catch (const std::logic_error& err)
      {
        LOG_FAIL_FMT(err.what());
        return;
      }

      // Ignore if we don't recognise the node.
      auto node = nodes.find(r.from_node);
      if (node == nodes.end())
      {
        LOG_INFO_FMT(
          "Recv request vote response to {} from {}: unknown node",
          service_state->my_node_id,
          r.from_node);
        return;
      }

      if (service_state->current_view < r.term)
      {
        // Become a follower in the new term.
        LOG_INFO_FMT(
          "Recv request vote response to {} from {}: their term is more recent "
          "({} < {})",
          service_state->my_node_id,
          r.from_node,
          service_state->current_view,
          r.term);
        become_follower(r.term);
        return;
      }
      else if (service_state->current_view != r.term)
      {
        // Ignore as it is stale.
        LOG_INFO_FMT(
          "Recv request vote response to {} from {}: stale ({} != {})",
          service_state->my_node_id,
          r.from_node,
          service_state->current_view,
          r.term);
        return;
      }
      else if (!r.vote_granted)
      {
        // Do nothing.
        LOG_INFO_FMT(
          "Recv request vote response to {} from {}: they voted no",
          service_state->my_node_id,
          r.from_node);
        return;
      }

      LOG_INFO_FMT(
        "Recv request vote response to {} from {}: they voted yes",
        service_state->my_node_id,
        r.from_node);
      add_vote_for_me(r.from_node);
    }

    void restart_election_timeout()
    {
      // Randomise timeout_elapsed to get a random election timeout
      // between 0.5x and 1x the configured election timeout.
      timeout_elapsed = std::chrono::milliseconds(distrib(rand));
    }

    void become_candidate()
    {
      state = Candidate;
      leader_id = NoNode;
      LOG_DEBUG_FMT("ZZZZZ leader is NoNode");
      voted_for = service_state->my_node_id;
      votes_for_me.clear();
      service_state->current_view++;

      restart_election_timeout();
      add_vote_for_me(service_state->my_node_id);

      LOG_INFO_FMT("Becoming candidate {}: {}", service_state->my_node_id, service_state->current_view);

      for (auto it = nodes.begin(); it != nodes.end(); ++it)
      {
        channels->create_channel(
          it->first, it->second.node_info.hostname, it->second.node_info.port);
        send_request_vote(it->first);
      }
    }

    void become_leader()
    {
      // Discard any un-committed updates we may hold,
      // since we have no signature for them. Except at startup,
      // where we do not want to roll back the genesis transaction.
      if (service_state->commit_idx)
      {
        rollback(service_state->commit_idx);
      }
      else
      {
        // but we still want the KV to know which term we're in
        store->set_term(service_state->current_view);
      }

      committable_indices.clear();
      state = Leader;
      leader_id = service_state->my_node_id;
      LOG_DEBUG_FMT("ZZZZZ leader is {}", leader_id);

      using namespace std::chrono_literals;
      timeout_elapsed = 0ms;

      LOG_INFO_FMT("Becoming leader {}: {}", service_state->my_node_id, service_state->current_view);

      // Immediately commit if there are no other nodes.
      if (nodes.size() == 0)
      {
        commit(service_state->last_idx);
        return;
      }

      // Reset next, match, and sent indices for all nodes.
      auto next = service_state->last_idx + 1;

      for (auto it = nodes.begin(); it != nodes.end(); ++it)
      {
        it->second.match_idx = 0;
        it->second.sent_idx = next - 1;

        // Send an empty append_entries to all nodes.
        send_append_entries(it->first, next);
      }
    }

    void become_follower(Term term)
    {
      state = Follower;
      leader_id = NoNode;
      LOG_DEBUG_FMT("ZZZZZ leader is NoNode");
      restart_election_timeout();

      service_state->current_view = term;
      voted_for = NoNode;
      votes_for_me.clear();

      // Rollback unreplicated commits.
      rollback(service_state->commit_idx);
      committable_indices.clear();

      LOG_INFO_FMT("Becoming follower {}: {}", service_state->my_node_id, service_state->current_view);
      channels->close_all_outgoing();
    }

    void become_retired()
    {
      state = Retired;
      leader_id = NoNode;

      LOG_INFO_FMT("Becoming retired {}: {}", service_state->my_node_id, service_state->current_view);
      channels->destroy_all_channels();
    }

    void add_vote_for_me(NodeId from)
    {
      // Need 50% + 1 of the total nodes, which are the other nodes plus us.
      votes_for_me.insert(from);

      if (votes_for_me.size() >= ((nodes.size() + 1) / 2) + 1)
        become_leader();
    }

    void update_commit()
    {
      // If there exists some idx in the current term such that
      // idx > commit_idx and a majority of nodes have replicated it,
      // commit to that idx.
      auto new_commit_idx = std::numeric_limits<Index>::max();

      for (auto& c : configurations)
      {
        // The majority must be checked separately for each active
        // configuration.
        std::vector<Index> match;
        match.reserve(c.nodes.size() + 1);

        for (auto node : c.nodes)
        {
          if (node.first == service_state->my_node_id)
          {
            match.push_back(service_state->last_idx);
          }
          else
          {
            match.push_back(nodes.at(node.first).match_idx);
          }
        }

        sort(match.begin(), match.end());
        auto confirmed = match.at((match.size() - 1) / 2);

        if (confirmed < new_commit_idx)
        {
          new_commit_idx = confirmed;
        }
      }

      LOG_DEBUG_FMT(
        "In update_commit, new_commit_idx: {}, last_idx: {}",
        new_commit_idx,
        service_state->last_idx);

      if (new_commit_idx > service_state->last_idx)
      {
        throw std::logic_error(
          "Followers appear to have later match indices than leader");
      }

      commit_if_possible(new_commit_idx);
    }

    void commit_if_possible(Index idx)
    {
      if ((idx > service_state->commit_idx) && (get_term_internal(idx) <= service_state->current_view))
      {
        Index highest_committable = 0;
        bool can_commit = false;
        while (!committable_indices.empty() &&
               (committable_indices.front() <= idx))
        {
          highest_committable = committable_indices.front();
          committable_indices.pop_front();
          can_commit = true;
        }

        if (can_commit)
          commit(highest_committable);
      }
    }

    void commit(Index idx)
    {
      if (idx > service_state->last_idx)
        throw std::logic_error(
          "Tried to commit " + std::to_string(idx) + "but last_idx as " +
          std::to_string(service_state->last_idx));

      LOG_DEBUG_FMT("Starting commit");

      // This could happen if a follower becomes the leader when it
      // has committed fewer log entries, although it has them available.
      if (idx <= service_state->commit_idx)
        return;

      service_state->commit_idx = idx;

      LOG_DEBUG_FMT("Compacting...");
      snapshotter->compact(idx);
      if (state == Leader)
      {
        snapshotter->snapshot(idx);
      }
      store->compact(idx);
      ledger->commit(idx);

      LOG_DEBUG_FMT("Commit on {}: {}", service_state->my_node_id, idx);

      // Examine all configurations that are followed by a globally committed
      // configuration.
      bool changed = false;

      while (true)
      {
        auto conf = configurations.begin();
        if (conf == configurations.end())
          break;

        auto next = std::next(conf);
        if (next == configurations.end())
          break;

        if (idx < next->idx)
          break;

        configurations.pop_front();
        changed = true;
      }

      if (changed)
      {
        create_and_remove_node_state();
      }
    }

    void rollback(Index idx)
    {
      snapshotter->rollback(idx);
      store->rollback(idx, service_state->current_view);
      LOG_DEBUG_FMT("Setting term in store to: {}", service_state->current_view);
      ledger->truncate(idx);
      service_state->last_idx = idx;
      LOG_DEBUG_FMT("Rolled back at {}", idx);

      while (!committable_indices.empty() && (committable_indices.back() > idx))
      {
        committable_indices.pop_back();
      }

      // Rollback configurations.
      bool changed = false;

      while (!configurations.empty() && (configurations.back().idx > idx))
      {
        configurations.pop_back();
        changed = true;
      }

      if (changed)
      {
        create_and_remove_node_state();
      }
    }

    void create_and_remove_node_state()
    {
      // Find all nodes present in any active configuration.
      Configuration::Nodes active_nodes;

      for (auto& conf : configurations)
      {
        for (auto node : conf.nodes)
        {
          active_nodes.emplace(node.first, node.second);
        }
      }

      // Remove all nodes in the node state that are not present in any active
      // configuration.
      std::vector<NodeId> to_remove;

      for (auto& node : nodes)
      {
        if (active_nodes.find(node.first) == active_nodes.end())
        {
          to_remove.push_back(node.first);
        }
      }

      for (auto node_id : to_remove)
      {
        if (state == Leader)
        {
          channels->destroy_channel(node_id);
        }
        nodes.erase(node_id);
        LOG_INFO_FMT("Removed raft node {}", node_id);
      }

      // Add all active nodes that are not already present in the node state.
      bool self_is_active = false;

      for (auto node_info : active_nodes)
      {
        if (node_info.first == service_state->my_node_id)
        {
          self_is_active = true;
          continue;
        }

        if (nodes.find(node_info.first) == nodes.end())
        {
          // A new node is sent only future entries initially. If it does not
          // have prior data, it will communicate that back to the leader.
          auto index = service_state->last_idx + 1;
          nodes.try_emplace(node_info.first, node_info.second, index, 0);

          if (state == Leader)
          {
            channels->create_channel(
              node_info.first,
              node_info.second.hostname,
              node_info.second.port);

            send_append_entries(node_info.first, index);
          }

          LOG_INFO_FMT("Added raft node {}", node_info.first);
        }
      }

      if (!self_is_active)
      {
        LOG_INFO_FMT("Removed raft self {}", service_state->my_node_id);
        if (state == Leader)
        {
          become_retired();
        }
      }
    }

  };
}