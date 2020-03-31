// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/logger.h"
#include "ds/serialized.h"
#include "ds/spin_lock.h"
#include "kv/kv_types.h"
#include "node/nodetypes.h"
#include "raft_types.h"

#include <algorithm>
#include <deque>
#include <list>
#include <random>
#include <unordered_map>
#include <vector>

namespace raft
{
  class TermHistory
  {
    std::vector<Index> terms;

  public:
    void initialise(const std::vector<Index>& terms_)
    {
      std::copy(terms_.begin(), terms_.end(), std::back_inserter(terms));
    }

    void update(Index idx, Term term)
    {
      LOG_DEBUG_FMT("Updating term to: {} at index: {}", term, idx);
      for (auto i = terms.size(); i <= term; ++i)
        terms.push_back(idx);
    }

    Term term_at(Index idx)
    {
      if (idx == 0)
        return 0;

      auto it = upper_bound(terms.begin(), terms.end(), idx);
      return (it - terms.begin()) - 1;
    }
  };

  template <class LedgerProxy, class ChannelProxy>
  class Raft
  {
  private:
    enum State
    {
      Leader,
      Follower,
      Candidate
    };

    struct NodeState
    {
      // the highest matching index with the node that was confirmed
      Index match_idx;
      // the highest index sent to the node
      Index sent_idx;
    };

    struct Configuration
    {
      Index idx;
      std::unordered_set<NodeId> nodes;
    };

    SpinLock lock;
    std::unique_ptr<Store<kv::DeserialiseSuccess>> store;

    // Persistent
    Term current_term;
    NodeId local_id;
    NodeId voted_for;

    Index last_idx;
    Index commit_idx;
    TermHistory term_history;

    // Volatile
    NodeId leader_id;
    std::unordered_set<NodeId> votes_for_me;

    State state;
    std::chrono::milliseconds timeout_elapsed;

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

    // In recovery mode, while a follower is reading the private ledger, no
    // entries later than the index at which the network secrets are known
    // should be replicated
    std::optional<Index> recovery_max_index;

    // Randomness
    std::uniform_int_distribution<int> distrib;
    std::default_random_engine rand;

  public:
    static constexpr size_t append_entries_size_limit = 20000;
    std::unique_ptr<LedgerProxy> ledger;
    std::shared_ptr<ChannelProxy> channels;

  public:
    Raft(
      std::unique_ptr<Store<kv::DeserialiseSuccess>> store,
      std::unique_ptr<LedgerProxy> ledger_,
      std::shared_ptr<ChannelProxy> channels_,
      NodeId id,
      std::chrono::milliseconds request_timeout_,
      std::chrono::milliseconds election_timeout_,
      bool public_only_ = false) :
      store(std::move(store)),

      current_term(0),
      local_id(id),
      voted_for(NoNode),
      last_idx(0),
      commit_idx(0),

      leader_id(NoNode),

      state(Follower),
      timeout_elapsed(0),

      request_timeout(request_timeout_),
      election_timeout(election_timeout_),
      public_only(public_only_),

      ledger(std::move(ledger_)),
      channels(channels_),

      distrib(0, (int)election_timeout_.count() / 2),
      rand((int)(uintptr_t)this)
    {}

    NodeId leader()
    {
      return leader_id;
    }

    NodeId id()
    {
      return local_id;
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
      std::lock_guard<SpinLock> guard(lock);
      public_only = false;
    }

    void suspend_replication(Index idx)
    {
      // Suspend replication of append entries up to a specific version
      // Note that this should only be called when the raft lock is taken (e.g.
      // from a commit hook on a follower)
      LOG_INFO_FMT("Suspending replication for idx > {}", idx);
      recovery_max_index = idx;
    }

    void resume_replication()
    {
      // Resume replication.
      // Note that this should be called when the raft lock is not taken (e.g.
      // after the ledger has been read)
      std::lock_guard<SpinLock> guard(lock);
      LOG_INFO_FMT("Resuming replication");
      recovery_max_index.reset();
    }

    void force_become_leader()
    {
      // This is unsafe and should only be called when the node is certain
      // there is no leader and no other node will attempt to force leadership.
      if (leader_id != NoNode)
        throw std::logic_error(
          "Can't force leadership if there is already a leader");

      std::lock_guard<SpinLock> guard(lock);
      current_term += 2;
      become_leader();
    }

    void force_become_leader(Index index, Term term, Index commit_idx_)
    {
      // This is unsafe and should only be called when the node is certain
      // there is no leader and no other node will attempt to force leadership.
      if (leader_id != NoNode)
        throw std::logic_error(
          "Can't force leadership if there is already a leader");

      std::lock_guard<SpinLock> guard(lock);
      current_term = term;
      last_idx = index;
      commit_idx = commit_idx_;
      term_history.update(index, term);
      current_term += 2;
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
      std::lock_guard<SpinLock> guard(lock);
      current_term = term;
      last_idx = index;
      commit_idx = commit_idx_;
      term_history.initialise(terms);
      term_history.update(index, term);
      current_term += 2;
      become_leader();
    }

    Index get_last_idx()
    {
      return last_idx;
    }

    Index get_commit_idx()
    {
      std::lock_guard<SpinLock> guard(lock);
      return commit_idx;
    }

    Term get_term()
    {
      std::lock_guard<SpinLock> guard(lock);
      return current_term;
    }

    Term get_term(Index idx)
    {
      std::lock_guard<SpinLock> guard(lock);
      return get_term_internal(idx);
    }

    void add_configuration(Index idx, std::unordered_set<NodeId> conf)
    {
      // This should only be called when the spin lock is held.
      configurations.push_back({idx, move(conf)});
      create_and_remove_node_state();
    }

    template <typename T>
    size_t write_to_ledger(const T& data)
    {
      ledger->put_entry(data->data(), data->size());
      return data->size();
    }

    template <>
    size_t write_to_ledger<std::vector<uint8_t>>(
      const std::vector<uint8_t>& data)
    {
      ledger->put_entry(data);
      return data.size();
    }

    template <typename T>
    bool replicate(const std::vector<std::tuple<Index, T, bool>>& entries)
    {
      std::lock_guard<SpinLock> guard(lock);

      if (state != Leader)
      {
        LOG_FAIL_FMT(
          "Failed to replicate {} items: not leader", entries.size());
        rollback(last_idx);
        return false;
      }

      LOG_DEBUG_FMT("Replicating {} entries", entries.size());

      for (auto& [index, data, globally_committable] : entries)
      {
        if (index != last_idx + 1)
          return false;

        LOG_DEBUG_FMT(
          "Replicated on leader {}: {}{}",
          local_id,
          index,
          (globally_committable ? " committable" : ""));

        if (globally_committable)
          committable_indices.push_back(index);

        last_idx = index;
        auto s = write_to_ledger(*data);
        entry_size_not_limited += s;
        entry_count++;

        term_history.update(index, current_term);
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
      std::lock_guard<SpinLock> guard(lock);

      // The host does a CALLIN to this when a Raft message
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
        {}
      }
    }

    void periodic(std::chrono::milliseconds elapsed)
    {
      std::lock_guard<SpinLock> guard(lock);
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
        if (timeout_elapsed >= election_timeout)
        {
          // Start an election.
          become_candidate();
        }
      }
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
      if (idx > last_idx)
        return 0;

      return term_history.term_at(idx);
    }

    void send_append_entries(NodeId to, Index start_idx)
    {
      Index end_idx = (last_idx == 0) ?
        0 :
        std::min(start_idx + entries_batch_size, last_idx);

      for (Index i = end_idx; i < last_idx; i += entries_batch_size)
      {
        send_append_entries_range(to, start_idx, i);
        start_idx = std::min(i + 1, last_idx);
      }

      if (last_idx == 0 || end_idx <= last_idx)
      {
        send_append_entries_range(to, start_idx, last_idx);
      }
    }

    void send_append_entries_range(NodeId to, Index start_idx, Index end_idx)
    {
      const auto prev_idx = start_idx - 1;
      const auto prev_term = get_term_internal(prev_idx);
      const auto term_of_idx = get_term_internal(end_idx);

      LOG_DEBUG_FMT(
        "Send append entries from {} to {}: {} to {} ({})",
        local_id,
        to,
        start_idx,
        end_idx,
        commit_idx);

      AppendEntries ae = {raft_append_entries,
                          local_id,
                          end_idx,
                          prev_idx,
                          current_term,
                          prev_term,
                          commit_idx,
                          term_of_idx};

      auto& node = nodes.at(to);

      // Record the most recent index we have sent to this node.
      node.sent_idx = end_idx;

      // The host will append log entries to this message when it is
      // sent to the destination node.
      channels->send_authenticated(ccf::NodeMsgType::consensus_msg, to, ae);
    }

    void recv_append_entries(const uint8_t* data, size_t size)
    {
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

      const auto prev_term = get_term_internal(r.prev_idx);
      LOG_DEBUG_FMT("Previous term for {} should be {}", r.prev_idx, prev_term);

      // Don't check that the sender node ID is valid. Accept anything that
      // passes the integrity check. This way, entries containing dynamic
      // topology changes that include adding this new leader can be accepted.
      if (r.prev_idx < commit_idx)
      {
        LOG_DEBUG_FMT(
          "Recv append entries to {} from {} but prev_idex ({}) < commit_idx "
          "({})",
          local_id,
          r.from_node,
          r.prev_idx,
          commit_idx);
        return;
      }

      restart_election_timeout();

      if (current_term == r.term && state == Candidate)
      {
        // Become a follower in this term.
        become_follower(r.term);
      }
      else if (current_term < r.term)
      {
        // Become a follower in the new term.
        become_follower(r.term);
      }
      else if (current_term > r.term)
      {
        // Reply false, since our term is later than the received term.
        LOG_DEBUG_FMT(
          "Recv append entries to {} from {} but our term is later ({} > {})",
          local_id,
          r.from_node,
          current_term,
          r.term);
        send_append_entries_response(r.from_node, false);
        return;
      }

      if (prev_term != r.prev_term)
      {
        // Reply false if the log doesn't contain an entry at r.prev_idx
        // whose term is r.prev_term.
        if (prev_term == 0)
        {
          LOG_DEBUG_FMT(
            "Recv append entries to {} from {} but our log does not yet "
            "contain index {}",
            local_id,
            r.from_node,
            r.prev_idx);
        }
        else
        {
          LOG_DEBUG_FMT(
            "Recv append entries to {} from {} but our log at {} has the wrong "
            "term (ours: {}, theirs: {})",
            local_id,
            r.from_node,
            r.prev_idx,
            prev_term,
            r.prev_term);
        }
        send_append_entries_response(r.from_node, false);
        return;
      }

      LOG_DEBUG_FMT(
        "Recv append entries to {} from {} for index {} and previous index {}",
        local_id,
        r.from_node,
        r.idx,
        r.prev_idx);

      for (Index i = r.prev_idx + 1; i <= r.idx; i++)
      {
        if (i <= last_idx)
        {
          // If the current entry has already been deserialised, skip the
          // payload for that entry
          ledger->skip_entry(data, size);
          continue;
        }

        LOG_DEBUG_FMT("Replicating on follower {}: {}", local_id, i);

        // If replication is suspended during recovery, only accept entries if
        // their index is less than the max recovery index
        if (recovery_max_index.has_value() && i > recovery_max_index.value())
        {
          if (is_first_entry)
          {
            // If no entry was replicated in the batch, abort replication of the
            // whole batch
            LOG_INFO_FMT(
              "Replication suspended: {} > {}", i, recovery_max_index.value());
            send_append_entries_response(r.from_node, false);
            return;
          }
          else
          {
            // If an entry was successfully replicated in the batch, deserialise
            // up to that entry
            LOG_INFO_FMT(
              "Replication suspended up to {} but deserialised up to {}",
              recovery_max_index.value(),
              i - 1);
            send_append_entries_response(r.from_node, true);
            return;
          }
        }

        last_idx = i;
        is_first_entry = false;
        auto ret = ledger->record_entry(data, size);

        if (!ret.second)
        {
          // NB: This will currently never be triggered.
          // This should only fail if there is malformed data. Truncate
          // the log and reply false.
          LOG_FAIL_FMT(
            "Recv append entries to {} from {} but the data is malformed",
            local_id,
            r.from_node);

          last_idx = r.prev_idx;
          ledger->truncate(r.prev_idx);
          send_append_entries_response(r.from_node, false);
          return;
        }

        Term sig_term = 0;
        auto deserialise_success =
          store->deserialise(ret.first, public_only, &sig_term);

        switch (deserialise_success)
        {
          case kv::DeserialiseSuccess::FAILED:
            throw std::logic_error(
              "Follower failed to apply log entry " + std::to_string(i));
            break;

          case kv::DeserialiseSuccess::PASS_SIGNATURE:
            LOG_DEBUG_FMT("Deserialising signature at {}", i);
            committable_indices.push_back(i);
            if (sig_term)
              term_history.update(commit_idx + 1, sig_term);
            break;

          case kv::DeserialiseSuccess::PASS:
            break;

          default:
            throw std::logic_error("Unknown DeserialiseSuccess value");
        }
      }

      // Update the current leader because we accepted entries.
      if (leader_id != r.from_node)
      {
        leader_id = r.from_node;
        LOG_DEBUG_FMT("Node {} thinks leader is {}", local_id, leader_id);
      }

      send_append_entries_response(r.from_node, true);
      commit_if_possible(r.leader_commit_idx);

      term_history.update(commit_idx + 1, r.term_of_idx);
    }

    void send_append_entries_response(NodeId to, bool answer)
    {
      LOG_DEBUG_FMT(
        "Send append entries response from {} to {} for index {}: {}",
        local_id,
        to,
        last_idx,
        answer);

      AppendEntriesResponse response = {
        raft_append_entries_response, local_id, current_term, last_idx, answer};

      channels->send_authenticated(
        ccf::NodeMsgType::consensus_msg, to, response);
    }

    void recv_append_entries_response(const uint8_t* data, size_t size)
    {
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
          local_id,
          r.from_node);
        return;
      }
      else if (current_term < r.term)
      {
        // We are behind, convert to a follower.
        LOG_DEBUG_FMT(
          "Recv append entries response to {} from {}: more recent term",
          local_id,
          r.from_node);
        become_follower(r.term);
        return;
      }
      else if (current_term != r.term)
      {
        // Stale response, discard if success.
        // Otherwise reset sent_idx and try again.
        LOG_DEBUG_FMT(
          "Recv append entries response to {} from {}: stale term",
          local_id,
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
          local_id,
          r.from_node);
        if (r.success)
          return;
      }

      // Update next and match for the responding node.
      node->second.match_idx = std::min(r.last_log_idx, last_idx);

      if (!r.success)
      {
        // Failed due to log inconsistency. Reset sent_idx and try again.
        LOG_DEBUG_FMT(
          "Recv append entries response to {} from {}: failed",
          local_id,
          r.from_node);
        send_append_entries(r.from_node, node->second.match_idx + 1);
        return;
      }

      LOG_DEBUG_FMT(
        "Recv append entries response to {} from {} for index {}: success",
        local_id,
        r.from_node,
        r.last_log_idx);
      update_commit();
    }

    void send_request_vote(NodeId to)
    {
      LOG_INFO_FMT("Send request vote from {} to {}", local_id, to);

      RequestVote rv = {raft_request_vote,
                        local_id,
                        current_term,
                        commit_idx,
                        get_term_internal(commit_idx)};

      channels->send_authenticated(ccf::NodeMsgType::consensus_msg, to, rv);
    }

    void recv_request_vote(const uint8_t* data, size_t size)
    {
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
          local_id,
          r.from_node);
        return;
      }

      if (current_term > r.term)
      {
        // Reply false, since our term is later than the received term.
        LOG_DEBUG_FMT(
          "Recv request vote to {} from {}: our term is later ({} > {})",
          local_id,
          r.from_node,
          current_term,
          r.term);
        send_request_vote_response(r.from_node, false);
        return;
      }
      else if (current_term < r.term)
      {
        // Become a follower in the new term.
        LOG_DEBUG_FMT(
          "Recv request vote to {} from {}: their term is later ({} < {})",
          local_id,
          r.from_node,
          current_term,
          r.term);
        become_follower(r.term);
      }

      if ((voted_for != NoNode) && (voted_for != r.from_node))
      {
        // Reply false, since we already voted for someone else.
        LOG_DEBUG_FMT(
          "Recv request vote to {} from {}: alredy voted for {}",
          local_id,
          r.from_node,
          voted_for);
        send_request_vote_response(r.from_node, false);
        return;
      }

      // If the candidate's log is at least as up-to-date as ours, vote yes
      auto last_commit_term = get_term_internal(commit_idx);

      auto answer = (r.last_commit_term > last_commit_term) ||
        ((r.last_commit_term == last_commit_term) &&
         (r.last_commit_idx >= commit_idx));

      if (answer)
      {
        // If we grant our vote, we also acknowledge that an election is in
        // progress.
        restart_election_timeout();
        leader_id = NoNode;
        voted_for = r.from_node;
      }

      send_request_vote_response(r.from_node, answer);
    }

    void send_request_vote_response(NodeId to, bool answer)
    {
      LOG_INFO_FMT(
        "Send request vote response from {} to {}: {}", local_id, to, answer);

      RequestVoteResponse response = {
        raft_request_vote_response, local_id, current_term, answer};

      channels->send_authenticated(
        ccf::NodeMsgType::consensus_msg, to, response);
    }

    void recv_request_vote_response(const uint8_t* data, size_t size)
    {
      if (state != Candidate)
      {
        LOG_INFO_FMT(
          "Recv request vote response to {}: we aren't a candidate", local_id);
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
          local_id,
          r.from_node);
        return;
      }

      if (current_term < r.term)
      {
        // Become a follower in the new term.
        LOG_INFO_FMT(
          "Recv request vote response to {} from {}: their term is more recent "
          "({} < {})",
          local_id,
          r.from_node,
          current_term,
          r.term);
        become_follower(r.term);
        return;
      }
      else if (current_term != r.term)
      {
        // Ignore as it is stale.
        LOG_INFO_FMT(
          "Recv request vote response to {} from {}: stale ({} != {})",
          local_id,
          r.from_node,
          current_term,
          r.term);
        return;
      }
      else if (!r.vote_granted)
      {
        // Do nothing.
        LOG_INFO_FMT(
          "Recv request vote response to {} from {}: they voted no",
          local_id,
          r.from_node);
        return;
      }

      LOG_INFO_FMT(
        "Recv request vote response to {} from {}: they voted yes",
        local_id,
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
      voted_for = local_id;
      votes_for_me.clear();
      current_term++;

      restart_election_timeout();
      add_vote_for_me(local_id);

      LOG_INFO_FMT("Becoming candidate {}: {}", local_id, current_term);

      for (auto it = nodes.begin(); it != nodes.end(); ++it)
        send_request_vote(it->first);
    }

    void become_leader()
    {
      // Discard any un-committed updates we may hold,
      // since we have no signature for them. Except at startup,
      // where we do not want to roll back the genesis transaction.
      if (commit_idx)
      {
        rollback(commit_idx);
      }

      committable_indices.clear();
      state = Leader;
      leader_id = local_id;

      using namespace std::chrono_literals;
      timeout_elapsed = 0ms;

      LOG_INFO_FMT("Becoming leader {}: {}", local_id, current_term);

      // Immediately commit if there are no other nodes.
      if (nodes.size() == 0)
      {
        commit(last_idx);
        return;
      }

      // Reset next, match, and sent indices for all nodes.
      auto next = last_idx + 1;

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
      restart_election_timeout();

      current_term = term;
      voted_for = NoNode;
      votes_for_me.clear();

      // Rollback unreplicated commits.
      rollback(commit_idx);
      committable_indices.clear();

      LOG_INFO_FMT("Becoming follower {}: {}", local_id, current_term);
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
          if (node == local_id)
            match.push_back(last_idx);
          else
            match.push_back(nodes.at(node).match_idx);
        }

        sort(match.begin(), match.end());
        auto confirmed = match.at((match.size() - 1) / 2);

        if (confirmed < new_commit_idx)
          new_commit_idx = confirmed;
      }

      LOG_DEBUG_FMT(
        "In update_commit, new_commit_idx: {}, last_idx: {}",
        new_commit_idx,
        last_idx);

      if (new_commit_idx > last_idx)
      {
        throw std::logic_error(
          "Followers appear to have later match indices than leader");
      }

      commit_if_possible(new_commit_idx);
    }

    void commit_if_possible(Index idx)
    {
      if ((idx > commit_idx) && (get_term_internal(idx) <= current_term))
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
      if (idx > last_idx)
        throw std::logic_error(
          "Tried to commit " + std::to_string(idx) + "but last_idx as " +
          std::to_string(last_idx));

      LOG_DEBUG_FMT("Starting commit");

      // This could happen if a follower becomes the leader when it
      // has committed fewer log entries, although it has them available.
      if (idx <= commit_idx)
        return;

      commit_idx = idx;

      LOG_DEBUG_FMT("Compacting...");
      store->compact(idx);
      LOG_DEBUG_FMT("Commit on {}: {}", local_id, idx);

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
        create_and_remove_node_state();
    }

    void rollback(Index idx)
    {
      store->rollback(idx);
      ledger->truncate(idx);
      last_idx = idx;
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
        create_and_remove_node_state();
    }

    void create_and_remove_node_state()
    {
      // Find all nodes present in any active configuration.
      std::unordered_set<NodeId> active_nodes;

      for (auto& conf : configurations)
      {
        for (auto node_id : conf.nodes)
          active_nodes.insert(node_id);
      }

      // Find all nodes in the node state that are not present in any active
      // configuration.
      std::vector<NodeId> to_remove;

      for (auto& node : nodes)
      {
        if (active_nodes.find(node.first) == active_nodes.end())
          to_remove.push_back(node.first);
      }

      for (auto node_id : to_remove)
      {
        nodes.erase(node_id);
        LOG_INFO_FMT("Removed node {}", node_id);
      }

      for (auto node_id : active_nodes)
      {
        if (node_id == local_id)
          continue;

        if (nodes.find(node_id) == nodes.end())
        {
          // A new node is sent only future entries initially. If it does not
          // have prior data, it will communicate that back to the leader.
          auto index = last_idx + 1;
          nodes[node_id] = {0, index};

          if (state == Leader)
            send_append_entries(node_id, index);

          LOG_INFO_FMT("Added node {}", node_id);
        }
      }

      if (active_nodes.find(local_id) == active_nodes.end())
      {
        LOG_INFO_FMT("Removed self {}", local_id);
      }
    }
  };
}