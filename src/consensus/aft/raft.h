// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

// AFT supports multithreaded execution of append entries and the follows the
// following pseudocode
//
// func run_next_message:
// if async_exec_in_progress then
//   queue_message
// if message == append_entry and thread_count > 1 then
//   if consensus = cft then
//     exec_on_async_thread
//     return_to_home_thread
//   else
//     loop until no more pending tx
//       schedule next executable block of tx
//       run scheduled block of tx concurrently
// else
//   exec_on_current_thread
// if queued_messages > 0 then
//   run_next_message
//

#include "async_execution.h"
#include "async_executor.h"
#include "ccf/tx_id.h"
#include "ds/logger.h"
#include "ds/serialized.h"
#include "impl/execution.h"
#include "impl/request_message.h"
#include "impl/state.h"
#include "impl/view_change_tracker.h"
#include "kv/kv_types.h"
#include "node/node_to_node.h"
#include "node/node_types.h"
#include "node/progress_tracker.h"
#include "node/request_tracker.h"
#include "node/rpc/tx_status.h"
#include "node/signatures.h"
#include "raft_types.h"

#include <algorithm>
#include <deque>
#include <list>
#include <mutex>
#include <random>
#include <unordered_map>
#include <vector>

namespace aft
{
  using Configuration = kv::Configuration;

  template <class LedgerProxy, class ChannelProxy, class SnapshotterProxy>
  class Aft : public kv::ConfigurableConsensus, public AbstractConsensusCallback
  {
  private:
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
    std::unique_ptr<Store> store;

    // Persistent
    std::optional<ccf::NodeId> voted_for = std::nullopt;

    // Volatile
    std::optional<ccf::NodeId> leader_id = std::nullopt;
    std::unordered_set<ccf::NodeId> votes_for_me;

    // Replicas start in state Follower. Apart from a single forced
    // transition from Follower to Leader on the initial node at startup,
    // the state machine is made up of the following transitions:
    //
    // Follower -> Candidate, when election timeout expires
    // Follower -> Retired, when commit advances past the last config containing
    // the node
    // Candidate -> Leader, upon collecting enough votes
    // Leader -> Retired, when commit advances past the last config containing
    // the node
    // Leader -> Follower, when receiving entries for a newer term
    // Candidate -> Follower, when receiving entries for a newer term
    kv::ReplicaState replica_state;
    std::chrono::milliseconds timeout_elapsed;
    // Last (committable) index preceding the node's election, this is
    // used to decide when to start issuing signatures. While commit_idx
    // hasn't caught up with election_index, a newly elected leader is
    // effectively finishing establishing commit over the previous term
    // or even previous terms, and can therefore not meaningfully sign
    // over the commit level.
    kv::Version election_index = 0;
    bool is_execution_pending = false;
    std::list<std::unique_ptr<AbstractMsgCallback>> execution_backlog;

    // When this node receives append entries from a new primary, it may need to
    // roll back a committable but uncommitted suffix it holds. The
    // new primary dictates the index where this suffix begins, which
    // following the Raft election rules must be at least as high as the highest
    // commit index reported by the previous primary. The window in which this
    // rollback could be accepted is minimised to avoid unnecessary
    // retransmissions - this node only executes this rollback instruction on
    // the first append entries after it became a follower. As with any append
    // entries, the initial index will not advance until this node acks.
    bool is_new_follower = false;

    // BFT
    std::shared_ptr<aft::State> state;
    std::shared_ptr<Executor> executor;
    std::shared_ptr<aft::RequestTracker> request_tracker;
    std::unique_ptr<aft::ViewChangeTracker> view_change_tracker;

    // Async execution
    struct AsyncExecution;
    AsyncExecutor async_executor;
    std::unique_ptr<threading::Tmsg<AsyncExecution>> async_exec_msg;
    uint64_t next_exec_thread = 0;

    // Timeouts
    std::chrono::milliseconds request_timeout;
    std::chrono::milliseconds election_timeout;
    std::chrono::milliseconds view_change_timeout;
    size_t sig_tx_interval;

    // Configurations
    std::list<Configuration> configurations;
    std::unordered_map<ccf::NodeId, NodeState> nodes;
    std::unordered_map<ccf::NodeId, ccf::SeqNo> learners;
    bool use_two_tx_reconfig = false;

    // Index at which this node observes its retirement
    std::optional<ccf::SeqNo> retirement_idx = std::nullopt;
    // Earliest index at which this node's retirement can be committed
    std::optional<ccf::SeqNo> retirement_committable_idx = std::nullopt;

    size_t entry_size_not_limited = 0;
    size_t entry_count = 0;
    Index entries_batch_size = 1;
    static constexpr int batch_window_size = 100;
    int batch_window_sum = 0;

    // Indices that are eligible for global commit, from a Node's perspective
    std::deque<Index> committable_indices;

    // When this is set, only public domain is deserialised when receiving
    // append entries
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
    std::set<ccf::NodeId> backup_nodes;

  public:
    Aft(
      ConsensusType consensus_type_,
      std::unique_ptr<Store> store_,
      std::unique_ptr<LedgerProxy> ledger_,
      std::shared_ptr<ccf::NodeToNode> channels_,
      std::shared_ptr<SnapshotterProxy> snapshotter_,
      std::shared_ptr<enclave::RPCSessions> rpc_sessions_,
      std::shared_ptr<enclave::RPCMap> rpc_map_,
      const std::vector<uint8_t>& /*cert*/,
      std::shared_ptr<aft::State> state_,
      std::shared_ptr<Executor> executor_,
      std::shared_ptr<aft::RequestTracker> request_tracker_,
      std::unique_ptr<aft::ViewChangeTracker> view_change_tracker_,
      std::chrono::milliseconds request_timeout_,
      std::chrono::milliseconds election_timeout_,
      std::chrono::milliseconds view_change_timeout_,
      size_t sig_tx_interval_ = 0,
      bool public_only_ = false,
      kv::ReplicaState initial_state_ = kv::ReplicaState::Follower) :
      consensus_type(consensus_type_),
      store(std::move(store_)),

      replica_state(initial_state_),
      timeout_elapsed(0),

      state(state_),
      executor(executor_),
      request_tracker(request_tracker_),
      view_change_tracker(std::move(view_change_tracker_)),
      async_executor(threading::ThreadMessaging::thread_count),

      request_timeout(request_timeout_),
      election_timeout(election_timeout_),
      view_change_timeout(view_change_timeout_),
      sig_tx_interval(sig_tx_interval_),
      public_only(public_only_),

      distrib(0, (int)election_timeout_.count() / 2),
      rand((int)(uintptr_t)this),

      ledger(std::move(ledger_)),
      channels(channels_),
      snapshotter(snapshotter_),
      rpc_sessions(rpc_sessions_),
      rpc_map(rpc_map_)

    {
      if (view_change_tracker != nullptr)
      {
        view_change_tracker->set_current_view_change(starting_view_change);
      }

      auto progress_tracker = store->get_progress_tracker();
      if (progress_tracker != nullptr)
      {
        progress_tracker->set_is_public_only(public_only);
      }

      if (request_tracker != nullptr && !public_only)
      {
        request_tracker->start_tracking_requests();
      }

      if (consensus_type == ConsensusType::BFT)
      {
        // Initialize view history for bft. We start on view 2 and the first
        // commit is always 1.
        state->view_history.update(1, starting_view_change);
        use_two_tx_reconfig = true;
      }
    }

    virtual ~Aft() = default;

    std::optional<ccf::NodeId> leader()
    {
      return leader_id;
    }

    bool view_change_in_progress()
    {
      std::unique_lock<std::mutex> guard(state->lock);
      if (consensus_type == ConsensusType::BFT)
      {
        auto time = threading::ThreadMessaging::thread_messaging
                      .get_current_time_offset();
        return view_change_tracker->is_view_change_in_progress(time);
      }
      else
      {
        return (replica_state == kv::ReplicaState::Candidate);
      }
    }

    std::set<ccf::NodeId> active_nodes()
    {
      // Find all nodes present in any active configuration.
      if (backup_nodes.empty())
      {
        for (auto& conf : configurations)
        {
          for (auto node : conf.nodes)
          {
            backup_nodes.insert(node.first);
          }
        }
      }

      return backup_nodes;
    }

    ccf::NodeId id()
    {
      return state->my_node_id;
    }

    bool is_primary()
    {
      return replica_state == kv::ReplicaState::Leader;
    }

    bool is_bft_reexecution()
    {
      return consensus_type == ConsensusType::BFT && !is_primary();
    }

    bool can_replicate()
    {
      std::unique_lock<std::mutex> guard(state->lock, std::defer_lock);
      if (!is_bft_reexecution())
      {
        guard.lock();
      }
      return replica_state == kv::ReplicaState::Leader &&
        !retirement_committable_idx.has_value();
    }

    bool is_follower()
    {
      return replica_state == kv::ReplicaState::Follower;
    }

    bool is_learner()
    {
      return replica_state == kv::ReplicaState::Learner;
    }

    bool is_retired()
    {
      return replica_state == kv::ReplicaState::Retired;
    }

    bool is_retiring()
    {
      return replica_state == kv::ReplicaState::Retiring;
    }

    ccf::NodeId get_primary(ccf::View view)
    {
      CCF_ASSERT_FMT(
        consensus_type == ConsensusType::BFT,
        "Computing primary id from view is only supported with BFT consensus");

      const auto& config = configurations.back();
      return get_primary_at_config(view, config.bft_offset, config.nodes);
    }

    Index last_committable_index() const
    {
      return committable_indices.empty() ? state->commit_idx :
                                           committable_indices.back();
    }

    void enable_all_domains()
    {
      // When receiving append entries as a follower, all security domains will
      // be deserialised
      std::lock_guard<std::mutex> guard(state->lock);
      public_only = false;
      auto progress_tracker = store->get_progress_tracker();
      if (progress_tracker != nullptr)
      {
        progress_tracker->set_is_public_only(public_only);
      }
      if (request_tracker != nullptr)
      {
        request_tracker->start_tracking_requests();
      }
    }

    void force_become_leader()
    {
      // This is unsafe and should only be called when the node is certain
      // there is no leader and no other node will attempt to force leadership.
      if (leader_id.has_value())
      {
        throw std::logic_error(
          "Can't force leadership if there is already a leader");
      }

      std::lock_guard<std::mutex> guard(state->lock);
      state->current_view += starting_view_change;
      become_leader(true);
    }

    void force_become_leader(
      Index index,
      Term term,
      const std::vector<Index>& terms,
      Index commit_idx_)
    {
      // This is unsafe and should only be called when the node is certain
      // there is no leader and no other node will attempt to force leadership.
      if (leader_id.has_value())
      {
        throw std::logic_error(
          "Can't force leadership if there is already a leader");
      }

      std::lock_guard<std::mutex> guard(state->lock);
      state->current_view = term;
      state->last_idx = index;
      state->commit_idx = commit_idx_;
      state->view_history.initialise(terms);
      state->view_history.update(index, term);
      state->current_view += starting_view_change;
      become_leader(true);
    }

    void init_as_follower(
      Index index, Term term, const std::vector<Index>& term_history)
    {
      // This should only be called when the node resumes from a snapshot and
      // before it has received any append entries.
      std::lock_guard<std::mutex> guard(state->lock);

      state->last_idx = index;
      state->commit_idx = index;

      state->view_history.initialise(term_history);

      ledger->init(index);
      snapshotter->set_last_snapshot_idx(index);

      become_aware_of_new_term(term);
    }

    Index get_last_idx()
    {
      return state->last_idx;
    }

    Index get_commit_idx()
    {
      std::lock_guard<std::mutex> guard(state->lock);
      return get_commit_idx_unsafe();
    }

    Term get_term()
    {
      std::lock_guard<std::mutex> guard(state->lock);
      return state->current_view;
    }

    std::pair<Term, Index> get_commit_term_and_idx()
    {
      std::lock_guard<std::mutex> guard(state->lock);
      ccf::SeqNo commit_idx = get_commit_idx_unsafe();
      return {get_term_internal(commit_idx), commit_idx};
    }

    std::optional<kv::Consensus::SignableTxIndices>
    get_signable_commit_term_and_idx()
    {
      std::lock_guard<std::mutex> guard(state->lock);
      if (
        consensus_type == ConsensusType::BFT ||
        state->commit_idx >= election_index)
      {
        kv::Consensus::SignableTxIndices r;
        r.term = get_term_internal(state->commit_idx);
        r.version = state->commit_idx;
        r.previous_version = last_committable_index();
        return r;
      }
      else
      {
        return std::nullopt;
      }
    }

    Term get_term(Index idx)
    {
      std::lock_guard<std::mutex> guard(state->lock);
      return get_term_internal(idx);
    }

    std::vector<Index> get_term_history(Index idx)
    {
      // This should only be called when the spin lock is held.
      return state->view_history.get_history_until(idx);
    }

    void initialise_term_history(const std::vector<Index>& term_history)
    {
      // This should only be called when the spin lock is held.
      return state->view_history.initialise(term_history);
    }

    void add_configuration(
      Index idx,
      const Configuration::Nodes& conf,
      const std::unordered_set<ccf::NodeId>& new_learners = {})
    {
      std::unordered_set<ccf::NodeId> conf_ids;
      for (const auto& [id, _] : conf)
      {
        conf_ids.insert(id);
      }
      LOG_DEBUG_FMT("Configurations: add {{{}}}", fmt::join(conf_ids, ", "));

      std::unique_lock<std::mutex> guard(state->lock, std::defer_lock);
      // It is safe to call is_follower() by construction as the consensus
      // can only change from leader or follower while in a view-change during
      // which time transaction cannot be executed.
      if (is_bft_reexecution() && threading::ThreadMessaging::thread_count > 1)
      {
        guard.lock();
      }

      if (!use_two_tx_reconfig)
      {
        // Detect when we are retired by observing a configuration
        // from which we are absent following a configuration in which
        // we were included. Note that this relies on retirement being
        // a final state, and node identities never being re-used.
        if (
          !configurations.empty() &&
          configurations.back().nodes.find(state->my_node_id) !=
            configurations.back().nodes.end() &&
          conf.find(state->my_node_id) == conf.end())
        {
          CCF_ASSERT_FMT(
            !retirement_idx.has_value(),
            "retirement_idx already set to {}",
            retirement_idx.value());
          retirement_idx = idx;
          LOG_INFO_FMT("Node retiring at {}", idx);
        }
      }

      uint32_t offset = 0;
      if (consensus_type == ConsensusType::BFT && !configurations.empty())
      {
        auto progress_tracker = store->get_progress_tracker();
        auto target = progress_tracker->get_primary_at_last_view_change();
        for (; offset < configurations.back().nodes.size(); ++offset)
        {
          if (
            get_primary_at_config(std::get<1>(target), offset, conf) ==
            std::get<0>(target))
          {
            break;
          }
        }
      }
      configurations.push_back({idx, std::move(conf), offset});
      if (use_two_tx_reconfig)
      {
        if (!new_learners.empty())
        {
          LOG_DEBUG_FMT(
            "Configurations: new learners: {{{}}}",
            fmt::join(new_learners, ", "));
          for (auto& id : new_learners)
          {
            if (learners.find(id) == learners.end())
            {
              learners[id] = idx;
            }
          }
        }
      }
      else if (!new_learners.empty())
      {
        throw std::runtime_error(
          "learner requires two-transaction reconfiguration");
      }
      backup_nodes.clear();
      create_and_remove_node_state();
    }

    void add_network_configuration(
      ccf::SeqNo seqno, const kv::NetworkConfiguration& config)
    {
      LOG_DEBUG_FMT("Configurations: new network config: {{{}}}", config);
      std::unique_lock<std::mutex> guard(state->lock, std::defer_lock);

      if (is_bft_reexecution() && threading::ThreadMessaging::thread_count > 1)
      {
        guard.lock();
      }

      // Hooks may be reordered, so the node info in `configurations` and
      // `nodes` may not be available yet.

      if (
        use_two_tx_reconfig && !is_learner() && !is_retired() &&
        config.nodes.find(state->my_node_id) != config.nodes.end())
      {
        // Send/schedule ORCs
      }
    }

    Configuration::Nodes get_latest_configuration_unsafe() const
    {
      if (configurations.empty())
      {
        return {};
      }

      return configurations.back().nodes;
    }

    Configuration::Nodes get_latest_configuration()
    {
      std::lock_guard<std::mutex> guard(state->lock);
      return get_latest_configuration_unsafe();
    }

    kv::ConsensusDetails get_details()
    {
      kv::ConsensusDetails details;
      std::lock_guard<std::mutex> guard(state->lock);
      details.state = replica_state;
      for (auto& config : configurations)
      {
        details.configs.push_back(config);
      }
      for (auto& [k, v] : nodes)
      {
        details.acks[k] = v.match_idx;
      }
      if (use_two_tx_reconfig)
      {
        details.learners = learners;
      }
      return details;
    }

    template <typename T>
    bool replicate(
      const std::vector<
        std::tuple<Index, T, bool, std::shared_ptr<kv::ConsensusHookPtrs>>>&
        entries,
      Term term)
    {
      if (is_bft_reexecution())
      {
        // Already under lock in the current BFT path
        for (auto& [_, __, ___, hooks] : entries)
        {
          for (auto& hook : *hooks)
          {
            hook->call(this);
          }
        }
        return true;
      }

      std::lock_guard<std::mutex> guard(state->lock);

      if (replica_state != kv::ReplicaState::Leader)
      {
        LOG_FAIL_FMT(
          "Failed to replicate {} items: not leader", entries.size());
        rollback(state->last_idx);
        return false;
      }

      if (term != state->current_view)
      {
        LOG_FAIL_FMT(
          "Failed to replicate {} items at term {}, current term is {}",
          entries.size(),
          term,
          state->current_view);
        return false;
      }

      LOG_DEBUG_FMT("Replicating {} entries", entries.size());

      for (auto& [index, data, is_globally_committable, hooks] : entries)
      {
        bool globally_committable = is_globally_committable;

        if (index != state->last_idx + 1)
          return false;

        if (retirement_committable_idx.has_value())
        {
          CCF_ASSERT_FMT(
            index > retirement_committable_idx.value(),
            "Index {} unexpectedly lower than retirement_committable_idx {}",
            index,
            retirement_committable_idx.value());
          return false;
        }

        LOG_DEBUG_FMT(
          "Replicated on leader {}: {}{} ({} hooks)",
          state->my_node_id.trim(),
          index,
          (globally_committable ? " committable" : ""),
          hooks->size());

        for (auto& hook : *hooks)
        {
          hook->call(this);
        }

        bool force_ledger_chunk = false;
        if (globally_committable)
        {
          if (retirement_idx.has_value())
          {
            CCF_ASSERT_FMT(
              index >= retirement_idx.value(),
              "Index {} unexpectedly lower than retirement_idx {}",
              index,
              retirement_idx.value());
            retirement_committable_idx = index;
            LOG_INFO_FMT("Node retirement committable at {}", index);
          }
          committable_indices.push_back(index);

          // Only if globally committable, a snapshot requires a new ledger
          // chunk to be created
          force_ledger_chunk = snapshotter->record_committable(index);
        }

        state->last_idx = index;
        ledger->put_entry(*data, globally_committable, force_ledger_chunk);
        entry_size_not_limited += data->size();
        entry_count++;

        state->view_history.update(index, state->current_view);
        if (entry_size_not_limited >= append_entries_size_limit)
        {
          update_batch_size();
          entry_count = 0;
          entry_size_not_limited = 0;
          for (const auto& it : nodes)
          {
            LOG_DEBUG_FMT("Sending updates to follower {}", it.first.trim());
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

    void recv_message(const ccf::NodeId& from, const uint8_t* data, size_t size)
    {
      std::unique_ptr<AbstractMsgCallback> aee;
      RaftMsgType type = serialized::peek<RaftMsgType>(data, size);

      try
      {
        switch (type)
        {
          case raft_append_entries:
          {
            AppendEntries r =
              channels->template recv_authenticated<AppendEntries>(
                from, data, size);
            aee = std::make_unique<AppendEntryCallback>(
              *this, from, std::move(r), data, size);
            break;
          }
          case raft_append_entries_response:
          {
            AppendEntriesResponse r =
              channels->template recv_authenticated<AppendEntriesResponse>(
                from, data, size);
            aee = std::make_unique<AppendEntryResponseCallback>(
              *this, from, std::move(r));
            break;
          }
          case raft_append_entries_signed_response:
          {
            SignedAppendEntriesResponse r =
              channels
                ->template recv_authenticated<SignedAppendEntriesResponse>(
                  from, data, size);
            aee = std::make_unique<SignedAppendEntryResponseCallback>(
              *this, from, std::move(r));
            break;
          }

          case raft_request_vote:
          {
            RequestVote r = channels->template recv_authenticated<RequestVote>(
              from, data, size);
            aee =
              std::make_unique<RequestVoteCallback>(*this, from, std::move(r));
            break;
          }

          case raft_request_vote_response:
          {
            RequestVoteResponse r =
              channels->template recv_authenticated<RequestVoteResponse>(
                from, data, size);
            aee = std::make_unique<RequestVoteResponseCallback>(
              *this, from, std::move(r));
            break;
          }

          case bft_signature_received_ack:
          {
            SignaturesReceivedAck r =
              channels->template recv_authenticated<SignaturesReceivedAck>(
                from, data, size);
            aee =
              std::make_unique<SignatureAckCallback>(*this, from, std::move(r));
            break;
          }

          case bft_nonce_reveal:
          {
            NonceRevealMsg r =
              channels->template recv_authenticated<NonceRevealMsg>(
                from, data, size);
            aee =
              std::make_unique<NonceRevealCallback>(*this, from, std::move(r));
            break;
          }
          case bft_view_change:
          {
            RequestViewChangeMsg r =
              channels
                ->template recv_authenticated_with_load<RequestViewChangeMsg>(
                  from, data, size);
            aee = std::make_unique<ViewChangeCallback>(
              *this, from, std::move(r), data, size);
            break;
          }

          case bft_skip_view:
          {
            SkipViewMsg r =
              channels->template recv_authenticated_with_load<SkipViewMsg>(
                from, data, size);
            aee = std::make_unique<SkipViewCallback>(*this, from, std::move(r));
            break;
          }

          case bft_view_change_evidence:
          {
            ViewChangeEvidenceMsg r =
              channels
                ->template recv_authenticated_with_load<ViewChangeEvidenceMsg>(
                  from, data, size);

            aee = std::make_unique<ViewChangeEvidenceCallback>(
              *this, from, std::move(r), data, size);
            break;
          }

          default:
          {
          }
        }
      }
      catch (const ccf::NodeToNode::DroppedMessageException& e)
      {
        LOG_INFO_FMT("Dropped invalid message from {}", e.from);
        return;
      }
      catch (const std::exception& e)
      {
        LOG_FAIL_EXC(e.what());
        return;
      }

      if (!is_execution_pending)
      {
        aee->execute();
      }
      else
      {
        execution_backlog.push_back(std::move(aee));
      }

      try_execute_pending();
    }

    void try_execute_pending()
    {
      if (threading::ThreadMessaging::thread_count > 1)
      {
        {
          do_periodic();
        }
        while (!is_execution_pending && !execution_backlog.empty())
        {
          auto pe = std::move(execution_backlog.front());
          execution_backlog.pop_front();
          pe->execute();
        }
      }
      else
      {
        CCF_ASSERT_FMT(
          execution_backlog.empty(), "No message should be run asynchronously");
      }
    }
    void periodic(std::chrono::milliseconds elapsed)
    {
      {
        std::unique_lock<std::mutex> guard(state->lock);
        timeout_elapsed += elapsed;
        if (is_execution_pending)
        {
          return;
        }
      }
      do_periodic();
    }

    void do_periodic()
    {
      std::unique_lock<std::mutex> guard(state->lock);
      if (consensus_type == ConsensusType::BFT)
      {
        auto time = threading::ThreadMessaging::thread_messaging
                      .get_current_time_offset();
        request_tracker->tick(time);

        if (
          !view_change_tracker->is_view_change_in_progress(time) &&
          (is_follower() || is_learner()) && (has_bft_timeout_occurred(time)) &&
          view_change_tracker->should_send_view_change(time))
        {
          // We have not seen a request executed within an expected period of
          // time. We should invoke a view-change.
          //
          ccf::View new_view = view_change_tracker->get_target_view();
          ccf::SeqNo seqno;
          std::unique_ptr<ccf::ViewChangeRequest> vc;

          auto progress_tracker = store->get_progress_tracker();
          std::tie(vc, seqno) =
            progress_tracker->get_view_change_message(new_view);

          size_t vc_size = vc->get_serialized_size();

          RequestViewChangeMsg vcm = {{bft_view_change}, new_view, seqno};

          std::vector<uint8_t> m;
          m.resize(sizeof(RequestViewChangeMsg) + vc_size);

          uint8_t* data = m.data();
          size_t size = m.size();

          serialized::write(
            data, size, reinterpret_cast<uint8_t*>(&vcm), sizeof(vcm));
          vc->serialize(data, size);
          CCF_ASSERT_FMT(size == 0, "Did not write everything");

          LOG_INFO_FMT(
            "Sending view change msg view:{}, primary_at_view:{}",
            vcm.view,
            get_primary(vcm.view));
          for (auto it = nodes.begin(); it != nodes.end(); ++it)
          {
            auto to = it->first;
            if (to != state->my_node_id)
            {
              channels->send_authenticated(
                to, ccf::NodeMsgType::consensus_msg, m);
            }
          }

          if (
            aft::ViewChangeTracker::ResultAddView::APPEND_NEW_VIEW_MESSAGE ==
              view_change_tracker->add_request_view_change(
                *vc, id(), new_view, get_last_configuration_nodes()) &&
            get_primary(new_view) == id())
          {
            // We need to reobtain the lock when writing to the ledger so we
            // need to release it at this time.
            //
            // It is safe to release the lock here because there is no
            // concurrency based dependency between appending to the ledger and
            // replicating the ledger to other machines.
            guard.unlock();
            append_new_view(new_view);
            guard.lock();
          }
        }
      }

      if (replica_state == kv::ReplicaState::Leader)
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
      else if (consensus_type != ConsensusType::BFT)
      {
        if (can_endorse_primary() && timeout_elapsed >= election_timeout)
        {
          // Start an election.
          become_candidate();
        }
      }
    }

    void recv_view_change(
      const ccf::NodeId& from,
      RequestViewChangeMsg r,
      const uint8_t* data,
      size_t size)
    {
      LOG_DEBUG_FMT("Received evidence for view:{}, from:{}", r.view, from);
      auto node = nodes.find(from);
      if (node == nodes.end())
      {
        // Ignore if we don't recognise the node.
        LOG_FAIL_FMT(
          "Recv nonce reveal to {} from {}: unknown node",
          state->my_node_id,
          from);
        return;
      }

      ccf::ViewChangeRequest v =
        ccf::ViewChangeRequest::deserialize(data, size);
      LOG_INFO_FMT(
        "Received view change from:{}, view:{}", from.trim(), r.view);

      auto progress_tracker = store->get_progress_tracker();
      auto result =
        progress_tracker->apply_view_change_message(v, from, r.view, r.seqno);

      if (result == ccf::ProgressTracker::ApplyViewChangeMessageResult::FAIL)
      {
        return;
      }

      if (
        result ==
          ccf::ProgressTracker::ApplyViewChangeMessageResult::SKIP_VIEW &&
        get_primary(r.view) == id())
      {
        SkipViewMsg response = {{bft_skip_view}, r.view};
        channels->send_authenticated(
          from, ccf::NodeMsgType::consensus_msg, response);
        return;
      }

      if (
        aft::ViewChangeTracker::ResultAddView::APPEND_NEW_VIEW_MESSAGE ==
          view_change_tracker->add_request_view_change(
            v, from, r.view, get_last_configuration_nodes()) &&
        get_primary(r.view) == id())
      {
        append_new_view(r.view);
      }
    }

    void recv_view_change_evidence(
      const ccf::NodeId& from,
      ViewChangeEvidenceMsg r,
      const uint8_t* data,
      size_t size)
    {
      auto node = nodes.find(from);
      if (node == nodes.end())
      {
        // Ignore if we don't recognise the node.
        LOG_FAIL_FMT(
          "Recv view change evidence to {} from {}: unknown node",
          state->my_node_id,
          from);
        return;
      }

      if (!state->requested_evidence_from.has_value())
      {
        LOG_FAIL_FMT("Received unrequested view change evidence");
        return;
      }

      if (from != state->requested_evidence_from.value())
      {
        // Ignore if we didn't request this evidence.
        LOG_FAIL_FMT("Received unrequested view change evidence from {}", from);
        return;
      }
      if (!view_change_tracker->add_unknown_primary_evidence(
            {data, size}, r.view, from, get_last_configuration_nodes()))
      {
        LOG_FAIL_FMT("Failed to verify view_change_evidence from {}", from);
        return;
      }

      become_aware_of_new_term(r.view);
    }

    void recv_skip_view(const ccf::NodeId& from, SkipViewMsg r)
    {
      auto node = nodes.find(from);
      if (node == nodes.end())
      {
        LOG_FAIL_FMT(
          "Recv skip view to {} from {}: unknown node",
          state->my_node_id,
          from);
        return;
      }

      if (from != get_primary(r.view))
      {
        LOG_FAIL_FMT(
          "Recv skip view to {} from {}: wrong replica",
          state->my_node_id,
          from);
        return;
      }

      view_change_tracker->received_skip_view(r);
    }

    bool is_first_request = true;

    bool on_request(const kv::TxHistory::RequestCallbackArgs& args)
    {
      auto request = executor->create_request_message(args, get_commit_idx());
      executor->execute_request(std::move(request), is_first_request);
      is_first_request = false;

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

    ccf::NodeId get_primary_at_config(
      ccf::View view, uint32_t offset, const Configuration::Nodes& conf)
    {
      CCF_ASSERT_FMT(
        consensus_type == ConsensusType::BFT,
        "Computing primary id from view is only supported with BFT consensus");

      auto it = conf.begin();
      std::advance(it, (view - starting_view_change + offset) % conf.size());
      return it->first;
    }

    void append_new_view(ccf::View view)
    {
      LOG_INFO_FMT(
        "Writing view change to ledger as a new primay, view:{}", view);
      state->current_view = view;
      become_leader();
      state->new_view_idx =
        view_change_tracker->write_view_change_confirmation_append_entry(
          view, id());
      view_change_tracker->clear(get_primary(view) == id(), view);
      request_tracker->clear();
    }

    bool has_bft_timeout_occurred(std::chrono::milliseconds time)
    {
      auto oldest_entry = request_tracker->oldest_entry();
      ccf::SeqNo last_sig_seqno;
      std::chrono::milliseconds last_sig_time;
      std::tie(last_sig_seqno, last_sig_time) =
        request_tracker->get_seqno_time_last_request();

      if (
        view_change_timeout != std::chrono::milliseconds(0) &&
        oldest_entry.has_value() &&
        oldest_entry.value() + view_change_timeout < time)
      {
        LOG_FAIL_FMT("Timeout waiting for request to be executed");
        return true;
      }

      // Check if any requests were added to the ledger since the last signature
      if (last_sig_seqno >= state->last_idx)
      {
        return false;
      }

      constexpr auto wait_factor = 10;
      std::chrono::milliseconds expire_time = last_sig_time +
        std::chrono::milliseconds(view_change_timeout.count() * wait_factor);

      // Check if we are waiting too long since the last signature
      if (expire_time < time)
      {
        LOG_FAIL_FMT(
          "Timeout waiting for global commit, last_sig_seqno:{}, last_idx:{}",
          last_sig_seqno,
          state->last_idx);
        return true;
      }

      // Check if there have been too many entries since the last signature
      if (
        sig_tx_interval != 0 &&
        last_sig_seqno + sig_tx_interval * wait_factor <
          static_cast<size_t>(state->last_idx))
      {
        LOG_FAIL_FMT(
          "Too many transactions occurred since last signature, "
          "last_sig_seqno:{}, "
          "last_idx:{}",
          last_sig_seqno,
          state->last_idx);
        return true;
      }

      return false;
    }

    Term get_term_internal(Index idx)
    {
      if (idx > state->last_idx)
        return ccf::VIEW_UNKNOWN;

      return state->view_history.view_at(idx);
    }

    Index get_commit_idx_unsafe()
    {
      if (consensus_type == ConsensusType::CFT)
      {
        return state->commit_idx;
      }
      else
      {
        auto progress_tracker = store->get_progress_tracker();
        return progress_tracker->get_highest_committed_level();
      }
    }

    void send_append_entries(const ccf::NodeId& to, Index start_idx)
    {
      Index end_idx = (state->last_idx == 0) ?
        0 :
        std::min(start_idx + entries_batch_size, state->last_idx);

      for (Index i = end_idx; i < state->last_idx; i += entries_batch_size)
      {
        send_append_entries_range(to, start_idx, i);
        start_idx = std::min(i + 1, state->last_idx);
      }

      if (state->last_idx == 0 || end_idx <= state->last_idx)
      {
        send_append_entries_range(to, start_idx, state->last_idx);
      }
    }

    void send_append_entries_range(
      const ccf::NodeId& to, Index start_idx, Index end_idx)
    {
      const auto prev_idx = start_idx - 1;

      if (is_retired() && start_idx >= end_idx)
      {
        // Continue to replicate, but do not send heartbeats if we are retired
        return;
      }

      const auto prev_term = get_term_internal(prev_idx);
      const auto term_of_idx = get_term_internal(end_idx);
      const bool contains_new_view =
        (state->new_view_idx > prev_idx) && (state->new_view_idx <= end_idx);

      LOG_DEBUG_FMT(
        "Send append entries from {} to {}: {} to {} ({})",
        state->my_node_id.trim(),
        to.trim(),
        start_idx,
        end_idx,
        state->commit_idx);

      AppendEntries ae = {{raft_append_entries},
                          {end_idx, prev_idx},
                          state->current_view,
                          prev_term,
                          state->commit_idx,
                          term_of_idx,
                          contains_new_view};

      auto& node = nodes.at(to);

      // The host will append log entries to this message when it is
      // sent to the destination node.
      if (!channels->send_authenticated(
            to, ccf::NodeMsgType::consensus_msg, ae))
      {
        return;
      }

      // Record the most recent index we have sent to this node.
      node.sent_idx = end_idx;
    }

    struct AsyncExecution
    {
      AsyncExecution(
        Aft<LedgerProxy, ChannelProxy, SnapshotterProxy>* self_,
        std::vector<std::tuple<
          std::unique_ptr<kv::AbstractExecutionWrapper>,
          kv::Version>>&& append_entries_,
        const ccf::NodeId& from_,
        AppendEntries&& r_,
        bool confirm_evidence_) :
        self(self_),
        append_entries(std::move(append_entries_)),
        from(from_),
        r(std::move(r_)),
        confirm_evidence(confirm_evidence_),
        next_append_entry_index(0)
      {}

      Aft<LedgerProxy, ChannelProxy, SnapshotterProxy>* self;
      std::vector<
        std::tuple<std::unique_ptr<kv::AbstractExecutionWrapper>, kv::Version>>
        append_entries;
      ccf::NodeId from;
      AppendEntries r;
      bool confirm_evidence;
      uint64_t next_append_entry_index;
    };

    void recv_append_entries(
      const ccf::NodeId& from,
      AppendEntries r,
      const uint8_t* data,
      size_t size)
    {
      std::unique_lock<std::mutex> guard(state->lock);

      LOG_DEBUG_FMT(
        "Received append entries: {}.{} to {}.{} (from {} in term {})",
        r.prev_term,
        r.prev_idx,
        r.term_of_idx,
        r.idx,
        from.trim(),
        r.term);

      // Don't check that the sender node ID is valid. Accept anything that
      // passes the integrity check. This way, entries containing dynamic
      // topology changes that include adding this new leader can be accepted.

      // When we are running with in a Byzantine model we cannot trust that the
      // replica is sending up this data is correct so we need to validate
      // additional properties that go above and beyond the non-byzantine
      // scenario.
      bool confirm_evidence = false;
      if (consensus_type == ConsensusType::BFT)
      {
        if (!state->initial_recovery_primary.has_value())
        {
          state->initial_recovery_primary = std::make_tuple(from, r.term);
        }
        if (
          active_nodes().size() == 0 ||
          (std::get<0>(state->initial_recovery_primary.value()) == from &&
           std::get<1>(state->initial_recovery_primary.value()) == r.term))
        {
          // The replica is just starting up, we want to check that this replica
          // is part of the network we joined but that is dependent on Byzantine
          // identity
        }
        else if (get_primary(r.term) != from)
        {
          LOG_DEBUG_FMT(
            "Recv append entries to {} from {} at view:{} but the primary at "
            "this view should be {}",
            state->my_node_id,
            from,
            r.term,
            get_primary(r.term));
          send_append_entries_response(from, AppendEntriesResponseType::FAIL);
          return;
        }
        else if (!view_change_tracker->check_evidence(r.term))
        {
          if (r.contains_new_view)
          {
            confirm_evidence = true;
          }
          else
          {
            LOG_DEBUG_FMT(
              "Recv append entries to {} from {} at view:{} but we do not have "
              "the evidence to support this view",
              state->my_node_id,
              from,
              r.term);
            send_append_entries_response(
              from, AppendEntriesResponseType::REQUIRE_EVIDENCE);
            return;
          }
        }
      }

      // First, check append entries term against our own term, becoming
      // follower if necessary
      if (
        state->current_view == r.term &&
        replica_state == kv::ReplicaState::Candidate)
      {
        become_aware_of_new_term(r.term);
      }
      else if (state->current_view < r.term)
      {
        become_aware_of_new_term(r.term);
      }
      else if (state->current_view > r.term)
      {
        // Reply false, since our term is later than the received term.
        LOG_INFO_FMT(
          "Recv append entries to {} from {} but our term is later ({} > {})",
          state->my_node_id,
          from,
          state->current_view,
          r.term);
        send_append_entries_response(from, AppendEntriesResponseType::FAIL);
        return;
      }

      // Second, check term consistency with the entries we have so far
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
            state->my_node_id,
            from,
            r.prev_idx);
        }
        else
        {
          LOG_DEBUG_FMT(
            "Recv append entries to {} from {} but our log at {} has the wrong "
            "previous term (ours: {}, theirs: {})",
            state->my_node_id,
            from,
            r.prev_idx,
            prev_term,
            r.prev_term);
        }
        send_append_entries_response(from, AppendEntriesResponseType::FAIL);
        return;
      }

      // Then check if those append entries extend past our retirement
      if (
        retirement_committable_idx.has_value() &&
        r.idx > retirement_committable_idx)
      {
        send_append_entries_response(from, AppendEntriesResponseType::FAIL);
        return;
      }

      // If the terms match up, it is sufficient to convince us that the sender
      // is leader in our term
      restart_election_timeout();
      if (!leader_id.has_value() || leader_id.value() != from)
      {
        leader_id = from;
        LOG_DEBUG_FMT(
          "Node {} thinks leader is {}", state->my_node_id, leader_id.value());
      }

      // Third, check index consistency, making sure entries are not in the past
      // or in the future
      if (
        (consensus_type == ConsensusType::CFT &&
         r.prev_idx < state->commit_idx) ||
        r.prev_idx < state->bft_watermark_idx)
      {
        LOG_DEBUG_FMT(
          "Recv append entries to {} from {} but prev_idx ({}), bft_watermark "
          "({}) < commit_idx "
          "({})",
          state->my_node_id,
          from,
          r.prev_idx,
          state->bft_watermark_idx,
          state->commit_idx);
        return;
      }
      else if (r.prev_idx > state->last_idx)
      {
        LOG_DEBUG_FMT(
          "Recv append entries to {} from {} but prev_idx ({}) > last_idx ({})",
          state->my_node_id,
          from,
          r.prev_idx,
          state->last_idx);
        return;
      }

      LOG_DEBUG_FMT(
        "Recv append entries to {} from {} for index {} and previous index {}",
        state->my_node_id.trim(),
        from.trim(),
        r.idx,
        r.prev_idx);

      if (is_new_follower)
      {
        if (state->last_idx > r.prev_idx)
        {
          LOG_DEBUG_FMT(
            "New follower received first append entries with mismatch - "
            "rolling back from {} to {}",
            state->last_idx,
            r.prev_idx);
          auto rollback_level = r.prev_idx;
          if (consensus_type == ConsensusType::BFT)
          {
            auto progress_tracker = store->get_progress_tracker();
            rollback_level = progress_tracker->get_rollback_seqno();
          }
          rollback(rollback_level);
        }
        else
        {
          LOG_DEBUG_FMT(
            "New follower has no conflict with prev_idx {}", r.prev_idx);
        }
        is_new_follower = false;
      }

      std::vector<
        std::tuple<std::unique_ptr<kv::AbstractExecutionWrapper>, kv::Version>>
        append_entries;
      // Finally, deserialise each entry in the batch
      for (Index i = r.prev_idx + 1; i <= r.idx; i++)
      {
        if (i <= state->last_idx)
        {
          // If the current entry has already been deserialised, skip the
          // payload for that entry
          ledger->skip_entry(data, size);
          continue;
        }

        LOG_DEBUG_FMT(
          "Replicating on follower {}: {}", state->my_node_id.trim(), i);

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
            state->my_node_id,
            from,
            e.what());
          send_append_entries_response(from, AppendEntriesResponseType::FAIL);
          return;
        }

        auto ds = store->apply(entry, consensus_type, public_only);
        if (ds == nullptr)
        {
          LOG_FAIL_FMT(
            "Recv append entries to {} from {} but the entry could not be "
            "deserialised",
            state->my_node_id,
            from);
          send_append_entries_response(from, AppendEntriesResponseType::FAIL);
          return;
        }
        append_entries.push_back(std::make_tuple(std::move(ds), i));
      }

      is_execution_pending = true;
      auto msg = std::make_unique<threading::Tmsg<AsyncExecution>>(
        execute_append_entries_cb,
        this,
        std::move(append_entries),
        from,
        std::move(r),
        confirm_evidence);

      if (threading::ThreadMessaging::thread_count > 1)
      {
        threading::ThreadMessaging::thread_messaging.add_task(
          threading::ThreadMessaging::get_execution_thread(
            threading::MAIN_THREAD_ID),
          std::move(msg));
      }
      else
      {
        apply_execution_message(std::move(msg));
      }
    }

    struct AsyncExecutionRet
    {
      AsyncExecutionRet(
        Aft<LedgerProxy, ChannelProxy, SnapshotterProxy>* self_) :
        self(self_)
      {}

      Aft<LedgerProxy, ChannelProxy, SnapshotterProxy>* self;
    };

    static void execute_append_entries_cb(
      std::unique_ptr<threading::Tmsg<AsyncExecution>> msg)
    {
      auto self = msg->data.self;
      std::unique_lock<std::mutex> guard(self->state->lock);
      self->apply_execution_message(std::move(msg));
    }

    void apply_execution_message(
      std::unique_ptr<threading::Tmsg<AsyncExecution>> msg)
    {
      auto self = msg->data.self;
      if (self->consensus_type == ConsensusType::CFT)
      {
        self->execute_append_entries_sync(msg);
      }
      else
      {
        if (
          self->execute_append_entries_async(msg) ==
          AsyncSchedulingResult::SYNCH_POINT)
        {
          return;
        }
      }

      auto msg_ret = std::make_unique<threading::Tmsg<AsyncExecutionRet>>(
        continue_execution, self);
      if (threading::ThreadMessaging::thread_count > 1)
      {
        threading::ThreadMessaging::thread_messaging.add_task(
          threading::MAIN_THREAD_ID, std::move(msg_ret));
      }
      else
      {
        msg_ret->cb(std::move(msg_ret));
      }
    }

    static void continue_execution(
      std::unique_ptr<threading::Tmsg<AsyncExecutionRet>> msg)
    {
      msg->data.self->is_execution_pending = false;
      msg->data.self->try_execute_pending();
    }

    struct AsyncExecTxMsg
    {
      AsyncExecTxMsg(
        Aft<LedgerProxy, ChannelProxy, SnapshotterProxy>* self_,
        std::unique_ptr<kv::AbstractExecutionWrapper>&& ds_,
        kv::Version last_idx_,
        kv::Version commit_idx_,
        uint16_t scheduler_thread_) :
        self(self_),
        ds(std::move(ds_)),
        last_idx(last_idx_),
        commit_idx(commit_idx_),
        scheduler_thread(scheduler_thread_)
      {}

      Aft<LedgerProxy, ChannelProxy, SnapshotterProxy>* self;
      std::unique_ptr<kv::AbstractExecutionWrapper> ds;
      kv::Version last_idx;
      kv::Version commit_idx;
      uint16_t scheduler_thread;
      std::shared_ptr<AsyncExecutor> ctx;
    };

    // This code is duplicated in part by execute_append_entries_async. This is
    // done to de-risk the version 1.0 released. These two functions should be
    // combined post 1.0.
    void execute_append_entries_sync(
      std::unique_ptr<threading::Tmsg<AsyncExecution>>& msg)
    {
      std::vector<
        std::tuple<std::unique_ptr<kv::AbstractExecutionWrapper>, kv::Version>>&
        append_entries = msg->data.append_entries;
      AppendEntries& r = msg->data.r;
      auto& from = msg->data.from;
      bool confirm_evidence = msg->data.confirm_evidence;

      for (auto& ae : append_entries)
      {
        auto& [ds, i] = ae;
        state->last_idx = i;

        kv::ApplyResult apply_success = ds->apply();
        if (apply_success == kv::ApplyResult::FAIL)
        {
          state->last_idx = i - 1;
          ledger->truncate(state->last_idx);
          send_append_entries_response(from, AppendEntriesResponseType::FAIL);
          return;
        }

        for (auto& hook : ds->get_hooks())
        {
          hook->call(this);
        }

        bool globally_committable =
          (apply_success == kv::ApplyResult::PASS_SIGNATURE);
        bool force_ledger_chunk = false;
        if (globally_committable)
        {
          force_ledger_chunk = snapshotter->record_committable(i);
        }

        ledger->put_entry(
          ds->get_entry(), globally_committable, force_ledger_chunk);

        switch (apply_success)
        {
          case kv::ApplyResult::FAIL:
          {
            LOG_FAIL_FMT("Follower failed to apply log entry: {}", i);
            state->last_idx--;
            ledger->truncate(state->last_idx);
            send_append_entries_response(
              msg->data.from, AppendEntriesResponseType::FAIL);
            break;
          }

          case kv::ApplyResult::PASS_SIGNATURE:
          {
            LOG_DEBUG_FMT("Deserialising signature at {}", i);
            auto prev_lci = last_committable_index();
            if (retirement_idx.has_value())
            {
              CCF_ASSERT_FMT(
                i >= retirement_idx.value(),
                "Index {} unexpectedly lower than retirement_idx {}",
                i,
                retirement_idx.value());
              retirement_committable_idx = i;
              LOG_INFO_FMT("Node retirement committable at {}", i);
            }
            committable_indices.push_back(i);

            if (ds->get_term())
            {
              // A signature for sig_term tells us that all transactions from
              // the previous signature onwards (at least, if not further back)
              // happened in sig_term. We reflect this in the history.
              if (r.term_of_idx == aft::ViewHistory::InvalidView)
              {
                state->view_history.update(1, r.term);
              }
              else
              {
                state->view_history.update(prev_lci + 1, ds->get_term());
              }
              commit_if_possible(r.leader_commit_idx);
            }
            if (consensus_type == ConsensusType::BFT)
            {
              send_append_entries_signed_response(
                msg->data.from, ds->get_signature());
            }
            break;
          }

          case kv::ApplyResult::PASS:
          {
            break;
          }

          case kv::ApplyResult::PASS_SNAPSHOT_EVIDENCE:
          case kv::ApplyResult::PASS_ENCRYPTED_PAST_LEDGER_SECRET:
          {
            break;
          }

          default:
          {
            throw std::logic_error("Unknown ApplyResult value");
          }
        }
      }

      execute_append_entries_finish(confirm_evidence, r, from);
    }

    bool process_async_execution(
      kv::ApplyResult apply_result,
      std::unique_ptr<kv::AbstractExecutionWrapper>& ds,
      kv::Version i,
      AppendEntries& r,
      const ccf::NodeId& from)
    {
      if (apply_result == kv::ApplyResult::FAIL)
      {
        // Setting last_idx to i-1 is a work around that should be fixed
        // shortly. In BFT mode when we deserialize and realize we need to
        // create a new map we remember this. If we need to create the same
        // map multiple times (for tx in the same group of append entries) the
        // first create successes but the second fails because the map is
        // already there. This works around the problem by stopping just
        // before the 2nd create (which failed at this point) and when the
        // primary resends the append entries we will succeed as the map is
        // already there. This will only occur on BFT startup so not a perf
        // problem but still need to be resolved.
        // https://github.com/microsoft/CCF/issues/2799
        if (ds->should_rollback_to_last_committed())
        {
          auto progress_tracker = store->get_progress_tracker();
          ccf::SeqNo rollback_level = progress_tracker->get_rollback_seqno();
          rollback(rollback_level);
        }
        else
        {
          state->last_idx = i - 1;
          ledger->truncate(state->last_idx);
        }
        send_append_entries_response(from, AppendEntriesResponseType::FAIL);
        return false;
      }

      for (auto& hook : ds->get_hooks())
      {
        hook->call(this);
      }

      bool globally_committable =
        (apply_result == kv::ApplyResult::PASS_SIGNATURE);
      bool force_ledger_chunk = false;
      if (globally_committable)
      {
        force_ledger_chunk = snapshotter->record_committable(i);
      }

      ledger->put_entry(
        ds->get_entry(), globally_committable, force_ledger_chunk);

      switch (apply_result)
      {
        case kv::ApplyResult::FAIL:
        {
          LOG_FAIL_FMT("Follower failed to apply log entry: {}", i);
          state->last_idx--;
          ledger->truncate(state->last_idx);
          send_append_entries_response(from, AppendEntriesResponseType::FAIL);
          break;
        }

        case kv::ApplyResult::PASS_SIGNATURE:
        {
          LOG_DEBUG_FMT("Deserialising signature at {}", i);
          auto prev_lci = last_committable_index();
          committable_indices.push_back(i);

          if (ds->get_term())
          {
            // A signature for sig_term tells us that all transactions from
            // the previous signature onwards (at least, if not further back)
            // happened in sig_term. We reflect this in the history.
            if (r.term_of_idx == aft::ViewHistory::InvalidView)
            {
              state->last_idx = executor->execute_request(
                ds->get_request(),
                request_tracker,
                state->last_idx,
                ds->get_max_conflict_version(),
                ds->get_term());
            }
            else
            {
              state->view_history.update(prev_lci + 1, ds->get_term());
            }
            commit_if_possible(r.leader_commit_idx);
          }
          send_append_entries_signed_response(from, ds->get_signature());
          break;
        }

        case kv::ApplyResult::PASS_BACKUP_SIGNATURE:
        {
          break;
        }
        case kv::ApplyResult::PASS_NEW_VIEW:
        {
          view_change_tracker->clear(
            get_primary(ds->get_term()) == id(), ds->get_term());
          request_tracker->clear();
          break;
        }

        case kv::ApplyResult::PASS_BACKUP_SIGNATURE_SEND_ACK:
        {
          try_send_sig_ack(
            {ds->get_term(), ds->get_index()},
            kv::TxHistory::Result::SEND_SIG_RECEIPT_ACK);
          break;
        }

        case kv::ApplyResult::PASS_NONCES:
        {
          request_tracker->insert_signed_request(
            state->last_idx,
            threading::ThreadMessaging::thread_messaging
              .get_current_time_offset());
          break;
        }

        case kv::ApplyResult::PASS:
        {
          if (threading::ThreadMessaging::thread_count != 1)
          {
            auto tmsg = std::make_unique<threading::Tmsg<AsyncExecTxMsg>>(
              [](std::unique_ptr<threading::Tmsg<AsyncExecTxMsg>> msg) {
                auto self = msg->data.self;
                self->executor->execute_request(
                  msg->data.ds->get_request(),
                  self->request_tracker,
                  msg->data.last_idx,
                  msg->data.ds->get_max_conflict_version(),
                  msg->data.ds->get_term());

                if (threading::ThreadMessaging::thread_count == 1)
                {
                  return;
                }

                msg->reset_cb(
                  [](std::unique_ptr<threading::Tmsg<AsyncExecTxMsg>> msg) {
                    auto self = msg->data.self;
                    if (
                      self->async_executor.decrement_pending() ==
                      AsyncSchedulingResult::DONE)
                    {
                      self->apply_execution_message(
                        std::move(self->async_exec_msg));
                    }
                  });
                uint16_t scheduler_thread = msg->data.scheduler_thread;
                threading::ThreadMessaging::thread_messaging.add_task(
                  scheduler_thread, std::move(msg));
              },
              this,
              std::move(ds),
              state->last_idx,
              state->commit_idx,
              threading::get_current_thread_id());

            async_executor.increment_pending();
            threading::ThreadMessaging::thread_messaging.add_task(
              threading::ThreadMessaging::get_execution_thread(
                ++next_exec_thread),
              std::move(tmsg));
          }
          else
          {
            executor->execute_request(
              ds->get_request(),
              request_tracker,
              state->last_idx,
              ds->get_max_conflict_version(),
              ds->get_term());
          }
          break;
        }
        case kv::ApplyResult::PASS_APPLY:
        {
          if (!ds->is_public_only())
          {
            executor->mark_request_executed(ds->get_request(), request_tracker);
          }
          break;
        }
        case kv::ApplyResult::PASS_ENCRYPTED_PAST_LEDGER_SECRET:
        case kv::ApplyResult::PASS_SNAPSHOT_EVIDENCE:
        {
          break;
        }

        default:
        {
          throw std::logic_error("Unknown ApplyResult value");
        }
      }
      return true;
    }

    AsyncSchedulingResult execute_append_entries_async(
      std::unique_ptr<threading::Tmsg<AsyncExecution>>& msg)
    {
      // This function is responsible for selecting the next batch of
      // transactions to execute concurrently and then starting said
      // execution.
      std::vector<
        std::tuple<std::unique_ptr<kv::AbstractExecutionWrapper>, kv::Version>>&
        append_entries = msg->data.append_entries;
      AppendEntries& r = msg->data.r;
      bool confirm_evidence = msg->data.confirm_evidence;
      auto& from = msg->data.from;
      async_exec_msg = std::move(msg);
      async_executor.execute_as_far_as_possible(state->last_idx);
      while (async_exec_msg->data.next_append_entry_index !=
             append_entries.size())
      {
        auto& [ds, i] =
          append_entries[async_exec_msg->data.next_append_entry_index];
        if (!async_executor.should_exec_next_append_entry(
              ds->support_async_execution(), ds->get_max_conflict_version()))
        {
          return AsyncSchedulingResult::SYNCH_POINT;
        }

        ++async_exec_msg->data.next_append_entry_index;
        state->last_idx = i;

        kv::ApplyResult apply_result = ds->apply();
        if (!process_async_execution(apply_result, ds, i, r, from))
        {
          return AsyncSchedulingResult::DONE;
        }
      }

      if (async_executor.execution_status() == AsyncSchedulingResult::DONE)
      {
        execute_append_entries_finish(confirm_evidence, r, from);
        return AsyncSchedulingResult::DONE;
      }
      return AsyncSchedulingResult::SYNCH_POINT;
    }

    void execute_append_entries_finish(
      bool confirm_evidence, AppendEntries& r, const ccf::NodeId& from)
    {
      if (
        consensus_type == ConsensusType::BFT && confirm_evidence &&
        !view_change_tracker->check_evidence(r.term))
      {
        rollback(last_committable_index());
        LOG_DEBUG_FMT(
          "Recv append entries to {} from {} at view:{} but we do not have "
          "the evidence to support this view, append message was marked as "
          "containing evidence",
          state->my_node_id,
          from,
          r.term);
        send_append_entries_response(
          from, AppendEntriesResponseType::REQUIRE_EVIDENCE);
        return;
      }

      // After entries have been deserialised, try to commit the leader's
      // commit index and update our term history accordingly
      commit_if_possible(r.leader_commit_idx);

      // The term may have changed, and we have not have seen a signature yet.
      auto lci = last_committable_index();
      if (r.term_of_idx == aft::ViewHistory::InvalidView)
      {
        state->view_history.update(1, r.term);
      }
      else
      {
        state->view_history.update(lci + 1, r.term_of_idx);
      }

      send_append_entries_response(from, AppendEntriesResponseType::OK);
    }

    void send_append_entries_response(
      ccf::NodeId to, AppendEntriesResponseType answer)
    {
      LOG_DEBUG_FMT(
        "Send append entries response from {} to {} for index {}: {}",
        state->my_node_id.trim(),
        to.trim(),
        state->last_idx,
        answer);

      if (answer == AppendEntriesResponseType::REQUIRE_EVIDENCE)
      {
        state->requested_evidence_from = to;
      }

      AppendEntriesResponse response = {{raft_append_entries_response},
                                        state->current_view,
                                        state->last_idx,
                                        answer};

      channels->send_authenticated(
        to, ccf::NodeMsgType::consensus_msg, response);
    }

    void send_append_entries_signed_response(
      ccf::NodeId to, ccf::PrimarySignature& sig)
    {
      LOG_DEBUG_FMT(
        "Send append entries signed response from {} to {} for index {}",
        state->my_node_id.trim(),
        to.trim(),
        state->last_idx);

      auto progress_tracker = store->get_progress_tracker();
      CCF_ASSERT(progress_tracker != nullptr, "progress_tracker is not set");

      SignedAppendEntriesResponse r = {{raft_append_entries_signed_response},
                                       state->current_view,
                                       state->last_idx,
                                       {},
                                       static_cast<uint32_t>(sig.sig.size()),
                                       {}};

      std::optional<crypto::Sha256Hash> hashed_nonce;
      progress_tracker->get_node_hashed_nonce(
        {state->current_view, state->last_idx}, hashed_nonce);
      if (!hashed_nonce.has_value())
      {
        LOG_TRACE_FMT(
          "Nonce for view:{}, seqno:{} does not exist",
          state->current_view,
          state->last_idx);
        return;
      }
      r.hashed_nonce = hashed_nonce.value();

      std::copy(sig.sig.begin(), sig.sig.end(), r.sig.data());

      auto result = progress_tracker->add_signature(
        {r.term, r.last_log_idx},
        state->my_node_id,
        r.signature_size,
        r.sig,
        r.hashed_nonce,
        get_last_configuration_nodes(),
        is_primary());

      for (auto it = nodes.begin(); it != nodes.end(); ++it)
      {
        auto to = it->first;
        if (to != state->my_node_id)
        {
          channels->send_authenticated(to, ccf::NodeMsgType::consensus_msg, r);
        }
      }

      try_send_sig_ack({r.term, r.last_log_idx}, result);
    }

    void recv_append_entries_signed_response(
      const ccf::NodeId& from, SignedAppendEntriesResponse r)
    {
      auto node = nodes.find(from);
      if (node == nodes.end())
      {
        // Ignore if we don't recognise the node.
        LOG_FAIL_FMT(
          "Recv signed append entries response to {} from {}: unknown node",
          state->my_node_id,
          from);
        return;
      }

      auto progress_tracker = store->get_progress_tracker();
      CCF_ASSERT(progress_tracker != nullptr, "progress_tracker is not set");
      auto result = progress_tracker->add_signature(
        {r.term, r.last_log_idx},
        from,
        r.signature_size,
        r.sig,
        r.hashed_nonce,
        get_last_configuration_nodes(),
        is_primary());
      try_send_sig_ack({r.term, r.last_log_idx}, result);
    }

    void try_send_sig_ack(ccf::TxID tx_id, kv::TxHistory::Result r)
    {
      switch (r)
      {
        case kv::TxHistory::Result::OK:
        case kv::TxHistory::Result::FAIL:
        {
          break;
        }
        case kv::TxHistory::Result::SEND_SIG_RECEIPT_ACK:
        {
          SignaturesReceivedAck r = {
            {bft_signature_received_ack}, tx_id.view, tx_id.seqno};
          for (auto it = nodes.begin(); it != nodes.end(); ++it)
          {
            auto to = it->first;
            if (to != state->my_node_id)
            {
              channels->send_authenticated(
                to, ccf::NodeMsgType::consensus_msg, r);
            }
          }

          auto progress_tracker = store->get_progress_tracker();
          CCF_ASSERT(
            progress_tracker != nullptr, "progress_tracker is not set");
          auto result = progress_tracker->add_signature_ack(
            tx_id, state->my_node_id, get_last_configuration_nodes());
          try_send_reply_and_nonce(tx_id, result);
          break;
        }
        default:
        {
          throw ccf::ccf_logic_error(fmt::format("Unknown enum type: {}", r));
        }
      }
    }

    void recv_signature_received_ack(
      const ccf::NodeId& from, SignaturesReceivedAck r)
    {
      auto node = nodes.find(from);
      if (node == nodes.end())
      {
        // Ignore if we don't recognise the node.
        LOG_FAIL_FMT(
          "Recv signature received ack to {} from {}: unknown node",
          state->my_node_id,
          from);
        return;
      }

      auto progress_tracker = store->get_progress_tracker();
      CCF_ASSERT(progress_tracker != nullptr, "progress_tracker is not set");
      LOG_TRACE_FMT(
        "processing recv_signature_received_ack, from:{} view:{}, seqno:{}",
        from.trim(),
        r.term,
        r.idx);

      auto result = progress_tracker->add_signature_ack(
        {r.term, r.idx}, from, get_last_configuration_nodes());
      try_send_reply_and_nonce({r.term, r.idx}, result);
    }

    void try_send_reply_and_nonce(ccf::TxID tx_id, kv::TxHistory::Result r)
    {
      switch (r)
      {
        case kv::TxHistory::Result::OK:
        case kv::TxHistory::Result::FAIL:
        {
          break;
        }
        case kv::TxHistory::Result::SEND_REPLY_AND_NONCE:
        {
          std::optional<Nonce> nonce;
          auto progress_tracker = store->get_progress_tracker();
          CCF_ASSERT(
            progress_tracker != nullptr, "progress_tracker is not set");
          nonce = progress_tracker->get_node_nonce(tx_id);
          if (!nonce.has_value())
          {
            break;
          }
          NonceRevealMsg r = {
            {bft_nonce_reveal}, tx_id.view, tx_id.seqno, nonce.value()};

          for (auto it = nodes.begin(); it != nodes.end(); ++it)
          {
            auto to = it->first;
            if (to != state->my_node_id)
            {
              channels->send_authenticated(
                to, ccf::NodeMsgType::consensus_msg, r);
            }
          }
          progress_tracker->add_nonce_reveal(
            tx_id,
            nonce.value(),
            state->my_node_id,
            get_last_configuration_nodes(),
            is_primary(),
            tx_id.seqno <= state->last_idx);
          break;
        }
        default:
        {
          throw ccf::ccf_logic_error(fmt::format("Unknown enum type: {}", r));
        }
      }
    }

    void recv_nonce_reveal(const ccf::NodeId& from, NonceRevealMsg r)
    {
      auto node = nodes.find(from);
      if (node == nodes.end())
      {
        // Ignore if we don't recognise the node.
        LOG_FAIL_FMT(
          "Recv nonce reveal to {} from {}: unknown node",
          state->my_node_id,
          from);
        return;
      }

      auto progress_tracker = store->get_progress_tracker();
      CCF_ASSERT(progress_tracker != nullptr, "progress_tracker is not set");
      LOG_TRACE_FMT(
        "processing nonce_reveal, from:{} view:{}, seqno:{}",
        from.trim(),
        r.term,
        r.idx);
      progress_tracker->add_nonce_reveal(
        {r.term, r.idx},
        r.nonce,
        from,
        get_last_configuration_nodes(),
        is_primary(),
        r.idx <= state->last_idx);

      update_commit();
    }

    void recv_append_entries_response(
      const ccf::NodeId& from, AppendEntriesResponse r)
    {
      std::lock_guard<std::mutex> guard(state->lock);
      // Ignore if we're not the leader.

      if (replica_state != kv::ReplicaState::Leader)
      {
        return;
      }

      auto node = nodes.find(from);
      if (node == nodes.end())
      {
        // Ignore if we don't recognise the node.
        LOG_FAIL_FMT(
          "Recv append entries response to {} from {}: unknown node",
          state->my_node_id,
          from);
        return;
      }
      else if (state->current_view < r.term)
      {
        // We are behind, update our state.
        LOG_DEBUG_FMT(
          "Recv append entries response to {} from {}: more recent term ({} "
          "> {})",
          state->my_node_id,
          from,
          r.term,
          state->current_view);
        become_aware_of_new_term(r.term);
        return;
      }
      else if (state->current_view != r.term)
      {
        // Stale response, discard if success.
        // Otherwise reset sent_idx and try again.
        LOG_DEBUG_FMT(
          "Recv append entries response to {} from {}: stale term ({} != {})",
          state->my_node_id,
          from,
          r.term,
          state->current_view);
        if (r.success == AppendEntriesResponseType::OK)
        {
          return;
        }
      }
      else if (r.last_log_idx < node->second.match_idx)
      {
        // Stale response, discard if success.
        // Otherwise reset sent_idx and try again.
        LOG_DEBUG_FMT(
          "Recv append entries response to {} from {}: stale idx",
          state->my_node_id,
          from);
        if (r.success == AppendEntriesResponseType::OK)
        {
          return;
        }
      }

      // Update next and match for the responding node.
      node->second.match_idx = std::min(r.last_log_idx, state->last_idx);

      if (r.success == AppendEntriesResponseType::REQUIRE_EVIDENCE)
      {
        // We need to provide evidence to the replica that we can send it append
        // entries. This should only happened if there is some kind of network
        // partition.
        ViewChangeEvidenceMsg vw = {{bft_view_change_evidence},
                                    state->current_view};

        std::vector<uint8_t> data =
          view_change_tracker->get_serialized_view_change_confirmation(
            state->current_view, id());

        data.insert(
          data.begin(),
          reinterpret_cast<uint8_t*>(&vw),
          reinterpret_cast<uint8_t*>(&vw) + sizeof(ViewChangeEvidenceMsg));

        LOG_DEBUG_FMT("Sending evidence to:{}", from);
        channels->send_authenticated(
          from, ccf::NodeMsgType::consensus_msg, data);
      }

      if (r.success != AppendEntriesResponseType::OK)
      {
        // Failed due to log inconsistency. Reset sent_idx and try again.
        LOG_DEBUG_FMT(
          "Recv append entries response to {} from {}: failed",
          state->my_node_id,
          from);
        send_append_entries(from, node->second.match_idx + 1);
        return;
      }

      LOG_DEBUG_FMT(
        "Recv append entries response to {} from {} for index {}: success",
        state->my_node_id.trim(),
        from.trim(),
        r.last_log_idx);
      update_commit();
    }

    void send_request_vote(const ccf::NodeId& to)
    {
      auto last_committable_idx = last_committable_index();
      LOG_INFO_FMT(
        "Send request vote from {} to {} at {}",
        state->my_node_id.trim(),
        to.trim(),
        last_committable_idx);
      CCF_ASSERT(last_committable_idx >= state->commit_idx, "lci < ci");

      RequestVote rv = {{raft_request_vote},
                        state->current_view,
                        last_committable_idx,
                        get_term_internal(last_committable_idx)};

      channels->send_authenticated(to, ccf::NodeMsgType::consensus_msg, rv);
    }

    void recv_request_vote(const ccf::NodeId& from, RequestVote r)
    {
      std::lock_guard<std::mutex> guard(state->lock);

      // Ignore if we don't recognise the node.
      auto node = nodes.find(from);
      if (node == nodes.end())
      {
        LOG_FAIL_FMT(
          "Recv request vote to {} from {}: unknown node",
          state->my_node_id,
          from);
        return;
      }

      if (state->current_view > r.term)
      {
        // Reply false, since our term is later than the received term.
        LOG_DEBUG_FMT(
          "Recv request vote to {} from {}: our term is later ({} > {})",
          state->my_node_id,
          from,
          state->current_view,
          r.term);
        send_request_vote_response(from, false);
        return;
      }
      else if (state->current_view < r.term)
      {
        LOG_DEBUG_FMT(
          "Recv request vote to {} from {}: their term is later ({} < {})",
          state->my_node_id,
          from,
          state->current_view,
          r.term);
        become_aware_of_new_term(r.term);
      }

      if ((voted_for.has_value()) && (voted_for.value() != from))
      {
        // Reply false, since we already voted for someone else.
        LOG_DEBUG_FMT(
          "Recv request vote to {} from {}: already voted for {}",
          state->my_node_id,
          from,
          voted_for.value());
        send_request_vote_response(from, false);
        return;
      }

      // If the candidate's committable log is at least as up-to-date as ours,
      // vote yes

      const auto last_committable_idx = last_committable_index();
      const auto term_of_last_committable_idx =
        get_term_internal(last_committable_idx);

      const auto answer =
        (r.term_of_last_committable_idx > term_of_last_committable_idx) ||
        ((r.term_of_last_committable_idx == term_of_last_committable_idx) &&
         (r.last_committable_idx >= last_committable_idx));

      if (answer)
      {
        // If we grant our vote, we also acknowledge that an election is in
        // progress.
        restart_election_timeout();
        leader_id.reset();
        voted_for = from;
      }
      else
      {
        LOG_INFO_FMT(
          "Voting against candidate at {}.{} because local state is at {}.{}",
          r.term_of_last_committable_idx,
          r.last_committable_idx,
          term_of_last_committable_idx,
          last_committable_idx);
      }

      send_request_vote_response(from, answer);
    }

    void send_request_vote_response(const ccf::NodeId& to, bool answer)
    {
      LOG_INFO_FMT(
        "Send request vote response from {} to {}: {}",
        state->my_node_id.trim(),
        to.trim(),
        answer);

      RequestVoteResponse response = {
        {raft_request_vote_response}, state->current_view, answer};

      channels->send_authenticated(
        to, ccf::NodeMsgType::consensus_msg, response);
    }

    void recv_request_vote_response(
      const ccf::NodeId& from, RequestVoteResponse r)
    {
      std::lock_guard<std::mutex> guard(state->lock);

      if (replica_state != kv::ReplicaState::Candidate)
      {
        LOG_INFO_FMT(
          "Recv request vote response to {}: we aren't a candidate",
          state->my_node_id);
        return;
      }

      // Ignore if we don't recognise the node.
      auto node = nodes.find(from);
      if (node == nodes.end())
      {
        LOG_INFO_FMT(
          "Recv request vote response to {} from {}: unknown node",
          state->my_node_id,
          from);
        return;
      }

      if (state->current_view < r.term)
      {
        LOG_INFO_FMT(
          "Recv request vote response to {} from {}: their term is more recent "
          "({} < {})",
          state->my_node_id,
          from,
          state->current_view,
          r.term);
        become_aware_of_new_term(r.term);
        return;
      }
      else if (state->current_view != r.term)
      {
        // Ignore as it is stale.
        LOG_INFO_FMT(
          "Recv request vote response to {} from {}: stale ({} != {})",
          state->my_node_id,
          from,
          state->current_view,
          r.term);
        return;
      }
      else if (!r.vote_granted)
      {
        // Do nothing.
        LOG_INFO_FMT(
          "Recv request vote response to {} from {}: they voted no",
          state->my_node_id,
          from);
        return;
      }

      LOG_INFO_FMT(
        "Recv request vote response to {} from {}: they voted yes",
        state->my_node_id,
        from);

      add_vote_for_me(from);
    }

    void restart_election_timeout()
    {
      // Randomise timeout_elapsed to get a random election timeout
      // between 0.5x and 1x the configured election timeout.
      timeout_elapsed = std::chrono::milliseconds(distrib(rand));
    }

    void become_candidate()
    {
      replica_state = kv::ReplicaState::Candidate;
      leader_id.reset();
      voted_for = state->my_node_id;
      votes_for_me.clear();
      state->current_view++;

      restart_election_timeout();
      add_vote_for_me(state->my_node_id);

      LOG_INFO_FMT(
        "Becoming candidate {}: {}", state->my_node_id, state->current_view);

      if (consensus_type != ConsensusType::BFT)
      {
        for (auto it = nodes.begin(); it != nodes.end(); ++it)
        {
          channels->create_channel(
            it->first,
            it->second.node_info.hostname,
            it->second.node_info.port);
          send_request_vote(it->first);
        }
      }
    }

    void become_leader(bool force_become_leader = false)
    {
      if (is_retired())
      {
        return;
      }

      // When we force to become the primary we are going around the
      // consensus protocol. This only happens when a node starts a new network
      // and have a gensis or recovery tx as the last transaction, for BFT this
      // transaction is not prepared and but must not be rolled back.
      if (consensus_type == ConsensusType::BFT && !force_become_leader)
      {
        auto progress_tracker = store->get_progress_tracker();
        election_index = progress_tracker->get_rollback_seqno();
      }
      else
      {
        election_index = last_committable_index();
      }
      LOG_DEBUG_FMT(
        "Election index is {} in term {}", election_index, state->current_view);
      // Discard any un-committable updates we may hold,
      // since we have no signature for them. Except at startup,
      // where we do not want to roll back the genesis transaction.
      if (state->commit_idx > 0)
      {
        rollback(election_index);
      }
      else
      {
        // but we still want the KV to know which term we're in
        store->initialise_term(state->current_view);
      }

      replica_state = kv::ReplicaState::Leader;
      leader_id = state->my_node_id;

      using namespace std::chrono_literals;
      timeout_elapsed = 0ms;

      LOG_INFO_FMT(
        "Becoming leader {}: {}", state->my_node_id, state->current_view);

      // Immediately commit if there are no other nodes.
      if (nodes.size() == 0)
      {
        commit(state->last_idx);
        return;
      }

      // Reset next, match, and sent indices for all nodes.
      auto next = state->last_idx + 1;

      for (auto it = nodes.begin(); it != nodes.end(); ++it)
      {
        it->second.match_idx = 0;
        it->second.sent_idx = next - 1;

        // Send an empty append_entries to all nodes.
        send_append_entries(it->first, next);
      }
    }

    bool can_advance_watermark()
    {
      return replica_state != kv::ReplicaState::Retired &&
        replica_state != kv::ReplicaState::Learner;
    }

    bool can_endorse_primary()
    {
      return replica_state != kv::ReplicaState::Retired &&
        replica_state != kv::ReplicaState::Learner;
    }

    // Called when a replica becomes aware of the existence of a new term
    // If retired already, state remains unchanged, but the replica otherwise
    // becomes a follower in the new term.
    void become_aware_of_new_term(Term term)
    {
      leader_id.reset();
      restart_election_timeout();

      state->current_view = term;
      voted_for.reset();
      votes_for_me.clear();

      if (consensus_type == ConsensusType::BFT)
      {
        auto progress_tracker = store->get_progress_tracker();
        ccf::SeqNo rollback_level = progress_tracker->get_rollback_seqno();
        rollback(rollback_level);
        view_change_tracker->set_current_view_change(state->current_view);
      }
      else
      {
        rollback(last_committable_index());
      }

      is_new_follower = true;

      if (can_endorse_primary())
      {
        replica_state = kv::ReplicaState::Follower;
        LOG_INFO_FMT(
          "Becoming follower {}: {}", state->my_node_id, state->current_view);
      }
    }

    void become_retiring()
    {
      assert(use_two_tx_reconfig);

      LOG_INFO_FMT(
        "Becoming retiring {}: {}", state->my_node_id, state->current_view);

      replica_state = kv::ReplicaState::Retiring;
      leader_id.reset();

      CCF_ASSERT_FMT(
        !retirement_idx.has_value(),
        "retirement_idx already set to {}",
        retirement_idx.value());
      retirement_idx = state->commit_idx;
      LOG_INFO_FMT("Node retiring at {}", state->commit_idx);
    }

    void become_retired()
    {
      replica_state = kv::ReplicaState::Retired;
      leader_id.reset();

      LOG_INFO_FMT(
        "Becoming retired {}: {}", state->my_node_id, state->current_view);
    }

    void add_vote_for_me(const ccf::NodeId& from)
    {
      size_t quorum = -1;

      if (use_two_tx_reconfig)
      {
        const auto& cfg = configurations.front();

        if (cfg.nodes.find(from) == cfg.nodes.end())
        {
          LOG_INFO_FMT("Ignoring vote from ineligible voter {}", from);
          return;
        }

        // Need 50% + 1 of the total nodes in the current config (including us).
        votes_for_me.insert(from);
        quorum = get_quorum(cfg);
      }
      else
      {
        // Need 50% + 1 of the total nodes, which are the other nodes plus us.
        votes_for_me.insert(from);
        quorum = ((nodes.size() + 1) / 2) + 1;
      }

      if (votes_for_me.size() >= quorum)
      {
        become_leader();
      }
    }

    void update_commit()
    {
      // If there exists some idx in the current term such that
      // idx > commit_idx and a majority of nodes have replicated it,
      // commit to that idx.
      auto new_commit_cft_idx = std::numeric_limits<Index>::max();
      auto new_commit_bft_idx = std::numeric_limits<Index>::max();

      // Obtain BFT watermarks
      auto progress_tracker = store->get_progress_tracker();
      if (progress_tracker != nullptr)
      {
        new_commit_bft_idx = progress_tracker->get_highest_committed_level();
      }

      // Obtain CFT watermarks
      for (auto& c : configurations)
      {
        // The majority must be checked separately for each active
        // configuration.
        std::vector<Index> match;
        match.reserve(c.nodes.size() + 1);

        for (auto node : c.nodes)
        {
          if (node.first == state->my_node_id)
          {
            match.push_back(state->last_idx);
          }
          else
          {
            match.push_back(nodes.at(node.first).match_idx);
          }
        }

        sort(match.begin(), match.end());
        auto confirmed = match.at((match.size() - 1) / 2);

        if (confirmed < new_commit_cft_idx)
        {
          new_commit_cft_idx = confirmed;
        }
      }
      LOG_DEBUG_FMT(
        "In update_commit, new_commit_cft_idx: {}, new_commit_bft_idx:{}. "
        "last_idx: {}",
        new_commit_cft_idx,
        new_commit_bft_idx,
        state->last_idx);

      if (new_commit_cft_idx != std::numeric_limits<Index>::max())
      {
        state->cft_watermark_idx = new_commit_cft_idx;
      }

      if (new_commit_bft_idx != std::numeric_limits<Index>::max())
      {
        state->bft_watermark_idx = new_commit_bft_idx;
      }

      if (get_commit_watermark_idx() > state->last_idx)
      {
        throw std::logic_error(
          "Followers appear to have later match indices than leader");
      }

      commit_if_possible(get_commit_watermark_idx());
    }

    void commit_if_possible(Index idx)
    {
      LOG_DEBUG_FMT(
        "Commit if possible {} (ci: {}) (ti {})",
        idx,
        state->commit_idx,
        get_term_internal(idx));
      if (
        (idx > state->commit_idx) &&
        (get_term_internal(idx) <= state->current_view))
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
        {
          if (consensus_type == ConsensusType::CFT)
          {
            commit(highest_committable);
          }
          else
          {
            auto progress_tracker = store->get_progress_tracker();
            commit(progress_tracker->get_highest_committed_level());
          }
        }
      }
    }

    size_t num_trusted(const kv::Configuration& c) const
    {
      size_t r = 0;
      for (const auto& [id, _] : c.nodes)
      {
        if (
          nodes.find(id) != nodes.end() && learners.find(id) == learners.end())
        {
          r++;
        }
      }
      return r;
    }

    size_t get_quorum(const kv::Configuration& c) const
    {
      switch (consensus_type)
      {
        case CFT:
          return (c.nodes.size() / 2) + 1;
        case BFT:
          return (c.nodes.size() / 3) + 1;
        default:
          return -1;
      }
    }

    bool have_quorum(size_t n, const kv::Configuration& c) const
    {
      return n >= get_quorum(c);
    }

    bool enough_trusted(const kv::Configuration& c) const
    {
      return have_quorum(num_trusted(c), c);
    }

    void commit(Index idx)
    {
      if (idx > state->last_idx)
      {
        throw std::logic_error(fmt::format(
          "Tried to commit {} but last_idx is {}", idx, state->last_idx));
      }

      LOG_DEBUG_FMT("Starting commit");

      // This could happen if a follower becomes the leader when it
      // has committed fewer log entries, although it has them available.
      if (idx <= state->commit_idx)
        return;

      state->commit_idx = idx;
      if (
        retirement_committable_idx.has_value() &&
        idx >= retirement_committable_idx.value() &&
        (!use_two_tx_reconfig || is_retiring()))
      {
        become_retired();
      }

      LOG_DEBUG_FMT("Compacting...");
      // Snapshots are not yet supported with BFT
      snapshotter->commit(
        idx,
        replica_state == kv::ReplicaState::Leader &&
          consensus_type == ConsensusType::CFT);

      store->compact(idx);
      ledger->commit(idx);

      LOG_DEBUG_FMT("Commit on {}: {}", state->my_node_id.trim(), idx);

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

        if (!use_two_tx_reconfig)
        {
          configurations.pop_front();
          backup_nodes.clear();
          changed = true;
        }
        else
        {
          if (is_primary())
          {
            if (!enough_trusted(*next))
            {
              LOG_TRACE_FMT(
                "Configurations: not enough trusted nodes for next "
                "configuration");
              break;
            }
          }

          if (num_trusted(*next) == next->nodes.size())
          {
            LOG_TRACE_FMT(
              "Configurations: all nodes trusted, switching to next "
              "configuration");

            if (!is_retiring())
            {
              if (
                conf->nodes.find(state->my_node_id) != conf->nodes.end() &&
                next->nodes.find(state->my_node_id) == next->nodes.end())
              {
                become_retiring();
              }
            }

            configurations.pop_front();
          }
          else
          {
            break;
          }
        }
      }

      if (changed)
      {
        create_and_remove_node_state();
      }
    }

    Index get_commit_watermark_idx()
    {
      if (consensus_type == ConsensusType::BFT)
      {
        return state->bft_watermark_idx;
      }
      else
      {
        return state->cft_watermark_idx;
      }
    }

    const Configuration::Nodes& get_last_configuration_nodes()
    {
      if (configurations.empty())
      {
        throw std::logic_error("Configurations is empty");
      }
      return configurations.back().nodes;
    }

    void rollback(Index idx)
    {
      if (
        (consensus_type == ConsensusType::CFT && idx < state->commit_idx) ||
        (consensus_type == ConsensusType::BFT &&
         idx < state->bft_watermark_idx))
      {
        LOG_FAIL_FMT(
          "Asked to rollback to idx:{} but committed to commit_idx:{}, "
          "bft_watermark_idx:{} - ignoring rollback request",
          idx,
          state->commit_idx,
          state->bft_watermark_idx);
        return;
      }

      snapshotter->rollback(idx);
      store->rollback({get_term_internal(idx), idx}, state->current_view);
      LOG_DEBUG_FMT("Setting term in store to: {}", state->current_view);
      ledger->truncate(idx);
      state->last_idx = idx;
      LOG_DEBUG_FMT("Rolled back at {}", idx);

      while (!committable_indices.empty() && (committable_indices.back() > idx))
      {
        committable_indices.pop_back();
      }

      if (retirement_idx.has_value() && retirement_idx.value() > idx)
      {
        retirement_idx = std::nullopt;
      }

      if (
        retirement_committable_idx.has_value() &&
        retirement_committable_idx.value() > idx)
      {
        retirement_committable_idx = std::nullopt;
      }

      // Rollback configurations.
      bool changed = false;

      while (!configurations.empty() && (configurations.back().idx > idx))
      {
        configurations.pop_back();
        backup_nodes.clear();
        changed = true;
      }

      if (use_two_tx_reconfig && changed)
      {
        std::unordered_set<ccf::NodeId> to_erase;
        for (auto& [id, seqno] : learners)
        {
          if (seqno > idx)
          {
            to_erase.insert(id);
          }
        }
        for (auto& id : to_erase)
        {
          learners.erase(id);
        }
      }

      if (changed)
      {
        create_and_remove_node_state();
      }
    }

    void create_and_remove_node_state()
    {
      if (use_two_tx_reconfig && is_learner())
      {
        for (auto& cfg : configurations)
        {
          if (cfg.idx > state->commit_idx)
            break;

          if (
            cfg.nodes.find(state->my_node_id) != cfg.nodes.end() &&
            learners.find(state->my_node_id) != learners.end())
          {
            LOG_INFO_FMT("Configurations: ready for promotion");
            // Submit promotion RPC here.
            learners.erase(state->my_node_id);

            // The transition to follower will happen when the reconfiguration
            // transaction commits.
            LOG_INFO_FMT(
              "Becoming follower {}: {}",
              state->my_node_id,
              state->current_view);
            replica_state = kv::ReplicaState::Follower;
          }
        }
      }

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
      std::vector<ccf::NodeId> to_remove;

      for (auto& node : nodes)
      {
        if (active_nodes.find(node.first) == active_nodes.end())
        {
          to_remove.push_back(node.first);
        }
      }

      for (auto node_id : to_remove)
      {
        nodes.erase(node_id);
        LOG_INFO_FMT("Removed raft node {}", node_id);
      }

      // Add all active nodes that are not already present in the node state.
      for (auto node_info : active_nodes)
      {
        if (node_info.first == state->my_node_id)
        {
          continue;
        }

        if (nodes.find(node_info.first) == nodes.end())
        {
          // A new node is sent only future entries initially. If it does not
          // have prior data, it will communicate that back to the leader.
          auto index = state->last_idx + 1;
          nodes.try_emplace(node_info.first, node_info.second, index, 0);

          if (
            replica_state == kv::ReplicaState::Leader ||
            consensus_type == ConsensusType::BFT)
          {
            channels->create_channel(
              node_info.first,
              node_info.second.hostname,
              node_info.second.port);
          }

          if (replica_state == kv::ReplicaState::Leader)
          {
            send_append_entries(node_info.first, index);
          }

          LOG_INFO_FMT("Added raft node {}", node_info.first);
        }
      }
    }
  };
}
