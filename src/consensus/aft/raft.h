// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/ccf_exception.h"
#include "ccf/ds/logger.h"
#include "ccf/pal/locking.h"
#include "ccf/tx_id.h"
#include "ccf/tx_status.h"
#include "ds/serialized.h"
#include "enclave/reconfiguration_type.h"
#include "impl/state.h"
#include "kv/kv_types.h"
#include "node/node_client.h"
#include "node/node_to_node.h"
#include "node/node_types.h"
#include "node/resharing_tracker.h"
#include "node/retired_nodes_cleanup.h"
#include "orc_requests.h"
#include "raft_types.h"
#include "service/tables/signatures.h"

#include <algorithm>
#include <deque>
#include <list>
#include <random>
#include <unordered_map>
#include <vector>

namespace aft
{
  using Configuration = kv::Configuration;

  template <class LedgerProxy>
  class Aft : public kv::Consensus
  {
  private:
    struct NodeState
    {
      Configuration::NodeInfo node_info;

      // the highest index sent to the node
      Index sent_idx;

      // the highest matching index with the node that was confirmed
      Index match_idx;

      // timeout tracking the last time an ack was received from the node
      std::chrono::milliseconds last_ack_timeout;

      NodeState() = default;

      NodeState(
        const Configuration::NodeInfo& node_info_,
        Index sent_idx_,
        Index match_idx_ = 0) :
        node_info(node_info_),
        sent_idx(sent_idx_),
        match_idx(match_idx_),
        last_ack_timeout(0)
      {}
    };

    // Persistent
    ConsensusType consensus_type;
    std::unique_ptr<Store> store;

    // Volatile
    std::optional<ccf::NodeId> voted_for = std::nullopt;
    std::optional<ccf::NodeId> leader_id = std::nullopt;

    // Keep track of votes in each active configuration
    struct Votes
    {
      std::unordered_set<ccf::NodeId> votes;
      size_t quorum;
    };
    std::map<Index, Votes> votes_for_me;

    // Replicas start in leadership state Follower. Apart from a single forced
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
    std::optional<kv::LeadershipState> leadership_state = std::nullopt;
    kv::MembershipState membership_state;
    std::optional<kv::RetirementPhase> retirement_phase = std::nullopt;
    std::chrono::milliseconds timeout_elapsed;
    // Last (committable) index preceding the node's election, this is
    // used to decide when to start issuing signatures. While commit_idx
    // hasn't caught up with election_index, a newly elected leader is
    // effectively finishing establishing commit over the previous term
    // or even previous terms, and can therefore not meaningfully sign
    // over the commit level.
    kv::Version election_index = 0;

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

    // When this node becomes primary, they should produce a new signature in
    // the current view. This signature is the first thing they may commit, as
    // they cannot confirm commit of anything from a previous view (Raft paper
    // section 5.4.2). This bool is true from the point this node becomes
    // primary, until it is explicitly reset by a call to get_signable_txid()
    bool should_sign = false;

    std::shared_ptr<aft::State> state;

    // Timeouts
    std::chrono::milliseconds request_timeout;
    std::chrono::milliseconds election_timeout;
    bool ticking = false;

    // Configurations
    std::list<Configuration> configurations;
    // Union of other nodes (i.e. all nodes but us) in each active
    // configuration. This should be used for diagnostic or broadcasting
    // messages but _not_ for counting quorums, which should be done for each
    // active configuration.
    std::unordered_map<ccf::NodeId, NodeState> all_other_nodes;
    std::unordered_map<ccf::NodeId, ccf::SeqNo> learner_nodes;
    std::unordered_map<ccf::NodeId, ccf::SeqNo> retired_nodes;
    ReconfigurationType reconfiguration_type;
    bool require_identity_for_reconfig = false;
    std::shared_ptr<ccf::ResharingTracker> resharing_tracker;
    std::unordered_map<kv::ReconfigurationId, std::unordered_set<ccf::NodeId>>
      orc_sets;

    // Node client to trigger submission of RPC requests
    std::shared_ptr<ccf::NodeClient> node_client;

    // Used to remove retired nodes from store
    std::unique_ptr<ccf::RetiredNodeCleanup> retired_node_cleanup;

    // Index at which this node observes its retirement
    std::optional<ccf::SeqNo> retirement_idx = std::nullopt;
    // Earliest index at which this node's retirement can be committed
    std::optional<ccf::SeqNo> retirement_committable_idx = std::nullopt;

    size_t entry_size_not_limited = 0;
    size_t entry_count = 0;
    Index entries_batch_size = 20;
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

  public:
    Aft(
      const consensus::Configuration& settings_,
      std::unique_ptr<Store> store_,
      std::unique_ptr<LedgerProxy> ledger_,
      std::shared_ptr<ccf::NodeToNode> channels_,
      std::shared_ptr<aft::State> state_,
      std::shared_ptr<ccf::ResharingTracker> resharing_tracker_,
      std::shared_ptr<ccf::NodeClient> rpc_request_context_,
      bool public_only_ = false,
      kv::MembershipState initial_membership_state_ =
        kv::MembershipState::Active,
      ReconfigurationType reconfiguration_type_ =
        ReconfigurationType::ONE_TRANSACTION) :
      consensus_type(settings_.type),
      store(std::move(store_)),

      membership_state(initial_membership_state_),
      timeout_elapsed(0),

      state(state_),

      request_timeout(settings_.message_timeout),
      election_timeout(settings_.election_timeout),

      reconfiguration_type(reconfiguration_type_),
      resharing_tracker(std::move(resharing_tracker_)),
      node_client(rpc_request_context_),
      retired_node_cleanup(
        std::make_unique<ccf::RetiredNodeCleanup>(node_client)),

      public_only(public_only_),

      distrib(0, (int)election_timeout.count() / 2),
      rand((int)(uintptr_t)this),

      ledger(std::move(ledger_)),
      channels(channels_)

    {
      LOG_DEBUG_FMT(
        "reconfiguration type: {}",
        reconfiguration_type == ONE_TRANSACTION ? "1tx" : "2tx");

      if (consensus_type == ConsensusType::BFT)
      {
        // Initialize view history for bft. We start on view 2 and the first
        // commit is always 1.
        state->view_history.update(1, starting_view_change);
        require_identity_for_reconfig = true;
        ticking = true;
      }

      if (require_identity_for_reconfig)
      {
        if (!resharing_tracker)
        {
          throw std::logic_error("missing identity tracker");
        }
      }
    }

    virtual ~Aft() = default;

    std::optional<ccf::NodeId> primary() override
    {
      return leader_id;
    }

    bool view_change_in_progress() override
    {
      std::unique_lock<ccf::pal::Mutex> guard(state->lock);
      if (consensus_type == ConsensusType::BFT)
      {
        LOG_FAIL_FMT("Unsupported");
        return false;
      }
      else
      {
        return (leadership_state == kv::LeadershipState::Candidate);
      }
    }

    ccf::NodeId id() override
    {
      return state->my_node_id;
    }

    bool is_primary() override
    {
      return leadership_state == kv::LeadershipState::Leader;
    }

    bool is_candidate() override
    {
      return leadership_state == kv::LeadershipState::Candidate;
    }

    bool can_replicate() override
    {
      std::unique_lock<ccf::pal::Mutex> guard(state->lock);
      return can_replicate_unsafe();
    }

    Consensus::SignatureDisposition get_signature_disposition() override
    {
      std::unique_lock<ccf::pal::Mutex> guard(state->lock);
      if (can_replicate_unsafe())
      {
        if (should_sign)
        {
          return Consensus::SignatureDisposition::SHOULD_SIGN;
        }
        else
        {
          return Consensus::SignatureDisposition::CAN_SIGN;
        }
      }
      else
      {
        return Consensus::SignatureDisposition::CANT_REPLICATE;
      }
    }

    bool is_backup() override
    {
      return leadership_state == kv::LeadershipState::Follower;
    }

    bool is_learner() const
    {
      return membership_state == kv::MembershipState::Learner;
    }

    bool is_retired() const
    {
      return membership_state == kv::MembershipState::Retired;
    }

    bool is_retiring() const
    {
      return membership_state == kv::MembershipState::RetirementInitiated;
    }

    Index last_committable_index() const
    {
      return committable_indices.empty() ? state->commit_idx :
                                           committable_indices.back();
    }

    void enable_all_domains() override
    {
      // When receiving append entries as a follower, all security domains will
      // be deserialised
      std::lock_guard<ccf::pal::Mutex> guard(state->lock);
      public_only = false;
    }

    ConsensusType type() override
    {
      return consensus_type;
    }

    void force_become_primary() override
    {
      // This is unsafe and should only be called when the node is certain
      // there is no leader and no other node will attempt to force leadership.
      if (leader_id.has_value())
      {
        throw std::logic_error(
          "Can't force leadership if there is already a leader");
      }

      std::lock_guard<ccf::pal::Mutex> guard(state->lock);
      state->current_view += starting_view_change;
      become_leader(true);
    }

    void force_become_primary(
      Index index,
      Term term,
      const std::vector<Index>& terms,
      Index commit_idx_) override
    {
      // This is unsafe and should only be called when the node is certain
      // there is no leader and no other node will attempt to force leadership.
      if (leader_id.has_value())
      {
        throw std::logic_error(
          "Can't force leadership if there is already a leader");
      }

      std::lock_guard<ccf::pal::Mutex> guard(state->lock);
      state->current_view = term;
      state->last_idx = index;
      state->commit_idx = commit_idx_;
      state->view_history.initialise(terms);
      state->view_history.update(index, term);
      state->current_view += starting_view_change;
      become_leader(true);
    }

    void init_as_backup(
      Index index,
      Term term,
      const std::vector<Index>& term_history,
      Index recovery_start_index = 0) override
    {
      // This should only be called when the node resumes from a snapshot and
      // before it has received any append entries.
      std::lock_guard<ccf::pal::Mutex> guard(state->lock);

      state->last_idx = index;
      state->commit_idx = index;

      state->view_history.initialise(term_history);

      ledger->init(index, recovery_start_index);

      become_aware_of_new_term(term);
    }

    Index get_last_idx()
    {
      return state->last_idx;
    }

    Index get_committed_seqno() override
    {
      std::lock_guard<ccf::pal::Mutex> guard(state->lock);
      return get_commit_idx_unsafe();
    }

    Term get_view() override
    {
      std::lock_guard<ccf::pal::Mutex> guard(state->lock);
      return state->current_view;
    }

    std::pair<Term, Index> get_committed_txid() override
    {
      std::lock_guard<ccf::pal::Mutex> guard(state->lock);
      ccf::SeqNo commit_idx = get_commit_idx_unsafe();
      return {get_term_internal(commit_idx), commit_idx};
    }

    kv::Consensus::SignableTxIndices get_signable_txid() override
    {
      std::lock_guard<ccf::pal::Mutex> guard(state->lock);

      kv::Consensus::SignableTxIndices r;
      r.version = state->last_idx;
      r.term = get_term_internal(r.version);
      r.previous_version = std::max(last_committable_index(), election_index);

      // NB: Reset here, since we're already holding the lock, and assume the
      // caller will go on to emit a signature
      should_sign = false;

      return r;
    }

    Term get_view(Index idx) override
    {
      std::lock_guard<ccf::pal::Mutex> guard(state->lock);
      return get_term_internal(idx);
    }

    std::vector<Index> get_view_history(Index idx) override
    {
      // This should only be called when the spin lock is held.
      return state->view_history.get_history_until(idx);
    }

    std::vector<Index> get_view_history_since(Index idx) override
    {
      // This should only be called when the spin lock is held.
      return state->view_history.get_history_since(idx);
    }

  private:
    uint32_t get_bft_offset(const Configuration::Nodes& conf) const
    {
      uint32_t offset = 0;
      return offset;
    }

  public:
    void add_configuration(
      Index idx,
      const kv::Configuration::Nodes& conf,
      const std::unordered_set<ccf::NodeId>& new_learner_nodes = {},
      const std::unordered_set<ccf::NodeId>& new_retired_nodes = {}) override
    {
      LOG_DEBUG_FMT(
        "Configurations: add new configuration at {}: {{{}}}", idx, conf);

      if (reconfiguration_type == ReconfigurationType::ONE_TRANSACTION)
      {
        assert(new_learner_nodes.empty());

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
          become_retired(idx, kv::RetirementPhase::Ordered);
        }
      }
      else
      {
        if (
          !configurations.empty() &&
          configurations.back().nodes.find(state->my_node_id) ==
            configurations.back().nodes.end() &&
          conf.find(state->my_node_id) == conf.end() &&
          (is_retiring() ||
           (is_retired() &&
            retirement_phase == kv::RetirementPhase::Committed)))
        {
          become_retired(idx, kv::RetirementPhase::Ordered);
        }

        if (!new_learner_nodes.empty())
        {
          LOG_DEBUG_FMT(
            "Configurations: new learners: {{{}}}",
            fmt::join(new_learner_nodes, ", "));
          for (auto& id : new_learner_nodes)
          {
            if (learner_nodes.find(id) == learner_nodes.end())
            {
              learner_nodes[id] = idx;
            }
          }
        }

        if (!new_retired_nodes.empty())
        {
          LOG_DEBUG_FMT(
            "Configurations: newly retired nodes: {{{}}}",
            fmt::join(new_retired_nodes, ", "));
          for (auto& id : new_retired_nodes)
          {
            if (retired_nodes.find(id) == retired_nodes.end())
            {
              retired_nodes[id] = idx;
            }
          }
        }

        if (!configurations.empty())
        {
          for (const auto& [nid, _] : conf)
          {
            if (
              all_other_nodes.find(nid) != all_other_nodes.end() &&
              learner_nodes.find(nid) != learner_nodes.end() &&
              new_learner_nodes.find(nid) == new_learner_nodes.end())
            {
              // Promotion of known learner
              learner_nodes.erase(nid);
            }
            if (is_learner() && nid == state->my_node_id)
            {
              LOG_DEBUG_FMT(
                "Configurations: observing own promotion, becoming an active "
                "follower");
              leadership_state = kv::LeadershipState::Follower;
              membership_state = kv::MembershipState::Active;
            }
          }
        }

        if (orc_sets.find(idx) == orc_sets.end())
        {
          orc_sets[idx] = {};
        }
      }

      if (conf != configurations.back().nodes)
      {
        uint32_t offset = get_bft_offset(conf);
        Configuration new_config = {idx, std::move(conf), offset, idx};
        configurations.push_back(new_config);

        if (
          reconfiguration_type == ReconfigurationType::TWO_TRANSACTION &&
          resharing_tracker)
        {
          resharing_tracker->add_network_configuration(new_config);
          if (is_primary())
          {
            resharing_tracker->reshare(new_config);
          }
        }

        create_and_remove_node_state();
      }
    }

    void start_ticking()
    {
      ticking = true;
      using namespace std::chrono_literals;
      timeout_elapsed = 0ms;
      LOG_INFO_FMT("Election timer has become active");
    }

    void add_resharing_result(
      ccf::SeqNo seqno,
      kv::ReconfigurationId rid,
      const ccf::ResharingResult& result) override
    {
      if (
        reconfiguration_type == ReconfigurationType::TWO_TRANSACTION &&
        require_identity_for_reconfig)
      {
        assert(resharing_tracker);
        resharing_tracker->add_resharing_result(seqno, rid, result);
      }
    }

    void clear_orc_sets()
    {
      for (auto& [_, s] : orc_sets)
      {
        s.clear();
      }
    }

    void reset_last_ack_timeouts()
    {
      for (auto& node : all_other_nodes)
      {
        using namespace std::chrono_literals;
        node.second.last_ack_timeout = 0ms;
      }
    }

    // For more info about Observed Reconfiguration Commits see
    // https://microsoft.github.io/CCF/main/architecture/consensus/2tx-reconfig.html
    //
    // Note that this call is not `const` and that it modifies `orc_sets`. This
    // is safe, despite the fact that the primary may change or a
    // reconfiguration may be (partially) rolled back, because the `orc_sets`
    // are cleared upon entering/exiting the leader/follower replica states.
    // This means that we never record spurious ORCs, while it is still
    // guaranteed that we will eventually receive all of them, since all
    // nodes keep re-submitting ORCs until they are able to switch to the next
    // pending configuration.

    std::optional<kv::Configuration::Nodes> orc(
      kv::ReconfigurationId rid, const ccf::NodeId& node_id) override
    {
      std::lock_guard<ccf::pal::Mutex> guard(state->lock);

      LOG_DEBUG_FMT(
        "Configurations: ORC for configuration #{} from {}", rid, node_id);

      const auto oit = orc_sets.find(rid);
      if (oit == orc_sets.end())
      {
        throw std::logic_error(
          fmt::format("Missing ORC set for configuration #{}", rid));
      }

      for (auto const& conf : configurations)
      {
        if (conf.rid == rid)
        {
          const auto& ncnodes = conf.nodes;
          if (ncnodes.find(node_id) == ncnodes.end())
          {
            LOG_DEBUG_FMT("Node not in the configuration {}: {}", rid, node_id);
            return std::nullopt;
          }
          else
          {
            oit->second.insert(node_id);
            LOG_DEBUG_FMT(
              "Configurations: have {} ORCs out of {} for configuration #{}",
              oit->second.size(),
              ncnodes.size(),
              rid);

            // Note: Learners in the next configuration become trusted when
            // there is quorum in the next configuration, i.e. they may become
            // trusted in the nodes table before they are fully caught up and
            // have submitted their own ORC.

            if (oit->second.size() >= get_quorum(ncnodes.size()))
            {
              return ncnodes;
            }
            else
            {
              return std::nullopt;
            }
          }
          break;
        }
      }

      return std::nullopt;
    }

    Configuration::Nodes get_latest_configuration_unsafe() const override
    {
      if (configurations.empty())
      {
        return {};
      }

      return configurations.back().nodes;
    }

    Configuration::Nodes get_latest_configuration() override
    {
      std::lock_guard<ccf::pal::Mutex> guard(state->lock);
      return get_latest_configuration_unsafe();
    }

    kv::ConsensusDetails get_details() override
    {
      kv::ConsensusDetails details;
      std::lock_guard<ccf::pal::Mutex> guard(state->lock);
      details.primary_id = leader_id;
      details.current_view = state->current_view;
      details.ticking = ticking;
      details.leadership_state = leadership_state;
      details.membership_state = membership_state;
      if (is_retired())
      {
        details.retirement_phase = retirement_phase;
      }
      for (auto const& conf : configurations)
      {
        details.configs.push_back(conf);
      }
      for (auto& [k, v] : all_other_nodes)
      {
        details.acks[k] = {
          v.match_idx, static_cast<size_t>(v.last_ack_timeout.count())};
      }
      details.reconfiguration_type = reconfiguration_type;
      if (reconfiguration_type == ReconfigurationType::TWO_TRANSACTION)
      {
        details.learners = learner_nodes;
      }
      return details;
    }

    bool replicate(const kv::BatchVector& entries, Term term) override
    {
      std::lock_guard<ccf::pal::Mutex> guard(state->lock);

      if (leadership_state != kv::LeadershipState::Leader)
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
          state->my_node_id,
          index,
          (globally_committable ? " committable" : ""),
          hooks->size());

        for (auto& hook : *hooks)
        {
          hook->call(this);
        }

        if (globally_committable)
        {
          LOG_DEBUG_FMT(
            "membership: {} leadership: {}",
            membership_state,
            leadership_state_string());
          if (
            membership_state == kv::MembershipState::Retired &&
            retirement_phase == kv::RetirementPhase::Ordered)
          {
            become_retired(index, kv::RetirementPhase::Signed);
          }
          committable_indices.push_back(index);
          start_ticking_if_necessary();
        }

        state->last_idx = index;
        ledger->put_entry(
          *data, globally_committable, state->current_view, index);
        entry_size_not_limited += data->size();
        entry_count++;

        state->view_history.update(index, state->current_view);
        if (entry_size_not_limited >= append_entries_size_limit)
        {
          update_batch_size();
          entry_count = 0;
          entry_size_not_limited = 0;
          for (const auto& it : all_other_nodes)
          {
            LOG_DEBUG_FMT("Sending updates to follower {}", it.first);
            send_append_entries(it.first, it.second.sent_idx + 1);
          }
        }
      }

      // If we are the only node, attempt to commit immediately.
      if (all_other_nodes.size() == 0)
      {
        update_commit();
      }

      return true;
    }

    void recv_message(
      const ccf::NodeId& from, const uint8_t* data, size_t size) override
    {
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
            recv_append_entries(from, r, data, size);
            break;
          }

          case raft_append_entries_response:
          {
            AppendEntriesResponse r =
              channels->template recv_authenticated<AppendEntriesResponse>(
                from, data, size);
            recv_append_entries_response(from, r);
            break;
          }

          case raft_request_vote:
          {
            RequestVote r = channels->template recv_authenticated<RequestVote>(
              from, data, size);
            recv_request_vote(from, r);
            break;
          }

          case raft_request_vote_response:
          {
            RequestVoteResponse r =
              channels->template recv_authenticated<RequestVoteResponse>(
                from, data, size);
            recv_request_vote_response(from, r);
            break;
          }

          default:
          {
            LOG_FAIL_FMT("Unhandled AFT message type: {}", type);
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
    }

    void periodic(std::chrono::milliseconds elapsed) override
    {
      std::unique_lock<ccf::pal::Mutex> guard(state->lock);
      timeout_elapsed += elapsed;

      if (leadership_state == kv::LeadershipState::Leader)
      {
        if (timeout_elapsed >= request_timeout)
        {
          using namespace std::chrono_literals;
          timeout_elapsed = 0ms;

          update_batch_size();
          // Send newly available entries to all other nodes.
          for (const auto& node : all_other_nodes)
          {
            send_append_entries(node.first, node.second.sent_idx + 1);
          }
        }

        for (auto& node : all_other_nodes)
        {
          node.second.last_ack_timeout += elapsed;
        }

        bool has_quorum_of_backups = false;
        for (auto const& conf : configurations)
        {
          size_t backup_ack_timeout_count = 0;
          for (auto const& node : conf.nodes)
          {
            auto search = all_other_nodes.find(node.first);
            if (search == all_other_nodes.end())
            {
              // Ignore ourselves as primary
              continue;
            }
            if (search->second.last_ack_timeout >= election_timeout)
            {
              LOG_DEBUG_FMT(
                "No ack received from {} in last {}",
                node.first,
                election_timeout);
              backup_ack_timeout_count++;
            }
          }

          if (backup_ack_timeout_count < get_quorum(conf.nodes.size() - 1))
          {
            // If primary has quorum of active backups in _any_ configuration,
            // it should remain primary
            has_quorum_of_backups = true;
            break;
          }
        }

        if (!has_quorum_of_backups)
        {
          // CheckQuorum: The primary automatically steps down if there are no
          // active configuration in which it has heard back from a majority of
          // backups within an election timeout.
          LOG_INFO_FMT(
            "Stepping down as follower {}: No ack received from a majority of "
            "backups in last {}",
            state->my_node_id,
            election_timeout);
          become_follower();
        }
      }
      else if (consensus_type != ConsensusType::BFT)
      {
        if (
          can_endorse_primary() && ticking &&
          timeout_elapsed >= election_timeout)
        {
          // Start an election.
          become_candidate();
        }
      }
    }

  private:
    Index find_highest_possible_match(const ccf::TxID& tx_id)
    {
      // Find the highest TxID this node thinks exists, which is still
      // compatible with the given tx_id. That is, given T.n, find largest n'
      // such that n' <= n && term_of(n') == T' && T' <= T. This may be T.n
      // itself, if this node holds that index. Otherwise, examine the final
      // entry in each term, counting backwards, until we find one which is
      // still possible.
      Index probe_index = std::min(tx_id.seqno, state->last_idx);
      Term term_of_probe = state->view_history.view_at(probe_index);
      while (term_of_probe > tx_id.view)
      {
        // Next possible match is the end of the previous term, which is
        // 1-before the start of the currently considered term. Anything after
        // that must have a term which is still too high.
        probe_index = state->view_history.start_of_view(term_of_probe);
        if (probe_index > 0)
        {
          --probe_index;
        }
        term_of_probe = state->view_history.view_at(probe_index);
      }

      LOG_TRACE_FMT(
        "Looking for match with {}.{}, from {}.{}, best answer is {}",
        tx_id.view,
        tx_id.seqno,
        state->view_history.view_at(state->last_idx),
        state->last_idx,
        probe_index);
      return probe_index;
    }

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
      if (idx > state->last_idx)
        return ccf::VIEW_UNKNOWN;

      return state->view_history.view_at(idx);
    }

    bool can_replicate_unsafe()
    {
      return leadership_state == kv::LeadershipState::Leader &&
        !retirement_committable_idx.has_value();
    }

    Index get_commit_idx_unsafe()
    {
      if (consensus_type == ConsensusType::CFT)
      {
        return state->commit_idx;
      }
      else
      {
        LOG_FAIL_FMT("Unsupported consensus type");
        return {};
      }
    }

    void send_append_entries(const ccf::NodeId& to, Index start_idx)
    {
      LOG_TRACE_FMT(
        "Sending append entries to node {} in batches of {}, covering the "
        "range {} -> {}",
        to,
        entries_batch_size,
        start_idx,
        state->last_idx);

      auto calculate_end_index = [this](Index start) {
        // Cap the end index in 2 ways:
        // - Must contain no more than entries_batch_size entries
        // - Must contain entries from a single term
        auto max_idx = state->last_idx;
        const auto term_of_ae = state->view_history.view_at(start);
        const auto index_at_end_of_term =
          state->view_history.end_of_view(term_of_ae);
        if (index_at_end_of_term != kv::NoVersion)
        {
          max_idx = index_at_end_of_term;
        }
        return std::min(start + entries_batch_size, max_idx);
      };

      Index end_idx;

      // We break _after_ sending, so that in the case where this is called
      // with start==last, we send a single empty heartbeat
      do
      {
        end_idx = calculate_end_index(start_idx);
        LOG_TRACE_FMT("Sending sub range {} -> {}", start_idx, end_idx);
        send_append_entries_range(to, start_idx, end_idx);
        start_idx = std::min(end_idx + 1, state->last_idx);
      } while (end_idx != state->last_idx);
    }

    void send_append_entries_range(
      const ccf::NodeId& to, Index start_idx, Index end_idx)
    {
      const auto prev_idx = start_idx - 1;

      if (
        is_retired() && retirement_phase > kv::RetirementPhase::Signed &&
        start_idx >= end_idx)
      {
        // Continue to replicate, but do not send heartbeats if we are retired
        return;
      }

      const auto prev_term = get_term_internal(prev_idx);
      const auto term_of_idx = get_term_internal(end_idx);
      const bool contains_new_view =
        (state->new_view_idx > prev_idx) && (state->new_view_idx <= end_idx);

      LOG_DEBUG_FMT(
        "Send append entries from {} to {}: ({}.{}, {}.{}] ({})",
        state->my_node_id,
        to,
        prev_term,
        prev_idx,
        term_of_idx,
        end_idx,
        state->commit_idx);

      AppendEntries ae = {
        {raft_append_entries},
        {end_idx, prev_idx},
        state->current_view,
        prev_term,
        state->commit_idx,
        term_of_idx,
        contains_new_view};

      auto& node = all_other_nodes.at(to);

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

    void recv_append_entries(
      const ccf::NodeId& from,
      AppendEntries r,
      const uint8_t* data,
      size_t size)
    {
      std::unique_lock<ccf::pal::Mutex> guard(state->lock);

      LOG_DEBUG_FMT(
        "Received append entries: {}.{} to {}.{} (from {} in term {})",
        r.prev_term,
        r.prev_idx,
        r.term_of_idx,
        r.idx,
        from,
        r.term);

      // Don't check that the sender node ID is valid. Accept anything that
      // passes the integrity check. This way, entries containing dynamic
      // topology changes that include adding this new leader can be accepted.

      // First, check append entries term against our own term, becoming
      // follower if necessary
      if (
        state->current_view == r.term &&
        leadership_state == kv::LeadershipState::Candidate)
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
          send_append_entries_response(from, AppendEntriesResponseType::FAIL);
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
          const ccf::TxID rejected_tx{r.prev_term, r.prev_idx};
          send_append_entries_response(
            from, AppendEntriesResponseType::FAIL, rejected_tx);
        }
        return;
      }

      // Then check if those append entries extend past our retirement
      if (is_retired() && retirement_phase >= kv::RetirementPhase::Completed)
      {
        assert(retirement_committable_idx.has_value());
        if (r.idx > retirement_committable_idx)
        {
          send_append_entries_response(from, AppendEntriesResponseType::FAIL);
          return;
        }
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
        consensus_type == ConsensusType::CFT && r.prev_idx < state->commit_idx)
      {
        LOG_DEBUG_FMT(
          "Recv append entries to {} from {} but prev_idx ({}) < commit_idx "
          "({})",
          state->my_node_id,
          from,
          r.prev_idx,
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
        state->my_node_id,
        from,
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

        std::vector<uint8_t> entry;
        try
        {
          entry = LedgerProxy::get_entry(data, size);
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

        kv::TxID expected{r.term_of_idx, i};
        auto ds = store->apply(entry, consensus_type, public_only, expected);
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

      execute_append_entries_sync(
        std::move(append_entries), from, std::move(r));
    }

    void execute_append_entries_sync(
      std::vector<std::tuple<
        std::unique_ptr<kv::AbstractExecutionWrapper>,
        kv::Version>>&& append_entries,
      const ccf::NodeId& from,
      AppendEntries&& r)
    {
      for (auto& ae : append_entries)
      {
        auto& [ds, i] = ae;
        LOG_DEBUG_FMT("Replicating on follower {}: {}", state->my_node_id, i);

        bool track_deletes_on_missing_keys = false;
        kv::ApplyResult apply_success =
          ds->apply(track_deletes_on_missing_keys);
        if (apply_success == kv::ApplyResult::FAIL)
        {
          ledger->truncate(i - 1);
          send_append_entries_response(from, AppendEntriesResponseType::FAIL);
          return;
        }
        state->last_idx = i;

        for (auto& hook : ds->get_hooks())
        {
          hook->call(this);
        }

        bool globally_committable =
          (apply_success == kv::ApplyResult::PASS_SIGNATURE);
        if (globally_committable)
        {
          start_ticking_if_necessary();
        }

        const auto& entry = ds->get_entry();

        ledger->put_entry(
          entry, globally_committable, ds->get_term(), ds->get_index());

        switch (apply_success)
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
            if (
              membership_state == kv::MembershipState::Retired &&
              retirement_phase == kv::RetirementPhase::Ordered)
            {
              become_retired(i, kv::RetirementPhase::Signed);
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
                // NB: This is only safe as long as AppendEntries only contain a
                // single term. If they cover multiple terms, then we need to
                // know our previous signature locally.
                state->view_history.update(r.prev_idx + 1, ds->get_term());
              }
              commit_if_possible(r.leader_commit_idx);
            }
            break;
          }

          case kv::ApplyResult::PASS:
          {
            break;
          }

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

      execute_append_entries_finish(r, from);
    }

    void execute_append_entries_finish(
      AppendEntries& r, const ccf::NodeId& from)
    {
      // After entries have been deserialised, try to commit the leader's
      // commit index and update our term history accordingly
      commit_if_possible(r.leader_commit_idx);

      // The term may have changed, and we have not have seen a signature yet.
      auto lci = last_committable_index();
      if (r.term_of_idx == aft::ViewHistory::InvalidView)
      {
        // If we don't yet have a term history, then this must be happening in
        // the current term. This can only happen before _any_ transactions have
        // occurred, when processing a heartbeat at index 0, which does not
        // happen in a real node (due to the genesis transaction executing
        // before ticks start), but may happen in tests.
        state->view_history.update(1, r.term);
      }
      else
      {
        // The end of this append entries (r.idx) was not a signature, but may
        // be in a new term. If it's a new term, this term started immediately
        // after the previous signature we saw (lci, last committable index).
        if (r.idx > lci)
        {
          state->view_history.update(lci + 1, r.term_of_idx);
        }
      }

      send_append_entries_response(from, AppendEntriesResponseType::OK);
    }

    void send_append_entries_response(
      ccf::NodeId to,
      AppendEntriesResponseType answer,
      const std::optional<ccf::TxID>& rejected = std::nullopt)
    {
      if (answer == AppendEntriesResponseType::REQUIRE_EVIDENCE)
      {
        state->requested_evidence_from = to;
      }

      aft::Index response_idx = state->last_idx;
      aft::Term response_term = state->current_view;

      // This matching-index-detection logic doesn't work on BFT, so is disabled
      // and still uses the original behaviour:
      // https://github.com/microsoft/CCF/issues/2853
      if (consensus_type != ConsensusType::BFT)
      {
        if (answer == AppendEntriesResponseType::FAIL && rejected.has_value())
        {
          response_idx = find_highest_possible_match(rejected.value());
          response_term = get_term_internal(response_idx);
        }
      }

      LOG_DEBUG_FMT(
        "Send append entries response from {} to {} for index {}: {}",
        state->my_node_id,
        to,
        response_idx,
        answer);

      AppendEntriesResponse response = {
        {raft_append_entries_response}, response_term, response_idx, answer};

      channels->send_authenticated(
        to, ccf::NodeMsgType::consensus_msg, response);
    }

    void recv_append_entries_response(
      const ccf::NodeId& from, AppendEntriesResponse r)
    {
      std::lock_guard<ccf::pal::Mutex> guard(state->lock);
      // Ignore if we're not the leader.

      if (leadership_state != kv::LeadershipState::Leader)
      {
        LOG_FAIL_FMT(
          "Recv append entries response to {} from {}: no longer leader",
          state->my_node_id,
          from);
        return;
      }

      auto node = all_other_nodes.find(from);
      if (node == all_other_nodes.end())
      {
        // Ignore if we don't recognise the node.
        LOG_FAIL_FMT(
          "Recv append entries response to {} from {}: unknown node",
          state->my_node_id,
          from);
        return;
      }

      using namespace std::chrono_literals;
      node->second.last_ack_timeout = 0ms;

      if (state->current_view < r.term)
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
        // NB: In NACKs the term may be that of an estimated matching index
        // in the log, rather than the current term, so it is correct for it to
        // be older in this case.
        if (r.success == AppendEntriesResponseType::OK)
        {
          LOG_DEBUG_FMT(
            "Recv append entries response to {} from {}: stale term ({} != {})",
            state->my_node_id,
            from,
            r.term,
            state->current_view);
          return;
        }
      }
      else if (r.last_log_idx < node->second.match_idx)
      {
        // Response about past indices, discard if success.
        // Otherwise reset sent_idx and try again.
        // NB: It is correct for this index to move backwards during NACKs
        // which iteratively discover the last matching index of divergent logs
        // after an election.
        if (r.success == AppendEntriesResponseType::OK)
        {
          LOG_DEBUG_FMT(
            "Recv append entries response to {} from {}: stale idx",
            state->my_node_id,
            from);
          return;
        }
      }

      // Update next and match for the responding node.
      auto& match_idx = node->second.match_idx;
      if (r.success == AppendEntriesResponseType::FAIL)
      {
        const auto this_match =
          find_highest_possible_match({r.term, r.last_log_idx});
        if (match_idx == 0)
        {
          match_idx = this_match;
        }
        else
        {
          match_idx = std::min(match_idx, this_match);
        }
      }
      else
      {
        match_idx = std::min(r.last_log_idx, state->last_idx);
      }

      if (r.success != AppendEntriesResponseType::OK)
      {
        // Failed due to log inconsistency. Reset sent_idx, and try again soon.
        LOG_DEBUG_FMT(
          "Recv append entries response to {} from {}: failed",
          state->my_node_id,
          from);
        node->second.sent_idx = node->second.match_idx;
        return;
      }

      LOG_DEBUG_FMT(
        "Recv append entries response to {} from {} for index {}: success",
        state->my_node_id,
        from,
        r.last_log_idx);
      update_commit();
    }

    void send_request_vote(const ccf::NodeId& to)
    {
      auto last_committable_idx = last_committable_index();
      LOG_INFO_FMT(
        "Send request vote from {} to {} at {}",
        state->my_node_id,
        to,
        last_committable_idx);
      CCF_ASSERT(last_committable_idx >= state->commit_idx, "lci < ci");

      RequestVote rv = {
        {raft_request_vote},
        state->current_view,
        last_committable_idx,
        get_term_internal(last_committable_idx)};

      channels->send_authenticated(to, ccf::NodeMsgType::consensus_msg, rv);
    }

    void recv_request_vote(const ccf::NodeId& from, RequestVote r)
    {
      std::lock_guard<ccf::pal::Mutex> guard(state->lock);

      // Do not check that from is a known node. It is possible to receive
      // RequestVotes from nodes that this node doesn't yet know, just as it
      // receives AppendEntries from those nodes. These should be obeyed just
      // like any other RequestVote - it is possible that this node is needed to
      // produce a primary in the new term, who will then help this node catch
      // up.

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

      if (leader_id.has_value())
      {
        // Reply false, since we already know the leader in the current term.
        LOG_DEBUG_FMT(
          "Recv request vote to {} from {}: leader {} already known in term {}",
          state->my_node_id,
          from,
          leader_id.value(),
          state->current_view);
        send_request_vote_response(from, false);
        return;
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
        state->my_node_id,
        to,
        answer);

      RequestVoteResponse response = {
        {raft_request_vote_response}, state->current_view, answer};

      channels->send_authenticated(
        to, ccf::NodeMsgType::consensus_msg, response);
    }

    void recv_request_vote_response(
      const ccf::NodeId& from, RequestVoteResponse r)
    {
      std::lock_guard<ccf::pal::Mutex> guard(state->lock);

      if (leadership_state != kv::LeadershipState::Candidate)
      {
        LOG_INFO_FMT(
          "Recv request vote response to {} from: {}: we aren't a candidate",
          state->my_node_id,
          from);
        return;
      }

      // Ignore if we don't recognise the node.
      auto node = all_other_nodes.find(from);
      if (node == all_other_nodes.end())
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

    void reset_votes_for_me()
    {
      votes_for_me.clear();
      for (auto const& conf : configurations)
      {
        votes_for_me[conf.idx].quorum = get_quorum(conf.nodes.size());
        votes_for_me[conf.idx].votes.clear();
      }
    }

    void become_candidate()
    {
      leadership_state = kv::LeadershipState::Candidate;
      leader_id.reset();
      clear_orc_sets();

      voted_for = state->my_node_id;
      reset_votes_for_me();
      state->current_view++;

      restart_election_timeout();
      reset_last_ack_timeouts();

      add_vote_for_me(state->my_node_id);

      LOG_INFO_FMT(
        "Becoming candidate {}: {}", state->my_node_id, state->current_view);

      if (consensus_type != ConsensusType::BFT)
      {
        for (auto const& node : all_other_nodes)
        {
          send_request_vote(node.first);
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
      // and has a genesis or recovery tx as the last transaction
      election_index = last_committable_index();

      // A newly elected leader must not advance the commit index until a
      // transaction in the new term commits. We achieve this by clearing our
      // list committable indices - so nothing from a previous term is now
      // considered committable. Instead this new primary will shortly produce
      // their own signature, which _will_ be considered committable.
      committable_indices.clear();

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

      leadership_state = kv::LeadershipState::Leader;
      leader_id = state->my_node_id;
      should_sign = true;

      using namespace std::chrono_literals;
      timeout_elapsed = 0ms;

      reset_last_ack_timeouts();

      LOG_INFO_FMT(
        "Becoming leader {}: {}", state->my_node_id, state->current_view);

      // Immediately commit if there are no other nodes.
      if (all_other_nodes.size() == 0)
      {
        commit(state->last_idx);
        return;
      }

      // Reset next, match, and sent indices for all nodes.
      auto next = state->last_idx + 1;

      for (auto& node : all_other_nodes)
      {
        node.second.match_idx = 0;
        node.second.sent_idx = next - 1;

        // Send an empty append_entries to all nodes.
        send_append_entries(node.first, next);
      }
    }

    bool can_advance_watermark()
    {
      return membership_state != kv::MembershipState::Retired &&
        membership_state != kv::MembershipState::Learner;
    }

    bool can_endorse_primary()
    {
      return membership_state != kv::MembershipState::Retired &&
        membership_state != kv::MembershipState::Learner;
    }

  public:
    // Called when a replica becomes follower in the same term, e.g. when the
    // primary node has not received a majority of acks (CheckQuorum)
    void become_follower()
    {
      leader_id.reset();
      restart_election_timeout();
      clear_orc_sets();
      reset_last_ack_timeouts();

      rollback(last_committable_index());

      if (
        can_endorse_primary() &&
        membership_state != kv::MembershipState::RetirementInitiated)
      {
        leadership_state = kv::LeadershipState::Follower;
        LOG_INFO_FMT(
          "Becoming follower {}: {}.{}",
          state->my_node_id,
          state->current_view,
          state->commit_idx);
      }
    }

    // Called when a replica becomes aware of the existence of a new term
    // If retired already, state remains unchanged, but the replica otherwise
    // becomes a follower in the new term.
    void become_aware_of_new_term(Term term)
    {
      LOG_DEBUG_FMT("Becoming aware of new term {}", term);

      state->current_view = term;
      voted_for.reset();
      reset_votes_for_me();
      become_follower();
      is_new_follower = true;
    }

    std::string leadership_state_string()
    {
      if (leadership_state.has_value())
        return fmt::format("{}", leadership_state.value());
      else
        return "none";
    }

  private:
    void become_retiring()
    {
      membership_state = kv::MembershipState::RetirementInitiated;
      LOG_INFO_FMT(
        "Becoming retiring {} (while {}): {}",
        state->my_node_id,
        leadership_state_string(),
        state->current_view);
    }

    void become_retired(Index idx, kv::RetirementPhase phase)
    {
      LOG_INFO_FMT(
        "Becoming retired, phase {} (leadership {}): {}: {} at {}",
        phase,
        leadership_state_string(),
        state->my_node_id,
        state->current_view,
        idx);

      if (phase == kv::RetirementPhase::Committed)
      {
        assert(membership_state == kv::MembershipState::RetirementInitiated);
        assert(retirement_phase == std::nullopt);
      }
      else if (phase == kv::RetirementPhase::Ordered)
      {
        CCF_ASSERT_FMT(
          !retirement_idx.has_value(),
          "retirement_idx already set to {}",
          retirement_idx.value());
        retirement_idx = idx;
        LOG_INFO_FMT("Node retiring at {}", idx);
      }
      else if (phase == kv::RetirementPhase::Signed)
      {
        assert(retirement_idx.has_value());
        CCF_ASSERT_FMT(
          idx >= retirement_idx.value(),
          "Index {} unexpectedly lower than retirement_idx {}",
          idx,
          retirement_idx.value());
        retirement_committable_idx = idx;
        LOG_INFO_FMT("Node retirement committable at {}", idx);
      }
      else if (phase == kv::RetirementPhase::Completed)
      {
        leader_id.reset();
        leadership_state = std::nullopt;
      }

      membership_state = kv::MembershipState::Retired;
      retirement_phase = phase;
    }

    void add_vote_for_me(const ccf::NodeId& from)
    {
      // Add vote for from node in each configuration where it is present
      for (auto const& conf : configurations)
      {
        auto const& nodes = conf.nodes;
        if (nodes.find(from) == nodes.end())
        {
          // from node is no longer in any active configuration.
          continue;
        }

        votes_for_me[conf.idx].votes.insert(from);
        LOG_DEBUG_FMT(
          "Node {} voted for {} in configuration {} with quorum {}",
          from,
          state->my_node_id,
          conf.idx,
          votes_for_me[conf.idx].quorum);
      }

      // We need a quorum of votes in _all_ configurations to become leader
      bool is_elected = true;
      for (auto const& v : votes_for_me)
      {
        auto const& quorum = v.second.quorum;
        auto const& votes = v.second.votes;

        if (votes.size() < quorum)
        {
          is_elected = false;
          break;
        }
      }

      if (is_elected)
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

      // Obtain CFT watermarks
      for (auto const& c : configurations)
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
            match.push_back(all_other_nodes.at(node.first).match_idx);
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
        "In update_commit, new_commit_cft_idx: {}, "
        "last_idx: {}",
        new_commit_cft_idx,
        state->last_idx);

      if (new_commit_cft_idx != std::numeric_limits<Index>::max())
      {
        state->cft_watermark_idx = new_commit_cft_idx;
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
            LOG_FAIL_FMT("Unsupported consensus type");
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
          (all_other_nodes.find(id) != all_other_nodes.end() &&
           learner_nodes.find(id) == learner_nodes.end()) ||
          (id == state->my_node_id && !is_learner()))
        {
          r++;
        }
      }
      return r;
    }

    size_t num_retired(
      const kv::Configuration& from, const kv::Configuration& to) const
    {
      size_t r = 0;
      for (const auto& [id, _] : from.nodes)
      {
        auto rit = retired_nodes.find(id);
        if (
          to.nodes.find(id) == to.nodes.end() && rit != retired_nodes.end() &&
          rit->second <= state->commit_idx)
        {
          LOG_DEBUG_FMT("Configurations: is retired: {}", id);
          r++;
        }
      }
      return r;
    }

    size_t num_required_retirements(
      const kv::Configuration& from, const kv::Configuration& to) const
    {
      size_t r = 0;
      for (auto& [nid, _] : from.nodes)
      {
        if (to.nodes.find(nid) == to.nodes.end())
        {
          LOG_DEBUG_FMT("Configurations: required retirement: {}", nid);
          r++;
        }
      }
      return r;
    }

    size_t get_quorum(size_t n) const
    {
      switch (consensus_type)
      {
        case CFT:
          return (n / 2) + 1;
        case BFT:
          return ((2 * n) / 3) + 1;
        default:
          return -1;
      }
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
        is_retired() && retirement_phase == kv::RetirementPhase::Signed &&
        retirement_committable_idx.has_value() &&
        idx >= retirement_committable_idx.value())
      {
        become_retired(idx, kv::RetirementPhase::Completed);
      }

      LOG_DEBUG_FMT("Compacting...");
      store->compact(idx);
      ledger->commit(idx);

      LOG_DEBUG_FMT("Commit on {}: {}", state->my_node_id, idx);

      // Examine each configuration that is followed by a globally committed
      // configuration.
      bool changed = false;

      while (true)
      {
        auto conf = configurations.begin();
        if (conf == configurations.end())
        {
          break;
        }

        auto next = std::next(conf);
        if (next == configurations.end())
        {
          break;
        }

        if (idx < next->idx)
        {
          break;
        }

        if (require_identity_for_reconfig)
        {
          assert(resharing_tracker);
          auto rr = resharing_tracker->find_reconfiguration(next->nodes);
          if (
            !rr.has_value() ||
            !resharing_tracker->have_resharing_result_for(rr.value(), idx))
          {
            LOG_TRACE_FMT(
              "Configurations: not switching to next configuration, resharing "
              "not completed yet.");
            break;
          }
        }

        if (reconfiguration_type == ReconfigurationType::ONE_TRANSACTION)
        {
          LOG_DEBUG_FMT(
            "Configurations: discard committed configuration at {}", conf->idx);
          configurations.pop_front();
          changed = true;

          if (retired_node_cleanup && is_primary())
          {
            retired_node_cleanup->cleanup();
          }
        }
        else
        {
          if (
            !is_retired() &&
            conf->nodes.find(state->my_node_id) != conf->nodes.end() &&
            next->nodes.find(state->my_node_id) == next->nodes.end())
          {
            if (!is_retiring())
            {
              become_retiring();
            }
            else
            {
              become_retired(idx, kv::RetirementPhase::Committed);
            }
          }

          size_t num_trusted_nodes = num_trusted(*next);
          size_t num_retired_nodes = num_retired(*conf, *next);
          size_t num_required_retired_nodes =
            num_required_retirements(*conf, *next);
          if (
            num_trusted_nodes == next->nodes.size() &&
            num_retired_nodes == num_required_retired_nodes)
          {
            LOG_TRACE_FMT(
              "Configurations: all nodes trusted ({}) or retired ({}), "
              "switching to configuration #{}",
              num_trusted_nodes,
              num_retired_nodes,
              next->rid);

            if (
              is_learner() &&
              next->nodes.find(state->my_node_id) != next->nodes.end())
            {
              LOG_INFO_FMT(
                "Becoming follower {}: {}",
                state->my_node_id,
                state->current_view);
              leadership_state = kv::LeadershipState::Follower;
              membership_state = kv::MembershipState::Active;
            }

            for (auto& [nid, _] : next->nodes)
            {
              learner_nodes.erase(nid);
            }

            for (auto& [nid, _] : conf->nodes)
            {
              if (next->nodes.find(nid) == next->nodes.end())
              {
                retired_nodes.erase(nid);
              }
            }

            if (retired_node_cleanup && is_primary())
            {
              retired_node_cleanup->cleanup();
            }

            configurations.pop_front();
          }
          else
          {
            LOG_TRACE_FMT(
              "Configurations: not enough trusted or retired nodes for "
              "configuration #{} ({}/{} trusted, {}/{} retired)",
              next->rid,
              num_trusted_nodes,
              next->nodes.size(),
              num_retired_nodes,
              num_required_retired_nodes);
            if (
              node_client && !is_learner() &&
              (next->nodes.find(state->my_node_id) != next->nodes.end() ||
               (is_retiring() &&
                next->nodes.find(state->my_node_id) == next->nodes.end())))
            {
              schedule_submit_orc(
                node_client, state->my_node_id, next->rid, 2 * request_timeout);
            }
            break;
          }
        }
      }

      if (resharing_tracker)
      {
        resharing_tracker->compact(idx);
      }

      if (changed)
      {
        create_and_remove_node_state();
      }
    }

    Index get_commit_watermark_idx()
    {
      return state->cft_watermark_idx;
    }

    bool is_self_in_latest_config()
    {
      bool present = false;
      if (!configurations.empty())
      {
        auto current_nodes = configurations.back().nodes;
        present = current_nodes.find(state->my_node_id) != current_nodes.end();
      }
      return present;
    }

    void start_ticking_if_necessary()
    {
      if (!ticking && is_self_in_latest_config())
      {
        start_ticking();
      }
    }

  public:
    void rollback(Index idx)
    {
      if (consensus_type == ConsensusType::CFT && idx < state->commit_idx)
      {
        LOG_FAIL_FMT(
          "Asked to rollback to idx:{} but committed to commit_idx:{} - "
          "ignoring rollback request",
          idx,
          state->commit_idx);
        return;
      }

      store->rollback({get_term_internal(idx), idx}, state->current_view);

      LOG_DEBUG_FMT("Setting term in store to: {}", state->current_view);
      ledger->truncate(idx);
      state->last_idx = idx;
      LOG_DEBUG_FMT("Rolled back at {}", idx);

      state->view_history.rollback(idx);

      while (!committable_indices.empty() && (committable_indices.back() > idx))
      {
        committable_indices.pop_back();
      }

      if (
        membership_state == kv::MembershipState::Retired &&
        retirement_phase == kv::RetirementPhase::Signed)
      {
        assert(retirement_committable_idx.has_value());
        if (retirement_committable_idx.value() > idx)
        {
          retirement_committable_idx = std::nullopt;
          retirement_phase = kv::RetirementPhase::Ordered;
        }
      }

      if (
        membership_state == kv::MembershipState::Retired &&
        retirement_phase == kv::RetirementPhase::Ordered)
      {
        assert(retirement_idx.has_value());
        if (retirement_idx.value() > idx)
        {
          retirement_idx = std::nullopt;
          retirement_phase = std::nullopt;
          membership_state = reconfiguration_type == ONE_TRANSACTION ?
            kv::MembershipState::Active :
            kv::MembershipState::RetirementInitiated;
          LOG_DEBUG_FMT(
            "Becoming {} after rollback",
            reconfiguration_type == ONE_TRANSACTION ? "Active" :
                                                      "RetirementInitiated");
        }
      }

      // Rollback configurations.
      bool changed = false;

      while (!configurations.empty() && (configurations.back().idx > idx))
      {
        LOG_DEBUG_FMT(
          "Configurations: rollback configuration at {}",
          configurations.back().idx);
        configurations.pop_back();
        changed = true;
      }

      if (reconfiguration_type == ReconfigurationType::TWO_TRANSACTION)
      {
        for (auto it = learner_nodes.begin(); it != learner_nodes.end();)
        {
          if (it->second > idx)
          {
            it = learner_nodes.erase(it);
          }
          else
          {
            it++;
          }
        }

        for (auto it = retired_nodes.begin(); it != retired_nodes.end();)
        {
          if (it->second > idx)
          {
            it = retired_nodes.erase(it);
          }
          else
          {
            it++;
          }
        }
      }

      if (changed)
      {
        create_and_remove_node_state();
      }
    }

  private:
    void create_and_remove_node_state()
    {
      // Find all nodes present in any active configuration.
      Configuration::Nodes active_nodes;

      for (auto const& conf : configurations)
      {
        for (auto const& node : conf.nodes)
        {
          active_nodes.emplace(node.first, node.second);
        }
      }

      // Remove all nodes in the node state that are not present in any active
      // configuration.
      std::vector<ccf::NodeId> to_remove;

      for (const auto& node : all_other_nodes)
      {
        if (active_nodes.find(node.first) == active_nodes.end())
        {
          to_remove.push_back(node.first);
        }
      }

      for (auto node_id : to_remove)
      {
        all_other_nodes.erase(node_id);
        LOG_INFO_FMT("Removed raft node {}", node_id);
      }

      // Add all active nodes that are not already present in the node state.
      for (auto node_info : active_nodes)
      {
        if (node_info.first == state->my_node_id)
        {
          continue;
        }

        if (all_other_nodes.find(node_info.first) == all_other_nodes.end())
        {
          if (!channels->have_channel(node_info.first))
          {
            LOG_DEBUG_FMT(
              "Configurations: create node channel with {}", node_info.first);

            channels->associate_node_address(
              node_info.first,
              node_info.second.hostname,
              node_info.second.port);
          }

          // A new node is sent only future entries initially. If it does not
          // have prior data, it will communicate that back to the leader.
          auto index = state->last_idx + 1;
          all_other_nodes.try_emplace(
            node_info.first, node_info.second, index, 0);

          if (leadership_state == kv::LeadershipState::Leader)
          {
            send_append_entries(node_info.first, index);
          }

          LOG_INFO_FMT(
            "Added raft node {} ({}:{})",
            node_info.first,
            node_info.second.hostname,
            node_info.second.port);
        }
      }
    }

  public:
    void update_parameters(kv::ConsensusParameters& params) override
    {
      // This should only be called when the state->lock is held, so we do not
      // acquire the lock here.
      CCF_ASSERT_FMT(
        params.reconfiguration_type != TWO_TRANSACTION || node_client,
        "Bug; all enclaves that support 2tx reconfig must have node_clients");
      reconfiguration_type = params.reconfiguration_type;
    }
  };
}
