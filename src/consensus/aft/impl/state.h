// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/verifier.h"
#include "ccf/pal/locking.h"
#include "ccf/tx_status.h"
#include "consensus/aft/raft_types.h"
#include "ds/internal_logger.h"
#include "kv/kv_types.h"

#include <deque>
#include <map>
#include <set>

namespace aft
{
  class ViewHistory
  {
    // Entry i stores the first version in view i+1
    std::vector<ccf::kv::Version> views;

  public:
    static constexpr ccf::View InvalidView = ccf::VIEW_UNKNOWN;

    void initialise(const std::vector<ccf::kv::Version>& terms_)
    {
      views.clear();
      for (size_t i = 0; i < terms_.size(); ++i)
      {
        update(terms_[i], i + 1);
      }
      LOG_DEBUG_FMT("Initialised views: {}", fmt::join(views, ", "));
    }

    void update(ccf::kv::Version idx, ccf::View view)
    {
      LOG_DEBUG_FMT("Updating view to: {} at version: {}", view, idx);
      if (!views.empty())
      {
        const auto current_latest_index = views.back();
        if (idx < current_latest_index)
        {
          throw std::logic_error(fmt::format(
            "version must not move backwards ({} < {})",
            idx,
            current_latest_index));
        }
      }

      for (ccf::View i = views.size(); i < view; ++i)
      {
        views.push_back(idx);
      }
      LOG_DEBUG_FMT("Resulting views: {}", fmt::join(views, ", "));
    }

    [[nodiscard]] ccf::View view_at(ccf::kv::Version idx) const
    {
      auto it = upper_bound(views.begin(), views.end(), idx);

      // Indices before the version of the first view are unknown
      if (it == views.begin())
      {
        return InvalidView;
      }

      return (it - views.begin());
    }

    [[nodiscard]] ccf::kv::Version start_of_view(ccf::View view) const
    {
      if (view > views.size() || view == InvalidView)
      {
        return ccf::kv::NoVersion;
      }

      // NB: If views == {5, 10, 10}, then view 2 doesn't start at 10. View 2
      // contains no transactions, and view 3 starts at 10
      const auto tentative = views[view - 1];
      if (view + 1 <= views.size() && views[view] == tentative)
      {
        return ccf::kv::NoVersion;
      }
      return tentative;
    }

    [[nodiscard]] ccf::kv::Version end_of_view(ccf::View view) const
    {
      // If this view has no start (potentially because it contains no
      // transactions), then it can't have an end
      if (start_of_view(view) == ccf::kv::NoVersion)
      {
        return ccf::kv::NoVersion;
      }

      if (view >= views.size() || view == InvalidView)
      {
        return ccf::kv::NoVersion;
      }

      // Otherwise the end of this view is the transaction before (- 1) the
      // start of the next view (views[view])
      return views[view] - 1;
    }

    [[nodiscard]] std::vector<ccf::kv::Version> get_history_until(
      ccf::kv::Version idx = std::numeric_limits<ccf::kv::Version>::max()) const
    {
      return {views.begin(), std::upper_bound(views.begin(), views.end(), idx)};
    }

    // view should be non-zero as views start at one in here
    [[nodiscard]] std::vector<ccf::kv::Version> get_history_since(
      uint64_t view) const
    {
      if (view > views.size())
      {
        return {};
      }
      return {views.begin() + view - 1, views.end()};
    }

    void rollback(ccf::kv::Version idx)
    {
      auto it = upper_bound(views.begin(), views.end(), idx);
      views.erase(it, views.end());
      LOG_DEBUG_FMT(
        "Resulting views from rollback: {}", fmt::join(views, ", "));
    }
  };

  struct State
  {
    State(ccf::NodeId node_id_, bool pre_vote_enabled_ = true) :
      node_id(std::move(node_id_)),
      pre_vote_enabled(pre_vote_enabled_)
    {}
    State() = default;

    ccf::pal::Mutex lock;

    ccf::NodeId node_id;
    ccf::View current_view = 0;
    ccf::kv::Version last_idx = 0;
    ccf::kv::Version commit_idx = 0;
    ViewHistory view_history;

    // Indices that are eligible for global commit, from a Node's perspective
    std::deque<Index> committable_indices;

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
    ccf::kv::LeadershipState leadership_state = ccf::kv::LeadershipState::None;
    ccf::kv::MembershipState membership_state =
      ccf::kv::MembershipState::Active;

    std::optional<ccf::kv::RetirementPhase> retirement_phase = std::nullopt;
    // Index at which this node observes its retirement
    std::optional<ccf::SeqNo> retirement_idx = std::nullopt;
    // Earliest index at which this node's retirement can be committed
    std::optional<ccf::SeqNo> retirement_committable_idx = std::nullopt;
    // Index at which this node observes its retired_committed, only set when
    // that index itself is committed
    std::optional<ccf::SeqNo> retired_committed_idx = std::nullopt;

    bool pre_vote_enabled = true;
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(State);
  DECLARE_JSON_REQUIRED_FIELDS(
    State,
    node_id,
    current_view,
    last_idx,
    commit_idx,
    leadership_state,
    membership_state,
    pre_vote_enabled);
  DECLARE_JSON_OPTIONAL_FIELDS(
    State,
    retirement_phase,
    retirement_idx,
    retirement_committable_idx,
    retired_committed_idx);
}