// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/key_pair.h"
#include "ccf/crypto/verifier.h"
#include "ccf/ds/logger.h"
#include "ccf/pal/locking.h"
#include "ccf/tx_status.h"
#include "consensus/aft/raft_types.h"
#include "kv/kv_types.h"

#include <map>
#include <set>

namespace aft
{
  class ViewHistory
  {
    // Entry i stores the first version in view i+1
    std::vector<kv::Version> views;

  public:
    static constexpr ccf::View InvalidView = ccf::VIEW_UNKNOWN;

    void initialise(const std::vector<kv::Version>& terms_)
    {
      views.clear();
      for (size_t i = 0; i < terms_.size(); ++i)
      {
        update(terms_[i], i + 1);
      }
      LOG_DEBUG_FMT("Initialised views: {}", fmt::join(views, ", "));
    }

    void update(kv::Version idx, ccf::View view)
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

    ccf::View view_at(kv::Version idx)
    {
      auto it = upper_bound(views.begin(), views.end(), idx);

      // Indices before the version of the first view are unknown
      if (it == views.begin())
      {
        return InvalidView;
      }

      return (it - views.begin());
    }

    kv::Version start_of_view(ccf::View view)
    {
      if (view > views.size() || view == InvalidView)
      {
        return kv::NoVersion;
      }

      // NB: If views == {5, 10, 10}, then view 2 doesn't start at 10. View 2
      // contains no transactions, and view 3 starts at 10
      const auto tentative = views[view - 1];
      if (view + 1 <= views.size() && views[view] == tentative)
      {
        return kv::NoVersion;
      }
      return tentative;
    }

    kv::Version end_of_view(ccf::View view)
    {
      // If this view has no start (potentially because it contains no
      // transactions), then it can't have an end
      if (start_of_view(view) == kv::NoVersion)
      {
        return kv::NoVersion;
      }

      if (view >= views.size() || view == InvalidView)
      {
        return kv::NoVersion;
      }

      // Otherwise the end of this view is the transaction before (- 1) the
      // start of the next view (views[view])
      return views[view] - 1;
    }

    std::vector<kv::Version> get_history_until(
      kv::Version idx = std::numeric_limits<kv::Version>::max())
    {
      return {views.begin(), std::upper_bound(views.begin(), views.end(), idx)};
    }

    // view should be non-zero as views start at one in here
    std::vector<kv::Version> get_history_since(uint64_t view)
    {
      if (view > views.size())
      {
        return {};
      }
      return {views.begin() + view - 1, views.end()};
    }

    void rollback(kv::Version idx)
    {
      auto it = upper_bound(views.begin(), views.end(), idx);
      views.erase(it, views.end());
      LOG_DEBUG_FMT(
        "Resulting views from rollback: {}", fmt::join(views, ", "));
    }
  };

  class Replica
  {
  public:
    Replica(const ccf::NodeId& id_, const std::vector<uint8_t>& cert_) :
      id(id_),
      verifier(crypto::make_unique_verifier(cert_))
    {}

    ccf::NodeId get_id() const
    {
      return id;
    }

  private:
    ccf::NodeId id;
    crypto::VerifierUniquePtr verifier;
  };

  struct State
  {
    State(const ccf::NodeId& my_node_id_) : my_node_id(my_node_id_) {}

    ccf::pal::Mutex lock;

    ccf::NodeId my_node_id;
    ccf::View current_view = 0;
    kv::Version last_idx = 0;
    kv::Version commit_idx = 0;

    kv::Version cft_watermark_idx = 0;

    ViewHistory view_history;
    kv::Version new_view_idx = 0;
    std::optional<ccf::NodeId> requested_evidence_from = std::nullopt;

    // When running with BFT, replicas do not know which replica to trust as the
    // primary during recovery startup. So what we do is just trust the first
    // replica that communicated with the replica in the view that it told us is
    // correct. This is a liveness issue if there is a failure during recovery
    // but CCF maintains integrity because it is derived from the members
    // signing the ledger the replica will see and verify before opening the
    // service.
    std::optional<std::tuple<ccf::NodeId, ccf::View>> initial_recovery_primary =
      std::nullopt;
  };
}