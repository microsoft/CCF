// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/aft/raft_types.h"
#include "crypto/key_pair.h"
#include "crypto/verifier.h"
#include "ds/logger.h"
#include "ds/spin_lock.h"
#include "kv/kv_types.h"
#include "node/rpc/tx_status.h"

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

      return views[view - 1];
    }

    std::vector<kv::Version> get_history_until(
      kv::Version idx = std::numeric_limits<kv::Version>::max())
    {
      return {views.begin(), std::upper_bound(views.begin(), views.end(), idx)};
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
    State(const ccf::NodeId& my_node_id_) :
      my_node_id(my_node_id_),
      current_view(0),
      last_idx(0),
      commit_idx(0),
      new_view_idx(0)
    {}

    SpinLock lock;
    std::map<ccf::NodeId, std::shared_ptr<Replica>> configuration;

    ccf::NodeId my_node_id;
    ccf::View current_view;
    kv::Version last_idx;
    kv::Version commit_idx;

    kv::Version cft_watermark_idx;
    kv::Version bft_watermark_idx;

    ViewHistory view_history;
    kv::Version new_view_idx;
    std::optional<ccf::NodeId> requested_evidence_from = std::nullopt;
  };
}