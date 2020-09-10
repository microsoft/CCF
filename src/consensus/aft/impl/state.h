// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/logger.h"
#include "ds/spin_lock.h"
#include "kv/kv_types.h"
#include "node/rpc/tx_status.h"
#include "tls/key_pair.h"
#include "tls/verifier.h"

#include <map>
#include <set>

namespace aft
{
  class ViewHistory
  {
    // Entry i stores the first version in view i+1
    std::vector<kv::Version> views;

  public:
    static constexpr kv::Consensus::View InvalidView = ccf::VIEW_UNKNOWN;

    void initialise(const std::vector<kv::Version>& terms_)
    {
      views.clear();
      for (size_t i = 0; i < terms_.size(); ++i)
      {
        update(terms_[i], i + 1);
      }
      LOG_DEBUG_FMT("ZZZZZ Initialised views: {}", fmt::join(views, ", "));
    }

    void update(kv::Version idx, kv::Consensus::View view)
    {
      LOG_DEBUG_FMT("ZZZZZ Updating view to: {} at version: {}", view, idx);
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

      for (int64_t i = views.size(); i < view; ++i)
      {
        views.push_back(idx);
      }
      LOG_DEBUG_FMT("ZZZZZ Resulting views: {}", fmt::join(views, ", "));
    }

    kv::Consensus::View term_at(kv::Version idx)
    {
      auto it = upper_bound(views.begin(), views.end(), idx);

      // Indices before the version of the first view are unknown
      if (it == views.begin())
      {
        return InvalidView;
      }

      return (it - views.begin());
    }
  };

  class Replica
  {
  public:
    Replica(kv::NodeId id_, const std::vector<uint8_t>& cert_) :
      id(id_),
      verifier(tls::make_unique_verifier(cert_))
    {}

    kv::NodeId get_id() const
    {
      return id;
    }

  private:
    kv::NodeId id;
    tls::VerifierUniquePtr verifier;
  };

  struct State
  {
    State(kv::NodeId my_node_id_) :
      my_node_id(my_node_id_),
      current_view(0),
      last_idx(0),
      commit_idx(0)
    {}

    SpinLock lock;
    std::map<kv::NodeId, std::shared_ptr<Replica>> configuration;

    kv::NodeId my_node_id;
    kv::Consensus::View current_view;
    kv::Version last_idx;
    kv::Version commit_idx;

    ViewHistory view_history;
  };
}