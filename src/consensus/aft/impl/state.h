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
    std::vector<kv::Version> versions_per_view;

  public:
    static constexpr kv::Consensus::View InvalidView = ccf::VIEW_UNKNOWN;

    void initialise(const std::vector<kv::Version>& terms_)
    {
      versions_per_view.clear();
      for (size_t i = 0; i < terms_.size(); ++i)
      {
        update(terms_[i], i + 1);
      }
      LOG_DEBUG_FMT(
        "Initialised views: {}", fmt::join(versions_per_view, ", "));
    }

    void update(kv::Version idx, kv::Consensus::View view)
    {
      LOG_DEBUG_FMT("Updating view to: {} at version: {}", view, idx);
      if (!versions_per_view.empty())
      {
        const auto current_latest_index = versions_per_view.back();
        if (idx < current_latest_index)
        {
          throw std::logic_error(fmt::format(
            "version must not move backwards ({} < {})",
            idx,
            current_latest_index));
        }
      }

      for (int64_t i = versions_per_view.size(); i < view; ++i)
      {
        versions_per_view.push_back(idx);
      }
      LOG_DEBUG_FMT("Resulting views: {}", fmt::join(versions_per_view, ", "));
    }

    kv::Consensus::View view_at(kv::Version idx)
    {
      auto it =
        upper_bound(versions_per_view.begin(), versions_per_view.end(), idx);

      // Indices before the version of the first view are unknown
      if (it == versions_per_view.begin())
      {
        return InvalidView;
      }

      return (it - versions_per_view.begin());
    }

    std::vector<kv::Version> get_history_until(
      kv::Version idx = std::numeric_limits<kv::Version>::max())
    {
      return {versions_per_view.begin(),
              std::upper_bound(
                versions_per_view.begin(), versions_per_view.end(), idx)};
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