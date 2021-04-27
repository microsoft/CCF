// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/app_interface.h"
#include "consensus/aft/raft_types.h"
#include "kv/kv_types.h"
#include "kv/store.h"
#include "node/config.h"
#include "node/entities.h"
#include "node/nodes.h"

using namespace ccf;

namespace aft
{
  using Index = uint64_t;

  struct NodeState
  {
    kv::Configuration::NodeInfo node_info;

    // the highest index sent to the node
    Index sent_idx;

    // the highest matching index with the node that was confirmed
    Index match_idx;

    NodeState() = default;

    NodeState(
      const kv::Configuration::NodeInfo& node_info_,
      Index sent_idx_,
      Index match_idx_ = 0) :
      node_info(node_info_),
      sent_idx(sent_idx_),
      match_idx(match_idx_)
    {}
  };

  class ConfigurationTracker
  {
  public:
    const NodeId& node_id;
    std::shared_ptr<kv::AbstractStore> store;

    typedef struct
    {
      kv::Configuration active;
      kv::Configuration::Nodes passive;
    } TrackedConfig;
    std::list<TrackedConfig> configurations;

  public:
    ConfigurationTracker(
      const NodeId& node_id_, std::shared_ptr<kv::AbstractStore> store_) :
      node_id(node_id_),
      store(store_)
    {}

    ~ConfigurationTracker() {}

    // Examine all configurations that are followed by a globally committed
    // configuration.
    bool examine_committed_configurations(Index idx)
    {
      bool r = false;
      while (true)
      {
        auto conf = configurations.begin();
        if (conf == configurations.end())
          break;

        auto next = std::next(conf);
        if (next == configurations.end())
          break;

        if (idx < next->active.idx)
          break;

        configurations.pop_front();
        r = true;
      }

      return r;
    }

    bool rollback(Index idx)
    {
      bool r = false;
      while (!configurations.empty() &&
             (configurations.back().active.idx > idx))
      {
        configurations.pop_back();
        r = true;
      }
      return r;
    }

    void add(size_t idx, const kv::Consensus::ConsensusConfiguration&& config)
    {
      configurations.push_back(
        {{idx, std::move(config.active)}, std::move(config.passive)});

      LOG_INFO_FMT("New configurations: {}", to_string());
    }

    bool empty() const
    {
      return configurations.empty();
    }

    kv::Consensus::ConsensusConfiguration get_latest_configuration_unsafe()
      const
    {
      if (configurations.empty())
      {
        return {};
      }

      return {configurations.back().active.nodes,
              configurations.back().passive};
    }

    void promote_if_possible(
      const NodeId& id, const TxID& txid, const TxID& primary_txid)
    {
      auto& last_config = configurations.back();
      if (last_config.passive.find(id) == last_config.passive.end())
        return;

      if (!(txid < primary_txid) && store != nullptr)
      {
        LOG_INFO_FMT("Promoting {} to TRUSTED as it has caught up with us", id);

        // TODO: Go through frontend

        kv::CommittableTx tx(store.get());
        auto nodes = tx.rw<Nodes>(Tables::NODES);
        auto value = nodes->get(id);
        if (value.has_value())
        {
          value->status = NodeStatus::TRUSTED;
          nodes->put(id, *value);
          if (tx.commit() != kv::CommitResult::SUCCESS)
          {
            throw std::logic_error("Promotion failed: error writing to store.");
          }
        }
      }
    }

    std::set<NodeId> active_node_ids()
    {
      // Find all nodes present in any active configuration.
      std::set<NodeId> result;

      for (auto& conf : configurations)
      {
        for (auto node : conf.active.nodes)
        {
          result.insert(node.first);
        }
      }

      return result;
    }

    kv::Configuration::Nodes active_nodes() const
    {
      kv::Configuration::Nodes r;

      for (auto& conf : configurations)
      {
        for (auto node : conf.active.nodes)
        {
          r.emplace(node.first, node.second);
        }
      }

      return r;
    }

    bool is_active(const NodeId& id)
    {
      for (auto& conf : configurations)
      {
        if (conf.active.nodes.find(id) != conf.active.nodes.end())
        {
          return true;
        }
      }

      return false;
    }

    bool is_passive(const NodeId& id)
    {
      if (is_active(id))
      {
        return false;
      }

      for (auto& conf : configurations)
      {
        if (conf.passive.find(id) != conf.passive.end())
        {
          return true;
        }
      }

      return false;
    }

    size_t num_active_nodes()
    {
      return active_nodes().size();
    }

    kv::Configuration::Nodes passive_nodes() const
    {
      kv::Configuration::Nodes r;

      for (auto& conf : configurations)
      {
        for (auto node : conf.passive)
        {
          r.emplace(node.first, node.second);
        }
      }

      return r;
    }

    kv::Configuration::Nodes all_nodes()
    {
      kv::Configuration::Nodes r;

      for (auto& conf : configurations)
      {
        for (auto node : conf.active.nodes)
        {
          r.emplace(node.first, node.second);
        }
        for (auto node : conf.passive)
        {
          r.emplace(node.first, node.second);
        }
      }

      return r;
    }

    Index cft_watermark(
      kv::Version last_idx, std::unordered_map<NodeId, aft::NodeState>& nodes)
    {
      Index r = std::numeric_limits<Index>::max();

      for (auto& c : configurations)
      {
        // The majority must be checked separately for each active
        // configuration.
        std::vector<Index> match;
        match.reserve(c.active.nodes.size() + 1);

        // In CFT mode, the passive nodes count toward the majority.
        for (const auto& cnodes : {c.active.nodes, c.passive})
        {
          for (const auto& node : cnodes)
          {
            if (node.first == node_id)
            {
              match.push_back(last_idx);
            }
            else
            {
              match.push_back(nodes.at(node.first).match_idx);
            }
          }
        }

        sort(match.begin(), match.end());
        auto confirmed = match.at((match.size() - 1) / 2);
        r = std::min(confirmed, r);
      }

      return r;
    }

    std::string to_string() const
    {
      std::stringstream ss;
      for (auto c : configurations)
      {
        ss << "[";
        ss << "active:";
        for (const auto& [node_id, _] : c.active.nodes)
          ss << " " << node_id;
        ss << " passive:";
        for (const auto& [node_id, _] : c.passive)
          ss << " " << node_id;
        ss << "] ";
      }
      return ss.str();
    }
  };
}
