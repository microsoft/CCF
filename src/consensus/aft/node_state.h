#pragma once
#include "kv/kv_types.h"
#include "raft_types.h"

#include <map>

namespace aft
{
  using Configuration = kv::Consensus::Configuration;

  struct Evidence{
    // TODO: we want things like the signature added here
  };

  struct NodeState
  {
    Configuration::NodeInfo node_info;

    // the highest index sent to the node
    Index sent_idx;

    // the highest matching index with the node that was confirmed
    Index match_idx;

    std::map<Index, std::unique_ptr<Evidence>> evidence;

    NodeState() = default;

    NodeState(
      const Configuration::NodeInfo& node_info_,
      Index sent_idx_,
      Index match_idx_ = 0) :
      node_info(node_info_), sent_idx(sent_idx_), match_idx(match_idx_)
    {}
  };
}