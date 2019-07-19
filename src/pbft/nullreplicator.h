// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv/kvtypes.h"
#include "node/entities.h"
#include "node/nodetonode.h"

namespace pbft
{
  // TODO(#PBFT): This class should eventually disappear and become one with
  // PBFT. Note that all replicated entries are automatically marked as globally
  // committed.
  class NullReplicator : public kv::Replicator
  {
  private:
    std::shared_ptr<ccf::NodeToNode> n2n_channels;
    bool _is_leader;
    ccf::NodeId self;
    kv::Version global_commit_index;

  public:
    NullReplicator(
      std::shared_ptr<ccf::NodeToNode> n2n_channels_, ccf::NodeId self_) :
      n2n_channels(n2n_channels_),
      _is_leader(false),
      self(self_),
      global_commit_index(0)
    {}

    void force_become_leader()
    {
      _is_leader = true;
    }
    void force_become_leader(
      kv::Version index, kv::Term term, kv::Version commit_idx_)
    {
      _is_leader = true;
    }
    void force_become_leader(
      kv::Version index,
      kv::Term term,
      const std::vector<kv::Version>& terms,
      kv::Version commit_idx_)
    {
      _is_leader = true;
    }

    void enable_all_domains() {}
    void resume_replication() {}
    void suspend_replication(kv::Version) {}
    void periodic(std::chrono::milliseconds elapsed) {}
    void recv_message(const uint8_t* data, size_t size) {}

    void add_configuration(kv::Version, std::unordered_set<kv::NodeId> conf) {}

    bool replicate(
      const std::vector<std::tuple<kv::Version, std::vector<uint8_t>, bool>>&
        entries) override
    {
      for (auto&& [index, data, globally_committable] : entries)
      {
        if (index != global_commit_index + 1)
          return false;

        global_commit_index = index;
      }
      return true;
    }

    kv::Term get_term() override
    {
      return 2;
    }

    kv::Term get_term(kv::Version version) override
    {
      return 2;
    }

    kv::Version get_commit_idx() override
    {
      return global_commit_index;
    }

    bool is_leader() override
    {
      return _is_leader;
    }

    bool is_follower()
    {
      return !is_leader();
    }

    ccf::NodeId leader() override
    {
      return 0;
    }

    ccf::NodeId id() override
    {
      return self;
    }
  };
}