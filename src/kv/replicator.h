// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "../crypto/symmkey.h"
#include "kvtypes.h"
#include "node/nodetonode.h"

#include <algorithm>
#include <iostream>

namespace kv
{
  class MultiReplicator : public Replicator
  {
  private:
    std::vector<std::unique_ptr<Replicator>> replicators;

  public:
    MultiReplicator(std::initializer_list<Replicator*> replicators_)
    {
      for (auto it = replicators_.begin(); it != replicators_.end(); ++it)
        replicators.push_back(std::unique_ptr<Replicator>(*it));
    }

    bool replicate(
      const std::vector<std::tuple<Version, std::vector<uint8_t>, bool>>&
        entries) override
    {
      for (auto it = replicators.begin(); it != replicators.end(); ++it)
      {
        if (!(*it)->replicate(entries))
          return false;
      }

      return true;
    }

    kv::Term get_term() override
    {
      return 0;
    }

    kv::Version get_commit_idx() override
    {
      return 0;
    }

    NodeId leader() override
    {
      return 1;
    }

    NodeId id() override
    {
      return 0;
    }

    kv::Term get_term(kv::Version version) override
    {
      return 2;
    }

    bool is_leader() override
    {
      return true;
    }
  };

  class NullReplicator : public Replicator
  {
  private:
    std::shared_ptr<ccf::NodeToNode> n2n_channels;
    bool i_am_leader;
    ccf::NodeId self;

  public:
    NullReplicator(std::shared_ptr<ccf::NodeToNode> n2n_channels_, ccf::NodeId self_) :
      n2n_channels(n2n_channels_),
      i_am_leader(false),
      self(self_)
    {}

    void force_become_leader()
    {
      i_am_leader = true;
    }
    void force_become_leader(Version index, Term term, Version commit_idx_)
    {
      i_am_leader = true;
    }
    void force_become_leader(
      Version index,
      Term term,
      const std::vector<Version>& terms,
      Version commit_idx_)
    {
      i_am_leader = true;
    }

    void enable_all_domains() {}
    void resume_replication() {}
    void suspend_replication(Version) {}
    void periodic(std::chrono::milliseconds elapsed)
    {
      if (i_am_leader)
      {
        std::vector<uint8_t> some_data;
        n2n_channels->send_authenticated(
          ccf::NodeMsgType::consensus_msg_raft, 1, some_data);
      }
    }
    void recv_message(const uint8_t* data, size_t size)
    {
      // LOG_FAIL << "!!!!!!! RECEIVED SOMETHING !!!!" << std::endl;
    }

    void add_configuration(Version, std::unordered_set<NodeId> conf) {}

    bool replicate(
      const std::vector<std::tuple<Version, std::vector<uint8_t>, bool>>&
        entries) override
    {
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
      return 0;
    }

    bool is_leader() override
    {
      return i_am_leader;
    }

    bool is_follower()
    {
      return !is_leader();
    }

    NodeId leader() override
    {
      return 0;
    }

    NodeId id() override
    {
      return self;
    }
  };

  class OStreamReplicator : public Replicator
  {
    std::ostream* const os;
    unsigned int n = 0;

  public:
    explicit OStreamReplicator(std::ostream* os) : os(os) {}

    bool replicate(
      const std::vector<std::tuple<Version, std::vector<uint8_t>, bool>>&
        entries) override
    {
      for (auto&& [index, data, globally_committable] : entries)
      {
        *os << "+++replication #" << n++ << "+++\n\t" << data.size()
            << " bytes: \"";
        os->write((const char*)data.data(), std::min(data.size(), (size_t)20u));
        *os << "...\"\n";
      }
      return true;
    }

    kv::Term get_term() override
    {
      return 0;
    }

    kv::Version get_commit_idx() override
    {
      return 0;
    }

    NodeId leader() override
    {
      return 1;
    }

    NodeId id() override
    {
      return 0;
    }

    kv::Term get_term(kv::Version version) override
    {
      return 2;
    }

    bool is_leader() override
    {
      return true;
    }
  };

  class CoutReplicator : public OStreamReplicator
  {
  public:
    CoutReplicator() : OStreamReplicator(&std::cout) {}
  };

  class StubReplicator : public Replicator
  {
  private:
    std::vector<std::vector<uint8_t>> replica;

  public:
    StubReplicator() : replica() {}

    bool replicate(
      const std::vector<std::tuple<Version, std::vector<uint8_t>, bool>>&
        entries) override
    {
      for (auto&& [index, data, globally_committable] : entries)
      {
        replica.push_back(data);
      }
      return true;
    }

    std::pair<std::vector<uint8_t>, bool> get_latest_data()
    {
      if (!replica.empty())
        return std::make_pair(replica.back(), true);
      else
        return std::make_pair(std::vector<uint8_t>(), false);
    }

    size_t number_of_replicas()
    {
      return replica.size();
    }

    void flush()
    {
      replica.clear();
    }

    kv::Term get_term() override
    {
      return 0;
    }

    kv::Version get_commit_idx() override
    {
      return 0;
    }

    NodeId leader() override
    {
      return 1;
    }

    NodeId id() override
    {
      return 0;
    }

    kv::Term get_term(kv::Version version) override
    {
      return 2;
    }

    bool is_leader() override
    {
      return true;
    }
  };

  class FollowerStubReplicator : public StubReplicator
  {
  public:
    bool is_leader() override
    {
      return false;
    }
  };

  class LeaderStubReplicator : public StubReplicator
  {
  public:
    bool is_leader() override
    {
      return true;
    }
  };
}
