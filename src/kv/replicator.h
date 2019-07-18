// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "../crypto/symmkey.h"
#include "kvtypes.h"

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
