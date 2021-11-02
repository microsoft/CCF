// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/logger.h"
#include "node/signatures.h"

namespace ccf
{
  struct NodeAddr
  {
    std::string hostname;
    std::string port;
  };

  class ConfigurationChangeHook : public kv::ConsensusHook
  {
    kv::Version version;
    std::map<NodeId, std::optional<NodeAddr>> cfg_delta;
    std::unordered_set<NodeId> learners;
    std::unordered_set<NodeId> retired_nodes;

  public:
    ConfigurationChangeHook(kv::Version version_, const Nodes::Write& w) :
      version(version_)
    {
      for (const auto& [node_id, opt_ni] : w)
      {
        const auto& ni = opt_ni.value();
        switch (ni.status)
        {
          case NodeStatus::PENDING:
          {
            // Pending nodes are not added to consensus until they are
            // trusted
            break;
          }
          case NodeStatus::TRUSTED:
          {
            cfg_delta.try_emplace(
              node_id,
              NodeAddr{ni.node_address.hostname, ni.node_address.port});
            break;
          }
          case NodeStatus::RETIRED:
          {
            cfg_delta.try_emplace(node_id, std::nullopt);
            retired_nodes.insert(node_id);
            break;
          }
          case NodeStatus::LEARNER:
          {
            cfg_delta.try_emplace(
              node_id,
              NodeAddr{ni.node_address.hostname, ni.node_address.port});
            learners.insert(node_id);
            break;
          }
          case NodeStatus::RETIRING:
          {
            cfg_delta.try_emplace(node_id, std::nullopt);
            break;
          }
          default:
          {
          }
        }
      }
    }

    void call(kv::ConfigurableConsensus* consensus) override
    {
      auto configuration = consensus->get_latest_configuration_unsafe();
      for (const auto& [node_id, opt_ni] : cfg_delta)
      {
        if (opt_ni.has_value())
        {
          configuration.try_emplace(node_id, opt_ni->hostname, opt_ni->port);
        }
        else
        {
          configuration.erase(node_id);
        }
      }
      if (!cfg_delta.empty())
      {
        consensus->add_configuration(
          version, configuration, learners, retired_nodes);
      }
    }
  };

  class NetworkConfigurationsHook : public kv::ConsensusHook
  {
    kv::Version version;
    std::set<kv::NetworkConfiguration> configs;

  public:
    NetworkConfigurationsHook(
      kv::Version version_, const NetworkConfigurations::Write& w) :
      version(version_)
    {
      for (const auto& [rid, opt_nc] : w)
      {
        if (rid != CONFIG_COUNT_KEY && opt_nc.has_value())
        {
          configs.insert(opt_nc.value());
        }
      }
    }

    void call(kv::ConfigurableConsensus* consensus) override
    {
      // This hook is always executed after the hook for the nodes table above,
      // because the hooks are sorted by table name.
      assert(
        std::string(Tables::NODES) < std::string(Tables::NODES_CONFIGURATIONS));

      for (const auto& nc : configs)
      {
        consensus->reconfigure(version, nc);
      }
    }
  };

  // Note: The SignaturesHook and SerialisedMerkleTreeHook are separate because
  // the signature and the Merkle tree are recorded in distinct tables (for
  // serialisation performance reasons). However here, they are expected to
  // always be called together and for the same version as they are always
  // written by each signature transaction.
  class SignaturesHook : public kv::ConsensusHook
  {
    kv::Version version;
    PrimarySignature sig;

  public:
    SignaturesHook(kv::Version version_, const Signatures::Write& w) :
      version(version_)
    {
      assert(w.has_value()); // Signatures are never deleted
      version = version_;
      sig = w.value();
    }

    void call(kv::ConfigurableConsensus* consensus) override
    {
      consensus->record_signature(version, sig.sig, sig.node, sig.cert);
    }
  };

  class SerialisedMerkleTreeHook : public kv::ConsensusHook
  {
    kv::Version version;
    std::vector<uint8_t> tree;

  public:
    SerialisedMerkleTreeHook(
      kv::Version version_, const SerialisedMerkleTree::Write& w) :
      version(version_)
    {
      assert(w.has_value()); // Merkle trees are never deleted
      version = version_;
      tree = w.value();
    }

    void call(kv::ConfigurableConsensus* consensus) override
    {
      consensus->record_serialised_tree(version, tree);
    }
  };

}