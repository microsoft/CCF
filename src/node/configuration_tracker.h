// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/app_interface.h"
#include "consensus/aft/raft_types.h"
#include "ds/logger.h"
#include "enclave/rpc_sessions.h"
#include "kv/kv_types.h"
#include "kv/store.h"
#include "node/config.h"
#include "node/entities.h"
#include "node/nodes.h"
#include "node/rpc/node_call_types.h"
#include "node/rpc/serdes.h"
#include "rpc/serialization.h"

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
    std::shared_ptr<enclave::RPCSessions> rpcsessions;
    std::shared_ptr<enclave::RPCMap> rpc_map;
    crypto::KeyPairPtr node_sign_kp;
    const crypto::Pem& node_cert;

    typedef struct
    {
      kv::Configuration active;
      kv::Configuration::Nodes passive;
    } TrackedConfig;
    std::list<TrackedConfig> configurations;

  public:
    ConfigurationTracker(
      const NodeId& node_id_,
      std::shared_ptr<kv::AbstractStore> store_,
      std::shared_ptr<enclave::RPCSessions> rpcsessions_,
      std::shared_ptr<enclave::RPCMap> rpc_map_,
      const crypto::KeyPairPtr& node_sign_kp_,
      const crypto::Pem& node_cert_) :
      node_id(node_id_),
      store(store_),
      rpcsessions(rpcsessions_),
      rpc_map(rpc_map_),
      node_sign_kp(node_sign_kp_),
      node_cert(node_cert_)
    {
      if (!node_sign_kp_)
        LOG_INFO_FMT("NO SIGNING KEY!");
      if (!rpc_map)
        LOG_INFO_FMT("NO RPC MAP!");
    }

    ~ConfigurationTracker() {}

    // Examine all configurations that are followed by a globally committed
    // configuration.
    bool commit(Index idx)
    {
      LOG_INFO_FMT("Config commit {}!", idx);

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

      LOG_INFO_FMT("Configurations now: {}", to_string());

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

      LOG_INFO_FMT("Configurations now: {}", to_string());

      return r;
    }

    void add(size_t idx, const kv::Consensus::ConsensusConfiguration&& config)
    {
      configurations.push_back(
        {{idx, std::move(config.active)}, std::move(config.passive)});

      LOG_INFO_FMT("Configurations now: {}", to_string());
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

    bool promote_if_possible(
      const NodeId& id, const TxID& txid, const TxID& primary_txid)
    {
      auto& last_config = configurations.back();
      if (last_config.passive.find(id) == last_config.passive.end())
        return true;

      if (!(txid < primary_txid) && store != nullptr)
      {
        return record_promotion(id);
      }

      return true;
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
      return configurations.back().active.nodes.find(id) !=
        configurations.back().active.nodes.end();
    }

    bool is_passive(const NodeId& id)
    {
      return !is_active(id) &&
        configurations.back().passive.find(id) !=
        configurations.back().passive.end();
    }

    size_t num_active_nodes()
    {
      return configurations.size() == 0 ?
        0 :
        configurations.back().active.nodes.size();
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

        for (const auto& node : c.active.nodes)
        {
          if (node.first == node_id)
          {
            match.push_back(last_idx);
          }
          else
          {
            match.push_back(nodes.at(node.first).match_idx);
          }

          LOG_INFO_FMT("Check: {} = {}", node.first, match.back());
        }

        sort(match.begin(), match.end());

        auto confirmed = match.at((match.size() - 1) / 2);

        LOG_INFO_FMT(
          "last_idx: {} confirmed: {} Matches: {}",
          last_idx,
          confirmed,
          ds::to_hex(match));

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
        ss << "]{" << c.active.idx << "} ";
      }
      return ss.str();
    }

    bool record_promotion(const NodeId& node_id)
    {
      LOG_INFO_FMT(
        "Promoting {} to TRUSTED as it has caught up with us", node_id);

      // Serialize request object
      PromoteNodeToTrusted::In ps = {node_id};

      http::Request request(fmt::format(
        "/{}/{}", ccf::get_actor_prefix(ccf::ActorsType::nodes), "promote"));
      request.set_header(
        http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);

      auto body = serdes::pack(ps, serdes::Pack::Text);
      request.set_body(&body);

      auto node_cert_der = crypto::cert_pem_to_der(node_cert);
      const auto key_id = crypto::Sha256Hash(node_cert_der).hex_str();

      http::sign_request(request, node_sign_kp, key_id);

      std::vector<uint8_t> packed = request.build_request();

      // Submit request
      auto node_session = std::make_shared<enclave::SessionContext>(
        enclave::InvalidSessionId, node_cert.raw());
      auto ctx = enclave::make_rpc_context(node_session, packed);

      const auto actor_opt = http::extract_actor(*ctx);
      if (!actor_opt.has_value())
      {
        throw std::logic_error("Unable to get actor");
      }

      const auto actor = rpc_map->resolve(actor_opt.value());
      auto frontend_opt = this->rpc_map->find(actor);
      if (!frontend_opt.has_value())
      {
        throw std::logic_error(
          "RpcMap::find returned invalid (empty) frontend");
      }

      auto frontend = frontend_opt.value();
      frontend->process(ctx);

      auto rs = ctx->get_response_status();

      if (rs != HTTP_STATUS_OK)
      {
        auto ser_res = ctx->serialise_response();
        std::string str((char*)ser_res.data(), ser_res.size());
        LOG_FAIL_FMT("Promotion request failed: {}", str);
      }

      return rs == HTTP_STATUS_OK;
    }
  };
}
