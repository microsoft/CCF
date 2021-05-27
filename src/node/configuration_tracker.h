// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/app_interface.h"
#include "ccf/entity_id.h"
#include "ccf/tx_id.h"
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

    // Flag indicating whether this node is still catching up; before that it's
    // not an eligible voter.
    bool catching_up;

    NodeState() = default;

    NodeState(
      const kv::Configuration::NodeInfo& node_info_,
      Index sent_idx_,
      Index match_idx_ = 0) :
      node_info(node_info_),
      sent_idx(sent_idx_),
      match_idx(match_idx_),
      catching_up(true)
    {}
  };

  class ConfigurationTracker
  {
  public:
    const NodeId& node_id;
    ConsensusType consensus_type;
    std::shared_ptr<kv::AbstractStore> store;
    std::shared_ptr<enclave::RPCSessions> rpcsessions;
    std::shared_ptr<enclave::RPCMap> rpc_map;
    crypto::KeyPairPtr node_sign_kp;
    const crypto::Pem& node_cert;
    std::unordered_map<ccf::NodeId, aft::NodeState>& nodes;
    std::list<kv::Configuration> configurations;

  public:
    ConfigurationTracker(
      const NodeId& node_id_,
      ConsensusType consensus_type_,
      std::unordered_map<ccf::NodeId, aft::NodeState>& nodes_,
      std::shared_ptr<kv::AbstractStore> store_,
      std::shared_ptr<enclave::RPCSessions> rpcsessions_,
      std::shared_ptr<enclave::RPCMap> rpc_map_,
      const crypto::KeyPairPtr& node_sign_kp_,
      const crypto::Pem& node_cert_) :
      node_id(node_id_),
      consensus_type(consensus_type_),
      store(store_),
      rpcsessions(rpcsessions_),
      rpc_map(rpc_map_),
      node_sign_kp(node_sign_kp_),
      node_cert(node_cert_),
      nodes(nodes_)
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
      LOG_INFO_FMT("Configurations: commit {}!", idx);

      bool r = false;
      while (true)
      {
        auto conf = configurations.begin();
        if (conf == configurations.end())
          break;

        auto next = std::next(conf);
        if (next == configurations.end())
          break;

        if (idx < next->idx)
          break;

        configurations.pop_front();
        r = true;
      }

      LOG_INFO_FMT("Configurations: {}", to_string());

      return r;
    }

    bool rollback(Index idx)
    {
      LOG_INFO_FMT("Configurations: rollback to {}", idx);
      bool r = false;
      while (!configurations.empty() && (configurations.back().idx > idx))
      {
        configurations.pop_back();
        r = true;
      }
      LOG_INFO_FMT("Configurations: {}", to_string());
      return r;
    }

    void add(size_t idx, const kv::Configuration::Nodes&& config)
    {
      configurations.push_back({idx, std::move(config)});
      LOG_INFO_FMT("Configurations: {}", to_string());
    }

    bool empty() const
    {
      return configurations.empty();
    }

    kv::Configuration::Nodes get_latest_configuration_unsafe() const
    {
      if (configurations.empty())
      {
        return {};
      }

      return configurations.back().nodes;
    }

    bool promote_if_possible(
      const NodeId& id, const TxID& txid, const TxID& primary_txid)
    {
      auto nit = nodes.find(id);
      if (
        nit != nodes.end() && nit->second.catching_up &&
        !(txid < primary_txid) && store != nullptr)
      {
        nit->second.catching_up = false;
        return record_promotion(id);
      }

      return true;
    }

    void update_node_progress(
      const NodeId& from, const TxID& txid, const TxID& node_txid)
    {
      // TODO
    }

    std::set<NodeId> active_node_ids()
    {
      // Find all nodes present in any active configuration.
      std::set<NodeId> result;
      auto an = active_nodes();
      for (const auto& [id, _] : an)
        result.insert(id);
      return result;
    }

    kv::Configuration::Nodes active_nodes() const
    {
      kv::Configuration::Nodes r;

      for (auto& conf : configurations)
      {
        for (auto node : conf.nodes)
        {
          auto nit = nodes.find(node.first);
          if (nit != nodes.end() && !nit->second.catching_up)
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
        for (auto node : conf.nodes)
        {
          r.emplace(node.first, node.second);
        }
      }

      return r;
    }

    Index cft_watermark(
      kv::Version last_idx, std::unordered_map<NodeId, aft::NodeState>& nodes)
    {
      LOG_INFO_FMT(
        "Configurations: CFT watermark; configurations: {}", to_string());
      Index r = std::numeric_limits<Index>::max();

      for (auto& c : configurations)
      {
        assert(c.nodes.size() > 0);

        // The majority must be checked separately for each active
        // configuration.
        std::vector<Index> match;
        match.reserve(c.nodes.size() + 1);

        for (const auto& node : c.nodes)
        {
          auto nit = nodes.find(node.first);

          if (node.first == node_id)
          {
            LOG_TRACE_FMT("CFTWM check: {}={}", node_id, last_idx);
            match.push_back(last_idx);
          }
          else if (nit->second.catching_up)
          {
            LOG_TRACE_FMT("CFTWM not eligible: {}", nit->first);
          }
          else
          {
            LOG_TRACE_FMT(
              "CFTWM check: {}={}", node.first, nit->second.match_idx);
            match.push_back(nit->second.match_idx);
          }
        }

        // `match` may be empty if multiple joining nodes are not caught up and
        // the current node is leaving, or when the whole network is being
        // replaced.
        size_t confirmed = 0;
        if (!match.empty())
        {
          sort(match.begin(), match.end());
          confirmed = match.at((match.size() - 1) / 2);
          r = std::min(confirmed, r);
        }

        std::stringstream ss;
        for (auto& m : match)
          ss << m << " ";
        LOG_INFO_FMT(
          "last_idx={} confirmed={} r={} match={}",
          last_idx,
          confirmed,
          r,
          ss.str());
      }

      return r;
    }

    std::string to_string() const
    {
      std::stringstream ss;
      for (auto c : configurations)
      {
        bool first = true;
        ss << "[";
        for (const auto& [id, _] : c.nodes)
        {
          if (first)
            first = false;
          else
            ss << " ";
          ss << id;
        }
        ss << "]@" << c.idx << " ";
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

    static void promote_cb(
      ConfigurationTracker& configuration_tracker,
      const NodeId& from,
      const TxID& txid,
      const TxID& primary_txid)
    {
      if (!configuration_tracker.promote_if_possible(from, txid, primary_txid))
      {
        threading::ThreadMessaging::thread_messaging.add_task(
          [&configuration_tracker, &from, &txid, &primary_txid]() {
            ConfigurationTracker::promote_cb(
              configuration_tracker, from, txid, primary_txid);
          });
      }
    }
  };
}
