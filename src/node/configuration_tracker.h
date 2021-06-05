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
#include "node/rpc/node_call_types.h"
#include "node/rpc/serdes.h"
#include "rpc/serialization.h"

#include <algorithm>

using namespace ccf;

namespace aft
{
  struct NodeState
  {
    ccf::NodeInfo node_info;

    // the highest sequence number sent to the node
    SeqNo sent_idx;

    // the highest matching sequence number with the node that was confirmed
    SeqNo match_idx;

    NodeState() = default;

    NodeState(
      const ccf::NodeInfo& node_info_,
      SeqNo sent_idx_,
      SeqNo match_idx_ = 0,
      bool catching_up_ = true) :
      node_info(node_info_),
      sent_idx(sent_idx_),
      match_idx(match_idx_)
    {}
  };

  class ConfigurationTracker
  {
  public:
    NodeId node_id;
    ConsensusType consensus_type;
    std::shared_ptr<kv::AbstractStore> store;
    std::shared_ptr<enclave::RPCSessions> rpcsessions;
    std::shared_ptr<enclave::RPCMap> rpc_map;
    crypto::KeyPairPtr node_sign_kp;
    const Pem& node_cert; // For followers, this may change from self-signed to
                          // network-signed.
    std::unordered_map<ccf::NodeId, aft::NodeState> nodes;
    std::list<kv::Configuration> configurations;
    std::set<NodeId> passive_nodes;

  public:
    ConfigurationTracker(
      NodeId node_id_,
      ConsensusType consensus_type_,
      std::shared_ptr<kv::AbstractStore> store_,
      std::shared_ptr<enclave::RPCSessions> rpcsessions_,
      std::shared_ptr<enclave::RPCMap> rpc_map_,
      crypto::KeyPairPtr node_sign_kp_,
      const Pem& node_cert_) :
      node_id(node_id_),
      consensus_type(consensus_type_),
      store(store_),
      rpcsessions(rpcsessions_),
      rpc_map(rpc_map_),
      node_sign_kp(node_sign_kp_),
      node_cert(node_cert_)
    {
      if (!node_sign_kp_)
        LOG_FAIL_FMT("No signing key");
      if (!rpc_map)
        LOG_FAIL_FMT("No RPC map");
    }

    ~ConfigurationTracker() {}

    void update_node(const NodeId& id, const std::optional<ccf::NodeInfo>& info)
    {
      if (info.has_value())
      {
        LOG_DEBUG_FMT("Update {} ({})", id, info->status);
        auto nit = nodes.find(id);
        if (nit == nodes.end())
          nodes.emplace(id, NodeState(info.value(), 0));
        else
          nit->second.node_info = info.value();
      }
      else
      {
        LOG_DEBUG_FMT("Remove {}", id);
        nodes.erase(id);
      }
    }

    void update_node_progress(const NodeId& from, const SeqNo& seq_no)
    {
      assert(consensus_type == ConsensusType::BFT);
      auto nit = nodes.find(from);
      if (nit != nodes.end())
      {
        nit->second.match_idx = std::max(nit->second.match_idx, seq_no);
      }
    }

    const std::set<NodeId>& current() const
    {
      assert(configurations.size() > 0);
      return configurations.front().nodes;
    }

    NodeState& state(const NodeId& id)
    {
      auto nit = nodes.find(id);
      assert(nit != nodes.end());
      return nit->second;
    }

    const NodeState& state(const NodeId& id) const
    {
      auto nit = nodes.find(id);
      assert(nit != nodes.end());
      return nit->second;
    }

    const NodeInfo& info(const NodeId& id) const
    {
      auto nit = nodes.find(id);
      assert(nit != nodes.end());
      return nit->second.node_info;
    }

    // Examine all configurations that are followed by a globally committed
    // configuration.
    std::pair<std::set<NodeId>, std::set<NodeId>> commit(SeqNo seq_no)
    {
      LOG_TRACE_FMT("Configurations: commit {}!", seq_no);

      std::pair<std::set<NodeId>, std::set<NodeId>> r;

      // Check whether the next configuration can be activated according to
      // quorum rules. If so, pop and finalize.

      std::set<NodeId> before = current();

      while (true)
      {
        auto conf = configurations.begin();
        if (conf == configurations.end())
          break;

        auto next = std::next(conf);
        if (next == configurations.end())
          break;

        if (seq_no < next->seq_no)
          break;

        // TODO: Check 2f+1 of the new config are caught up

        configurations.pop_front();
      }

      auto& after = current();

      // Nodes added
      for (auto& id : after)
      {
        if (before.find(id) == before.end())
        {
          r.first.insert(id);
        }
      }

      // Nodes removed
      for (auto& id : before)
      {
        if (after.find(id) == after.end())
        {
          r.second.insert(id);
        }
      }

      LOG_TRACE_FMT("Configurations: {}", to_string());

      return r;
    }

    bool rollback(SeqNo seq_no)
    {
      bool r = false;
      while (!configurations.empty() && (configurations.back().seq_no > seq_no))
      {
        configurations.pop_back();
        r = true;
      }
      LOG_TRACE_FMT(
        "Configurations: rolled back to {}: {}", seq_no, to_string());
      return r;
    }

    void add(const kv::Configuration& config)
    {
      LOG_TRACE_FMT(
        "Configurations: add configuration of {} nodes @ {}",
        config.nodes.size(),
        config.seq_no);
      for (auto& id : config.nodes)
      {
        auto nit = nodes.find(id);
        if (nit == nodes.end())
        {
          LOG_FAIL_FMT("New node without info: {}", id);
          nodes.emplace(id, NodeState());
        }
        else
          LOG_TRACE_FMT(
            "  {} = {}:{}",
            id,
            nit->second.node_info.nodehost,
            nit->second.node_info.nodeport);
      }
      configurations.push_back(std::move(config));
      check_for_promotions(config);
    }

    void abort(kv::Version id)
    {
      // TODO.
    }

    bool promote_if_possible(
      const NodeId& id, const SeqNo& seq_no, const SeqNo& primary_seq_no)
    {
      // Check if enough new nodes have caught up to finalize the next config.

      auto nit = nodes.find(id);
      if (store != nullptr && nit != nodes.end() && seq_no >= primary_seq_no)
      {
        return record_promotion(id);
      }

      return true;
    }

    std::set<NodeId> all_nodes()
    {
      std::set<NodeId> r;

      for (const auto& c : configurations)
      {
        for (const auto& id : c.nodes)
        {
          r.insert(id);
        }
      }

      return r;
    }

    SeqNo cft_watermark(kv::Version last_idx)
    {
      SeqNo r = std::numeric_limits<SeqNo>::max();

      for (auto& c : configurations)
      {
        // The majority must be checked separately for each active
        // configuration.
        std::vector<SeqNo> match;
        match.reserve(c.nodes.size() + 1);

        for (const auto& id : c.nodes)
        {
          LOG_TRACE_FMT("CFTWM check: {}", id);
          if (id == node_id)
          {
            match.push_back(last_idx);
          }
          else
          {
            auto nit = nodes.find(id);
            assert(nit != nodes.end());
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

        LOG_TRACE_FMT(
          "last_idx={} confirmed={} r={} matches=[{}]",
          last_idx,
          confirmed,
          r,
          fmt::join(match, ", "));
      }

      return r;
    }

    std::string to_string() const
    {
      std::stringstream ss;
      for (auto c : configurations)
      {
        bool first = true;
        ss << "{";
        for (const auto& id : c.nodes)
        {
          if (first)
            first = false;
          else
            ss << " ";
          ss << id;
          auto nit = nodes.find(id);
          if (nit == nodes.end() && id != node_id)
            ss << "!";
          // else if (nit != nodes.end())
          //   ss << "*";
        }
        ss << "}@" << c.seq_no << " ";
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

    void check_for_promotions(const kv::Configuration& config)
    {
      // for (const auto& [id, info] : nodes)
      // {
      //   LOG_DEBUG_FMT("Promo check {}: {}", id, info.node_info.status);
      // }

      // for (const auto& [id, info] : config.nodes)
      // {
      //   LOG_DEBUG_FMT("In config: {}: {}", id, info.catching_up);
      //   if (!info.catching_up)
      //   {
      //     auto nit = nodes.find(id);
      //     if (nit != nodes.end() && nit->second.catching_up)
      //     {
      //       LOG_DEBUG_FMT("Observing promotion: {}", id);
      //       nit->second.catching_up = false;
      //     }
      //   }
      // }
    }

    static void promote_cb(
      ConfigurationTracker& configuration_tracker,
      NodeId from,
      SeqNo seq_no,
      SeqNo primary_seq_no)
    {
      if (!configuration_tracker.promote_if_possible(
            from, seq_no, primary_seq_no))
      {
        threading::ThreadMessaging::thread_messaging.add_task(
          [&configuration_tracker, from, seq_no, primary_seq_no]() {
            ConfigurationTracker::promote_cb(
              configuration_tracker, from, seq_no, primary_seq_no);
          });
      }
    }
  };
}
