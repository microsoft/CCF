// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/app_interface.h"
#include "ccf/entity_id.h"
#include "ccf/tx_id.h"
#include "consensus/aft/raft_types.h"
#include "ds/logger.h"
#include "enclave/consensus_type.h"
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
    std::set<NodeId> active_;
    std::set<NodeId> learners_;
    std::set<NodeId> receivers_;

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

    typedef struct
    {
      std::set<NodeId> to_add;
      std::set<NodeId> to_remove;
    } News;

    News update_node(const NodeId& id, const std::optional<ccf::NodeInfo>& info)
    {
      if (info.has_value())
      {
        LOG_DEBUG_FMT("Nodes: update {}: {}", id, info->status);
        auto nit = nodes.find(id);
        if (nit == nodes.end())
          nodes.emplace(id, NodeState(info.value(), 0));
        else
          nit->second.node_info = info.value();

        switch (info->status)
        {
          case NodeStatus::CATCHING_UP:
          {
            LOG_DEBUG_FMT("Nodes: New learner: {}", id);
            learners_.insert(id);
            return {{id}, {}};
            break;
          }
          case NodeStatus::TRUSTED:
          {
            active_.clear();
            receivers_.clear();
            auto lit = learners_.find(id);
            if (lit != learners_.end())
            {
              bool own = *lit == node_id;
              learners_.erase(lit);
              if (own)
              {
                // Observing own promotion, nothing else to do
                return {{}, {}};
              }
              return {{id}, {}};
            }
            else
            {
              // Node is trusted immediately, without learner phase
              if (configurations.empty())
              {
                configurations.push_back({0, {}});
              }
              configurations.front().nodes.insert(id);
              return {{id}, {}};
            }
            break;
          }
          default:
            return {{}, {}};
            break;
        }
      }
      else
      {
        LOG_DEBUG_FMT("Nodes: remove {}", id);
        nodes.erase(id);
        learners_.erase(id);
        return {{}, {id}};
      }

      LOG_DEBUG_FMT("Configurations: {}", to_string());
      return {{}, {}};
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

    const std::set<NodeId>& voters() const
    {
      if (configurations.size() == 0)
      {
        static std::set<NodeId> n = {};
        return n;
      }

      return configurations.front().nodes;
    }

    const std::set<NodeId>& learners() const
    {
      return learners_;
    }

    const std::set<NodeId>& active()
    {
      if (active_.empty())
      {
        for (const auto& cfg : configurations)
        {
          for (const auto& id : cfg.nodes)
          {
            if (learners_.find(id) == learners_.end())
            {
              active_.insert(id);
            }
          }
        }
      }

      return active_;
    }

    std::set<NodeId> receivers()
    {
      if (receivers_.empty())
      {
        receivers_ = active();
        for (const auto& id : learners())
        {
          receivers_.insert(id);
        }
        receivers_.erase(node_id);
      }

      return receivers_;
    }

    bool is_eligible_voter(const NodeId& id) const
    {
      const auto& vs = voters();
      return vs.find(id) != vs.end() && learners_.find(id) == learners_.end();
    }

    size_t num_eligible_voters() const
    {
      size_t r = 0;
      for (const auto& id : voters())
      {
        if (learners_.find(id) == learners_.end())
        {
          r++;
        }
      }
      return r;
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

    size_t num_trusted(const kv::Configuration& c)
    {
      size_t r = 0;
      for (auto& id : c.nodes)
      {
        auto nit = nodes.find(id);
        if (
          nit != nodes.end() &&
          nit->second.node_info.status == ccf::NodeStatus::TRUSTED)
        {
          LOG_DEBUG_FMT("{}: trusted", id);
          r++;
        }
      }
      return r;
    }

    bool enough_trusted(const kv::Configuration& c)
    {
      size_t n = num_trusted(c);

      // The exceptions (<= 2/3 nodes) enable adding nodes to tiny networks
      // which by themselves wouldn't have enough nodes to get quorum for a
      // transition to a larger configuration. Needs discussion.
      switch (consensus_type)
      {
        case CFT:
          return (n >= (c.nodes.size() / 2 + 1)) || c.nodes.size() <= 2;
        case BFT:
          return n >= (c.nodes.size() / 3 + 1) || c.nodes.size() <= 3;
        default:
          return false;
      }
    }

    // Examine all configurations that are followed by a globally committed
    // configuration.
    News commit(SeqNo seq_no, bool is_primary)
    {
      LOG_TRACE_FMT("Configurations: commit {}!", seq_no);

      News r;

      std::set<NodeId> before = active();

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

        LOG_TRACE_FMT(
          "Configurations: checking next configuration: {{{}}} num_trusted={}",
          fmt::join(next->nodes, ", "),
          num_trusted(*next));

        if (is_primary)
        {
          if (!enough_trusted(*next))
          {
            LOG_TRACE_FMT(
              "Configurations: not enough trusted nodes for next "
              "configuration");
            break;
          }
          else
          {
            LOG_DEBUG_FMT(
              "Configurations: quorum reached, promoting rest of "
              "next configuration");
            threading::ThreadMessaging::thread_messaging.add_task(
              [this, cfg = *next]() { promote_configuration_cb(*this, cfg); });
          }
        }

        if (num_trusted(*next) == next->nodes.size())
        {
          LOG_TRACE_FMT(
            "Configurations: all nodes trusted, switching to next "
            "configuration");
          configurations.pop_front();
          active_.clear();
          receivers_.clear();
        }
        else
        {
          break;
        }
      }

      std::set<NodeId> after = active();

      // Nodes added
      for (auto& id : after)
      {
        if (before.find(id) == before.end())
        {
          r.to_add.insert(id);
        }
      }

      // Nodes removed
      for (auto& id : before)
      {
        if (after.find(id) == after.end())
        {
          r.to_remove.insert(id);
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
      active_.clear();
      receivers_.clear();
      LOG_TRACE_FMT(
        "Configurations: rolled back to {}: {}", seq_no, to_string());
      return r;
    }

    News add(const kv::Configuration& config)
    {
      News r;
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
          r.to_add.insert(id);
        }
        else
        {
          LOG_TRACE_FMT(
            "  {} = {}:{}",
            id,
            nit->second.node_info.nodehost,
            nit->second.node_info.nodeport);
        }
      }
      configurations.push_back(std::move(config));
      active_.clear();
      receivers_.clear();
      return r;
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

    SeqNo cft_watermark(kv::Version last_idx, const kv::Configuration& c)
    {
      // The majority must be checked separately for each active
      // configuration.
      std::vector<SeqNo> matches;
      matches.reserve(c.nodes.size() + 1);

      for (const auto& id : c.nodes)
      {
        if (id == node_id)
        {
          LOG_TRACE_FMT("CFTWM check: {}={}", id, last_idx);
          matches.push_back(last_idx);
        }
        else
        {
          auto nit = nodes.find(id);
          assert(nit != nodes.end());
          LOG_TRACE_FMT("CFTWM check: {}={}", id, nit->second.match_idx);
          matches.push_back(nit->second.match_idx);
        }
      }

      size_t confirmed = 0;
      if (!matches.empty())
      {
        sort(matches.begin(), matches.end());
        switch (consensus_type)
        {
          case CFT:
            confirmed = matches.at((matches.size() - 1) / 2);
            break;
          case BFT:
            confirmed = matches.at((matches.size() - 1) / 3);
            break;
        }
      }

      LOG_TRACE_FMT(
        "last_idx={} confirmed={} matches=[{}]",
        last_idx,
        confirmed,
        fmt::join(matches, ", "));

      return confirmed;
    }

    SeqNo cft_watermark(kv::Version last_idx)
    {
      SeqNo r = std::numeric_limits<SeqNo>::max();

      for (auto& c : configurations)
      {
        size_t confirmed = cft_watermark(last_idx, c);
        r = std::min(confirmed, r);
      }

      return r == std::numeric_limits<SeqNo>::max() ? 0 : r;
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

    bool request_promote_node(const NodeId& node_id)
    {
      LOG_DEBUG_FMT("Promoting {} to TRUSTED", node_id);

      PromoteNodeToTrusted::In ps = {node_id};

      http::Request request(fmt::format(
        "/{}/{}",
        ccf::get_actor_prefix(ccf::ActorsType::nodes),
        "promote_node"));
      request.set_header(
        http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);

      auto body = serdes::pack(ps, serdes::Pack::Text);
      request.set_body(&body);
      return make_request(request);
    }

    bool request_promote_configuration(const kv::Configuration& configuration)
    {
      LOG_DEBUG_FMT("Promoting next configuration");

      PromoteConfiguration::In ps = {configuration};

      http::Request request(fmt::format(
        "/{}/{}",
        ccf::get_actor_prefix(ccf::ActorsType::nodes),
        "promote_configuration"));
      request.set_header(
        http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);

      auto body = serdes::pack(ps, serdes::Pack::Text);
      request.set_body(&body);

      return make_request(request);
    }

    bool make_request(http::Request& request)
    {
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

    static void promote_node_cb(
      ConfigurationTracker& configuration_tracker,
      NodeId id,
      size_t retries = 10)
    {
      if (!configuration_tracker.request_promote_node(id))
      {
        if (retries > 0)
        {
          threading::ThreadMessaging::thread_messaging.add_task(
            [&configuration_tracker, id, retries]() {
              ConfigurationTracker::promote_node_cb(
                configuration_tracker, id, retries - 1);
            });
        }
        else
        {
          LOG_DEBUG_FMT(
            "Failed request, giving up as there are no more retries left");
        }
      }
    }

    static void promote_configuration_cb(
      ConfigurationTracker& configuration_tracker,
      kv::Configuration cfg,
      size_t retries = 10)
    {
      if (!configuration_tracker.request_promote_configuration(cfg))
      {
        if (retries > 0)
        {
          threading::ThreadMessaging::thread_messaging.add_task(
            [&configuration_tracker, cfg, retries]() {
              ConfigurationTracker::promote_configuration_cb(
                configuration_tracker, cfg, retries - 1);
            });
        }
        else
        {
          LOG_DEBUG_FMT(
            "Failed request, giving up as there are no more retries left");
        }
      }
    }
  };
}
