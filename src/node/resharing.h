// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/tx_id.h"
#include "consensus/aft/impl/state.h"
#include "crypto/pem.h"
#include "crypto/verifier.h"
#include "enclave/rpc_sessions.h"
#include "kv/kv_types.h"
#include "node/identity.h"
#include "node/resharing_tracker.h"
#include "node/rpc/call_types.h"
#include "node/rpc/serdes.h"
#include "node/rpc/serialization.h"
#include "node/splitid_context.h"
#include "service_map.h"

#include <optional>
#include <vector>

namespace ccf
{
  using Index = uint64_t;
  using Resharings = ServiceMap<kv::ReconfigurationId, ResharingResult>;

  class ResharingsHook : public kv::ConsensusHook
  {
    kv::Version version;
    std::unordered_map<kv::ReconfigurationId, ResharingResult> results;

  public:
    ResharingsHook(kv::Version version_, const Resharings::Write& w) :
      version(version_)
    {
      for (const auto& [rid, opt_rr] : w)
      {
        if (opt_rr.has_value())
        {
          results.try_emplace(rid, opt_rr.value());
        }
      }
    }

    void call(kv::ConfigurableConsensus* consensus) override
    {
      for (auto& [rid, res] : results)
      {
        consensus->add_resharing_result(version, rid, res);
      }
    }
  };

  class SplitIdentityResharingTracker : public ResharingTracker
  {
  protected:
    typedef struct
    {
      SeqNo seq_no;
      uint64_t sid;
      kv::NetworkConfiguration config;
    } ResharingSession;

  public:
    SplitIdentityResharingTracker(
      const ccf::NodeId& nid_,
      std::shared_ptr<kv::Store> store_,
      std::shared_ptr<SplitIdContext> splitid_context_) :
      nid(nid_),
      splitid_context(splitid_context_),
      first_id_sampled(false)
    {}

    virtual ~SplitIdentityResharingTracker() {}

    virtual void set_active_config(const kv::NetworkConfiguration& cfg) override
    {}

    virtual const kv::NetworkConfiguration& active_config() const override
    {
      return active_config_;
    }

    virtual void add_network_configuration(
      ccf::SeqNo seqno, const kv::NetworkConfiguration& config) override
    {
      if (config.nodes.size() >= 3)
      {
        LOG_DEBUG_FMT(
          "Resharings: add network configuration/queue resharing for {}",
          config);
        std::lock_guard<std::mutex> guard(lock);
        sessions.push_back({seqno, 0, config});
      }
    }

    virtual void reshare(
      ccf::SeqNo seqno, const kv::NetworkConfiguration& config) override
    {
      LOG_DEBUG_FMT("Resharings: queue resharing for configuration {}", config);

      if (config.nodes.size() < 3)
      {
        LOG_FAIL_FMT(
          "Resharings: configuration too small, need at least 3 nodes");
        return;
      }

      std::lock_guard<std::mutex> guard(lock);
      if (!first_id_sampled)
      {
        assert(sessions.size() == 1 && sessions.front().sid == 0);
        std::vector<ccf::NodeId> nids;
        for (auto& nid : config.nodes)
        {
          nids.push_back(nid);
        }
        sessions.front().sid = splitid_context->sample(nids, config.rid);
        first_id_sampled = true;
      }
      else if (sessions.size() == 1)
      {
        start_next_session();
      }
    }

    virtual bool have_resharing_result_for(
      kv::ReconfigurationId rid, ccf::SeqNo idx) const override
    {
      auto idt = results.find(rid);
      return idt != results.end() && idt->second.seqno <= idx;
    }

    virtual void add_resharing_result(
      ccf::SeqNo seqno,
      kv::ReconfigurationId rid,
      const ResharingResult& result) override
    {
      LOG_DEBUG_FMT(
        "Resharings: adding resharing result for configuration #{}", rid);
      std::lock_guard<std::mutex> guard(lock);

      ResharingResult r = result;
      r.seqno = seqno;
      results.emplace(rid, r);

      for (auto& s : sessions)
      {
        LOG_DEBUG_FMT("Current sessions: sid={} cfg={}", s.sid, s.config);
      }

      if (rid != sessions.front().config.rid)
      {
        // Is it possible that a result gets submitted twice?
        LOG_DEBUG_FMT(
          "Resharings: possibly duplicate result submission for {}?", rid);
        // throw std::logic_error("unexpected reconfiguration id");
      }
      else
      {
        active_config_ = sessions.front().config;
        sessions.pop_front();
      }
    }

    virtual void start_next_session() override
    {
      if (!sessions.empty())
      {
        auto next_config = sessions.front().config;
        LOG_DEBUG_FMT("SPLITID: Trigger resharing for {}", next_config);
        sessions.front().sid = splitid_context->reshare(
          active_config_.to_vector(), next_config.to_vector(), next_config.rid);
      }
    }

    virtual void compact(Index idx) override
    {
      splitid_context->on_compact();
    }

    virtual ResharingResult get_resharing_result(
      kv::ReconfigurationId rid) const override
    {
      auto iit = results.find(rid);
      if (iit == results.end())
      {
        throw std::runtime_error("missing resharing result");
      }
      return iit->second;
    }

    virtual void rollback(Index idx) override
    {
      for (auto it = results.begin(); it != results.end();)
      {
        if (it->second.seqno > idx)
        {
          it = results.erase(it);
        }
        else
        {
          it++;
        }
      }

      for (auto it = sessions.begin(); it != sessions.end();)
      {
        if (it->seq_no > idx)
        {
          it = sessions.erase(it);
        }
        else
        {
          it++;
        }
      }

      splitid_context->on_rollback();
    }

  protected:
    const ccf::NodeId& nid;
    std::unordered_map<kv::ReconfigurationId, ResharingResult> results;
    std::deque<ResharingSession> sessions;
    std::shared_ptr<SplitIdContext> splitid_context;
    bool first_id_sampled;
    std::mutex lock;
    kv::NetworkConfiguration active_config_;
  };
}
