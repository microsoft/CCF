// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/pem.h"
#include "ccf/serdes.h"
#include "ccf/service/map.h"
#include "ccf/tx_id.h"
#include "consensus/aft/impl/state.h"
#include "enclave/rpc_sessions.h"
#include "kv/kv_types.h"
#include "node/identity.h"
#include "node/resharing_tracker.h"
#include "node/rpc/call_types.h"
#include "node/rpc/serialization.h"

#include <optional>
#include <vector>

namespace ccf
{
  using Index = uint64_t;

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
          LOG_DEBUG_FMT(
            "Resharings: new resharing result for configuration #{}.", rid);
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
  public:
    enum class SessionState
    {
      STARTED,
      FINISHED
    };

    class ResharingSession
    {
    public:
      SessionState state = SessionState::STARTED;
      kv::Configuration config;

      ResharingSession(const kv::Configuration& config_) : config(config_) {}
    };

    SplitIdentityResharingTracker(
      std::shared_ptr<aft::State> shared_state_,
      std::shared_ptr<ccf::RPCMap> rpc_map_,
      crypto::KeyPairPtr node_sign_kp_,
      const crypto::Pem& self_signed_node_cert_,
      const std::optional<crypto::Pem>& endorsed_node_cert_) :
      shared_state(shared_state_),
      rpc_map(rpc_map_),
      node_sign_kp(node_sign_kp_),
      self_signed_node_cert(self_signed_node_cert_),
      endorsed_node_cert(endorsed_node_cert_)
    {}

    virtual ~SplitIdentityResharingTracker() {}

    virtual void add_network_configuration(
      const kv::Configuration& config) override
    {
      configs[config.rid] = config;
    }

    virtual void reshare(const kv::Configuration& config) override
    {
      auto rid = config.rid;
      LOG_DEBUG_FMT("Resharings: start resharing for configuration #{}", rid);
      sessions.emplace(rid, ResharingSession(config));

      const auto& node_cert = endorsed_node_cert.has_value() ?
        endorsed_node_cert.value() :
        self_signed_node_cert;
      auto msg = std::make_unique<threading::Tmsg<UpdateResharingTaskMsg>>(
        update_resharing_cb, rid, rpc_map, node_sign_kp, node_cert);

      auto& tm = threading::ThreadMessaging::instance();
      tm.add_task(
        tm.get_execution_thread(threading::MAIN_THREAD_ID), std::move(msg));
    }

    virtual std::optional<kv::ReconfigurationId> find_reconfiguration(
      const kv::Configuration::Nodes& nodes) const override
    {
      // We're searching for a configuration with the same set of nodes as
      // `nodes`. We currently don't have an easy way to look up the
      // reconfiguration ID, which would make this unnecessary.
      for (auto& [rid, config] : configs)
      {
        bool have_all = true;
        for (auto& [nid, _] : nodes)
        {
          if (config.nodes.find(nid) == config.nodes.end())
          {
            have_all = false;
            break;
          }
        }
        if (have_all)
        {
          return rid;
        }
      }
      return std::nullopt;
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
      results.emplace(rid, result);
      sessions.erase(rid);
    }

    virtual void compact(Index idx) override
    {
      for (auto it = sessions.begin(); it != sessions.end();)
      {
        if (it->first <= idx)
        {
          it = sessions.erase(it);
        }
        else
        {
          it++;
        }
      }
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
          assert(sessions.find(it->first) == sessions.end());
          it = results.erase(it);
        }
        else
        {
          it++;
        }
      }
    }

    struct UpdateResharingTaskMsg
    {
      UpdateResharingTaskMsg(
        kv::ReconfigurationId rid_,
        std::shared_ptr<ccf::RPCMap> rpc_map_,
        crypto::KeyPairPtr node_sign_kp_,
        const crypto::Pem& node_cert_,
        size_t retries_ = 10) :
        rid(rid_),
        rpc_map(rpc_map_),
        node_sign_kp(node_sign_kp_),
        node_cert(node_cert_),
        retries(retries_)
      {}

      kv::ReconfigurationId rid;
      std::shared_ptr<ccf::RPCMap> rpc_map;
      crypto::KeyPairPtr node_sign_kp;
      const crypto::Pem& node_cert;
      size_t retries;
    };

  protected:
    std::shared_ptr<aft::State> shared_state;
    std::shared_ptr<ccf::RPCMap> rpc_map;
    crypto::KeyPairPtr node_sign_kp;
    const crypto::Pem& self_signed_node_cert;
    const std::optional<crypto::Pem>& endorsed_node_cert;
    std::unordered_map<kv::ReconfigurationId, ResharingSession> sessions;
    std::unordered_map<kv::ReconfigurationId, ResharingResult> results;
    std::unordered_map<kv::ReconfigurationId, kv::Configuration> configs;

    static inline bool make_request(
      http::Request& request,
      std::shared_ptr<ccf::RPCMap> rpc_map,
      crypto::KeyPairPtr node_sign_kp,
      const crypto::Pem& node_cert)
    {
      auto node_cert_der = crypto::cert_pem_to_der(node_cert);
      const auto key_id = crypto::Sha256Hash(node_cert_der).hex_str();

      http::sign_request(request, node_sign_kp, key_id);
      std::vector<uint8_t> packed = request.build_request();
      auto node_session = std::make_shared<ccf::SessionContext>(
        ccf::InvalidSessionId, node_cert.raw());
      auto ctx = ccf::make_rpc_context(node_session, packed);

      std::shared_ptr<ccf::RpcHandler> search =
        http::fetch_rpc_handler(ctx, rpc_map);

      search->process(ctx);

      auto rs = ctx->get_response_status();

      if (rs != HTTP_STATUS_OK)
      {
        auto ser_res = ctx->serialise_response();
        std::string str((char*)ser_res.data(), ser_res.size());
        LOG_FAIL_FMT("request failed: {}", str);
      }

      return rs == HTTP_STATUS_OK;
    }

    static inline bool request_update_resharing(
      kv::ReconfigurationId rid,
      std::shared_ptr<ccf::RPCMap> rpc_map,
      crypto::KeyPairPtr node_sign_kp,
      const crypto::Pem& node_cert)
    {
      ccf::UpdateResharing::In ps = {rid};

      http::Request request(fmt::format(
        "/{}/{}",
        ccf::get_actor_prefix(ccf::ActorsType::nodes),
        "update-resharing"));
      request.set_header(
        http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);

      auto body = serdes::pack(ps, serdes::Pack::Text);
      request.set_body(&body);
      return make_request(request, rpc_map, node_sign_kp, node_cert);
    }

    static void update_resharing_cb(
      std::unique_ptr<threading::Tmsg<UpdateResharingTaskMsg>> msg)
    {
      if (!request_update_resharing(
            msg->data.rid,
            msg->data.rpc_map,
            msg->data.node_sign_kp,
            msg->data.node_cert))
      {
        if (--msg->data.retries > 0)
        {
          auto& tm = threading::ThreadMessaging::instance();
          tm.add_task(
            tm.get_execution_thread(threading::MAIN_THREAD_ID), std::move(msg));
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
