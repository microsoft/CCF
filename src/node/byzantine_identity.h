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
#include "node/rpc/call_types.h"
#include "node/rpc/serdes.h"
#include "node/rpc/serialization.h"
#include "service_map.h"

#include <vector>

namespace ccf
{
  struct ByzantineIdentity : public Identity
  {
    ByzantineIdentity() : Identity()
    {
      type = IdentityType::BYZANTINE;
    }
  };

  DECLARE_JSON_TYPE(ByzantineIdentity);
  DECLARE_JSON_REQUIRED_FIELDS(ByzantineIdentity, cert);

  using ByzantineIdentities =
    ServiceMap<kv::ReconfigurationId, ByzantineIdentity>;

  class ByzantineIdentitiesHook : public kv::ConsensusHook
  {
    kv::Version version;
    std::unordered_map<kv::ReconfigurationId, ByzantineIdentity> byids;

  public:
    ByzantineIdentitiesHook(
      kv::Version version_, const ByzantineIdentities::Write& w) :
      version(version_)
    {
      for (const auto& [rid, opt_bid] : w)
      {
        if (opt_bid.has_value())
        {
          LOG_DEBUG_FMT(
            "New Byzantine network identity, valid for configuration #{}.",
            rid);
          byids.try_emplace(rid, opt_bid.value());
        }
      }
    }

    void call(kv::ConfigurableConsensus* consensus) override
    {
      for (auto& [rid, id] : byids)
      {
        consensus->add_identity(version, rid, id);
      }
    }
  };

  class ByzantineIdentityTracker
  {
  public:
    enum class SessionState
    {
      STARTED,
      FINISHED
    };

    class Session
    {
    public:
      SessionState state = SessionState::STARTED;
      kv::NetworkConfiguration config;

      Session(const kv::NetworkConfiguration& config_) : config(config_) {}
    };

    ByzantineIdentityTracker(
      std::shared_ptr<aft::State> shared_state_,
      std::shared_ptr<enclave::RPCMap> rpc_map_,
      crypto::KeyPairPtr node_sign_kp_,
      const crypto::Pem& node_cert_) :
      shared_state(shared_state_),
      rpc_map(rpc_map_),
      node_sign_kp(node_sign_kp_),
      node_cert(node_cert_)
    {}

    virtual ~ByzantineIdentityTracker() {}

    void add_network_configuration(const kv::NetworkConfiguration& config)
    {
      network_configs[config.rid] = config;
    }

    void reshare(const kv::NetworkConfiguration& config)
    {
      auto rid = config.rid;
      LOG_DEBUG_FMT("Identities: start resharing for configuration #{}", rid);
      sessions.emplace(rid, Session(config));

      auto msg = std::make_unique<threading::Tmsg<UpdateIdentityTaskMsg>>(
        update_identity_cb, rid, rpc_map, node_sign_kp, node_cert);

      threading::ThreadMessaging::thread_messaging.add_task(
        threading::ThreadMessaging::get_execution_thread(
          threading::MAIN_THREAD_ID),
        std::move(msg));
    }

    kv::ReconfigurationId find_reconfiguration(
      const kv::Configuration::Nodes& nodes) const
    {
      // We're searching for a configuration with the same set of nodes as
      // `nodes`. We currently don't have an easy way to look up the
      // reconfiguration ID, which would make this unnecessary.
      for (auto& [rid, nc] : network_configs)
      {
        bool have_all = true;
        for (auto& [nid, byid] : nodes)
        {
          if (nc.nodes.find(nid) == nc.nodes.end())
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
      return -1;
    }

    bool have_identity_for(
      kv::ReconfigurationId rid, ccf::SeqNo commit_idx) const
    {
      auto idt = identities.find(rid);
      return idt != identities.end() && idt->second.seqno <= commit_idx;
    }

    void add_identity(
      ccf::SeqNo seqno, kv::ReconfigurationId rid, ccf::Identity id)
    {
      LOG_DEBUG_FMT("Identities: adding identity for configuration #{}", rid);

      assert(id.type == Identity::IdentityType::BYZANTINE);
      SeqNoById entry = {seqno, *reinterpret_cast<ByzantineIdentity*>(&id)};
      identities.emplace(rid, entry);

      sessions.erase(rid);

      // Delete old identities?
      for (auto it = sessions.begin(); it != sessions.end();)
      {
        if (it->first <= rid)
        {
          it = sessions.erase(it);
        }
        else
        {
          it++;
        }
      }
    }

    ByzantineIdentity get_identity(kv::ReconfigurationId rid) const
    {
      auto iit = identities.find(rid);
      if (iit == identities.end())
      {
        throw std::runtime_error("missing identity");
      }
      return iit->second.byid;
    }

    void rollback(SeqNo idx)
    {
      for (auto it = identities.begin(); it != identities.end();)
      {
        if (it->second.seqno > idx)
        {
          assert(sessions.find(it->first) == sessions.end());
          it = identities.erase(it);
        }
        else
        {
          it++;
        }
      }
    }

    struct UpdateIdentityTaskMsg
    {
      UpdateIdentityTaskMsg(
        kv::ReconfigurationId rid_,
        std::shared_ptr<enclave::RPCMap> rpc_map_,
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
      std::shared_ptr<enclave::RPCMap> rpc_map;
      crypto::KeyPairPtr node_sign_kp;
      const crypto::Pem& node_cert;
      size_t retries;
    };

  protected:
    std::shared_ptr<aft::State> shared_state;
    std::shared_ptr<enclave::RPCMap> rpc_map;
    crypto::KeyPairPtr node_sign_kp;
    const crypto::Pem& node_cert;
    std::unordered_map<kv::ReconfigurationId, Session> sessions;
    typedef struct
    {
      SeqNo seqno;
      ByzantineIdentity byid;
    } SeqNoById;
    std::unordered_map<kv::ReconfigurationId, SeqNoById> identities;
    std::unordered_map<kv::ReconfigurationId, kv::NetworkConfiguration>
      network_configs;

    static inline bool make_request(
      http::Request& request,
      std::shared_ptr<enclave::RPCMap> rpc_map,
      crypto::KeyPairPtr node_sign_kp,
      const crypto::Pem& node_cert)
    {
      auto node_cert_der = crypto::cert_pem_to_der(node_cert);
      const auto key_id = crypto::Sha256Hash(node_cert_der).hex_str();

      http::sign_request(request, node_sign_kp, key_id);
      std::vector<uint8_t> packed = request.build_request();
      auto node_session = std::make_shared<enclave::SessionContext>(
        enclave::InvalidSessionId, node_cert.raw());
      auto ctx = enclave::make_rpc_context(node_session, packed);

      const auto actor_opt = http::extract_actor(*ctx);
      if (!actor_opt.has_value())
      {
        throw std::logic_error("Unable to get actor");
      }

      const auto actor = rpc_map->resolve(actor_opt.value());
      auto frontend_opt = rpc_map->find(actor);
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
        LOG_FAIL_FMT("request failed: {}", str);
      }

      return rs == HTTP_STATUS_OK;
    }

    static inline bool request_update_identity(
      kv::ReconfigurationId rid,
      std::shared_ptr<enclave::RPCMap> rpc_map,
      crypto::KeyPairPtr node_sign_kp,
      const crypto::Pem& node_cert)
    {
      LOG_DEBUG_FMT("Submitting RPC call to update identity");
      ccf::UpdateIdentity::In ps = {rid};

      http::Request request(fmt::format(
        "/{}/{}",
        ccf::get_actor_prefix(ccf::ActorsType::nodes),
        "update-identity"));
      request.set_header(
        http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);

      auto body = serdes::pack(ps, serdes::Pack::Text);
      request.set_body(&body);
      return make_request(request, rpc_map, node_sign_kp, node_cert);
    }

    static void update_identity_cb(
      std::unique_ptr<threading::Tmsg<UpdateIdentityTaskMsg>> msg)
    {
      if (!request_update_identity(
            msg->data.rid,
            msg->data.rpc_map,
            msg->data.node_sign_kp,
            msg->data.node_cert))
      {
        if (--msg->data.retries > 0)
        {
          threading::ThreadMessaging::thread_messaging.add_task(
            threading::ThreadMessaging::get_execution_thread(
              threading::MAIN_THREAD_ID),
            std::move(msg));
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
