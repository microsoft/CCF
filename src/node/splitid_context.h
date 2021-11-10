// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/json.h"
#include "enclave/endpoint.h"
#include "enclave/rpc_context.h"
#include "enclave/rpc_map.h"
#include "enclave/rpc_sessions.h"
#include "http/http_parser.h"
#include "http/http_rpc_context.h"
#include "http/http_sig.h"
#include "http/http_status.h"
#include "kv/store.h"
#include "node/http_node_client.h"
#include "node/rpc/serdes.h"

#include <splitid/splitid.h>
#include <splitid/splitid_formatters.h>

using namespace SplitIdentity;

namespace SplitIdentity
{
  namespace EC
  {
    DECLARE_JSON_ENUM(CurveID, {{CurveID::SECP384R1, "secp384r1"}});
  }

  namespace ZKP
  {
    DECLARE_JSON_TYPE(CR);
    DECLARE_JSON_REQUIRED_FIELDS(CR, c, r);
    DECLARE_JSON_TYPE(MultProof)
    DECLARE_JSON_REQUIRED_FIELDS(
      MultProof, cy_aux, u_at_tau, v_at_tau, lz, c, responses);
  }

  DECLARE_JSON_TYPE(OpenKey);
  DECLARE_JSON_REQUIRED_FIELDS(OpenKey, x_share, zkp);
  DECLARE_JSON_TYPE(OpenK);
  DECLARE_JSON_REQUIRED_FIELDS(OpenK, k_share, zkp);
  DECLARE_JSON_TYPE(SignatureShare);
  DECLARE_JSON_REQUIRED_FIELDS(SignatureShare, ak, s, zkp);
  DECLARE_JSON_TYPE(Blame);
  DECLARE_JSON_REQUIRED_FIELDS(Blame, id, verifiable_symmetric_key);
  DECLARE_JSON_TYPE(Identity);
  DECLARE_JSON_REQUIRED_FIELDS(Identity, public_key, x_commits);

  struct RegisterRPC
  {
    struct In
    {
      ccf::NodeId node_id;
      std::vector<uint8_t> public_key;
    };

    using Out = void;
  };

  DECLARE_JSON_TYPE(RegisterRPC::In);
  DECLARE_JSON_REQUIRED_FIELDS(RegisterRPC::In, node_id, public_key);

  template <typename T>
  struct SplitIdRPC
  {
    struct In
    {
      uint64_t session_id;
      T payload;
    };

    using Out = void;
  };

  DECLARE_JSON_TYPE(EncryptedShares);
  DECLARE_JSON_REQUIRED_FIELDS(EncryptedShares, node_shares, public_key, zkp);
  DECLARE_JSON_TYPE(EncryptedDeal);
  DECLARE_JSON_REQUIRED_FIELDS(
    EncryptedDeal, id, encrypted_shares, commitments);
  DECLARE_JSON_TYPE(EncryptedResharing);
  DECLARE_JSON_REQUIRED_FIELDS(
    EncryptedResharing, encrypted_shares, batched_commits);

  typedef SplitIdRPC<EncryptedDeal> SamplingDealRPC;
  DECLARE_JSON_TYPE(SamplingDealRPC::In);
  DECLARE_JSON_REQUIRED_FIELDS(SamplingDealRPC::In, session_id, payload);

  typedef SplitIdRPC<EncryptedResharing> SamplingReshareRPC;
  DECLARE_JSON_TYPE(SamplingReshareRPC::In);
  DECLARE_JSON_REQUIRED_FIELDS(SamplingReshareRPC::In, session_id, payload);

  typedef SplitIdRPC<EncryptedDeal> ResharingDealRPC;
  typedef SplitIdRPC<EncryptedResharing> ResharingReshareRPC;
  // JSON equal to SamplingDealRPC/SamplingReshareRPC

  typedef SplitIdRPC<OpenKey> OpenKeyRPC;
  DECLARE_JSON_TYPE(OpenKeyRPC::In);
  DECLARE_JSON_REQUIRED_FIELDS(OpenKeyRPC::In, session_id, payload);

  using SigningDealRPC = SplitIdRPC<EncryptedDeal>;
  // JSON equal to SamplingDealRPC

  typedef SplitIdRPC<OpenK> OpenKRPC;
  DECLARE_JSON_TYPE(OpenKRPC::In);
  DECLARE_JSON_REQUIRED_FIELDS(OpenKRPC::In, session_id, payload);

  typedef SplitIdRPC<SignatureShare> SignatureShareRPC;
  DECLARE_JSON_TYPE(SignatureShareRPC::In);
  DECLARE_JSON_REQUIRED_FIELDS(SignatureShareRPC::In, session_id, payload);

  typedef SplitIdRPC<std::vector<uint8_t>> SignatureRPC;
  DECLARE_JSON_TYPE(SignatureRPC::In);
  DECLARE_JSON_REQUIRED_FIELDS(SignatureRPC::In, session_id, payload);

  typedef SplitIdRPC<Identity> UpdateIdentityRPC;
  DECLARE_JSON_TYPE(UpdateIdentityRPC::In);
  DECLARE_JSON_REQUIRED_FIELDS(UpdateIdentityRPC::In, session_id, payload);

  typedef SplitIdRPC<bool> CompleteResharingRPC;
  DECLARE_JSON_TYPE(CompleteResharingRPC::In);
  DECLARE_JSON_REQUIRED_FIELDS(CompleteResharingRPC::In, session_id);

  typedef struct
  {
    using In = void;

    struct Out
    {
      std::string pem;
    };
  } CurrentIdRPC;
  DECLARE_JSON_TYPE(CurrentIdRPC::Out);
  DECLARE_JSON_REQUIRED_FIELDS(CurrentIdRPC::Out, pem);

  struct SampleRPC
  {
    struct In
    {
      std::vector<ccf::NodeId> config;
      bool defensive;
      uint64_t app_id;
    };

    struct Out
    {
      uint64_t session_id;
      bool existed_before;
    };
  };

  struct SignRPC
  {
    struct In
    {
      std::vector<uint8_t> message;
      bool defensive;
      uint64_t app_id;
    };

    struct Out
    {
      uint64_t session_id;
    };
  };

  struct GetSigRPC
  {
    struct In
    {
      uint64_t session_id;
    };

    struct Out
    {
      std::vector<uint8_t> signature;
    };
  };

  struct ReshareRPC
  {
    struct In
    {
      Identity identity;
      std::vector<ccf::NodeId> next_config;
      bool defensive;
      uint64_t app_id;
    };

    struct Out
    {
      uint64_t session_id;
    };
  };

  DECLARE_JSON_TYPE(SampleRPC::In)
  DECLARE_JSON_REQUIRED_FIELDS(SampleRPC::In, config, defensive, app_id)
  DECLARE_JSON_TYPE(SampleRPC::Out)
  DECLARE_JSON_REQUIRED_FIELDS(SampleRPC::Out, session_id)
  DECLARE_JSON_TYPE(SignRPC::In)
  DECLARE_JSON_REQUIRED_FIELDS(SignRPC::In, message, defensive, app_id)
  DECLARE_JSON_TYPE(SignRPC::Out)
  DECLARE_JSON_REQUIRED_FIELDS(SignRPC::Out, session_id)
  DECLARE_JSON_TYPE(GetSigRPC::In)
  DECLARE_JSON_REQUIRED_FIELDS(GetSigRPC::In, session_id)
  DECLARE_JSON_TYPE(GetSigRPC::Out)
  DECLARE_JSON_REQUIRED_FIELDS(GetSigRPC::Out, signature)
  DECLARE_JSON_TYPE(ReshareRPC::In)
  DECLARE_JSON_REQUIRED_FIELDS(
    ReshareRPC::In, identity, next_config, defensive, app_id)
  DECLARE_JSON_TYPE(ReshareRPC::Out)
  DECLARE_JSON_REQUIRED_FIELDS(ReshareRPC::Out, session_id)

  DECLARE_JSON_TYPE(Session<ccf::NodeId>);
  DECLARE_JSON_REQUIRED_FIELDS(
    Session<ccf::NodeId>,
    defensive,
    curve,
    encrypted_reshares,
    config,
    indices,
    sharing_indices,
    app_id);

  DECLARE_JSON_TYPE_WITH_BASE(
    ResharingSession<ccf::NodeId>, Session<ccf::NodeId>);
  DECLARE_JSON_REQUIRED_FIELDS(
    ResharingSession<ccf::NodeId>,
    next_config,
    next_indices,
    next_sharing_indices,
    encrypted_deals,
    batched_commits,
    previous_identity);

  DECLARE_JSON_TYPE_WITH_BASE(
    SamplingSession<ccf::NodeId>, ResharingSession<ccf::NodeId>);
  DECLARE_JSON_REQUIRED_FIELDS(SamplingSession<ccf::NodeId>, open_keys)

  DECLARE_JSON_TYPE_WITH_BASE(
    SigningSession<ccf::NodeId>, Session<ccf::NodeId>);
  DECLARE_JSON_REQUIRED_FIELDS(
    SigningSession<ccf::NodeId>,
    encrypted_deals,
    message,
    openks,
    signature_shares,
    signature);

  DECLARE_JSON_ENUM(
    Context<ccf::NodeId>::SigningSessionCache::ProtocolState,
    {{Context<ccf::NodeId>::SigningSessionCache::ProtocolState::SESSION_CREATED,
      "session_created"},
     {Context<ccf::NodeId>::SigningSessionCache::ProtocolState::SUBMITTED_DEAL,
      "submitted_deal"},
     {Context<ccf::NodeId>::SigningSessionCache::ProtocolState::SUBMITTED_OPENK,
      "submitted_openk"},
     {Context<ccf::NodeId>::SigningSessionCache::ProtocolState::
        SUBMITTED_SIGNATURE_SHARE,
      "submitted_signature_share"},
     {Context<
        ccf::NodeId>::SigningSessionCache::ProtocolState::SUBMITTED_SIGNATURE,
      "submitted_signature"},
     {Context<
        ccf::NodeId>::SigningSessionCache::ProtocolState::COMPARED_SIGNATURE,
      "compared_signature"}});
  DECLARE_JSON_TYPE(Context<ccf::NodeId>::SigningSessionCache);
  DECLARE_JSON_REQUIRED_FIELDS(
    Context<ccf::NodeId>::SigningSessionCache, protocol_state, r);

  DECLARE_JSON_ENUM(
    Context<ccf::NodeId>::ResharingSessionCache::ProtocolState,
    {{Context<
        ccf::NodeId>::ResharingSessionCache::ProtocolState::SESSION_CREATED,
      "session_created"},
     {Context<
        ccf::NodeId>::ResharingSessionCache::ProtocolState::SUBMITTED_DEAL,
      "submitted_deal"},
     {Context<
        ccf::NodeId>::ResharingSessionCache::ProtocolState::SUBMITTED_RESHARING,
      "submitted_resharing"},
     {Context<
        ccf::NodeId>::ResharingSessionCache::ProtocolState::COMMITMENTS_UPDATED,
      "commitments_updated"}});
  DECLARE_JSON_TYPE(Context<ccf::NodeId>::ResharingSessionCache);
  DECLARE_JSON_REQUIRED_FIELDS(
    Context<ccf::NodeId>::ResharingSessionCache, protocol_state);

  DECLARE_JSON_ENUM(
    Context<ccf::NodeId>::SamplingSessionCache::ProtocolState,
    {
      {Context<
         ccf::NodeId>::SamplingSessionCache::ProtocolState::SESSION_CREATED,
       "session_created"},
      {Context<
         ccf::NodeId>::SamplingSessionCache::ProtocolState::SUBMITTED_DEAL,
       "submitted_deal"},
      {Context<
         ccf::NodeId>::SamplingSessionCache::ProtocolState::SUBMITTED_RESHARING,
       "submitted_resharing"},
      {Context<
         ccf::NodeId>::SamplingSessionCache::ProtocolState::SUBMITTED_OPEN_KEY,
       "submitted_open_key"},
      {Context<
         ccf::NodeId>::SamplingSessionCache::ProtocolState::COMPUTED_PUBLIC_KEY,
       "computed_public_key"},
    });
  DECLARE_JSON_TYPE(Context<ccf::NodeId>::SamplingSessionCache);
  DECLARE_JSON_REQUIRED_FIELDS(
    Context<ccf::NodeId>::SamplingSessionCache, protocol_state);
};

namespace ccf
{
  class CCFRequestAdapter : public RequestAdapter<ccf::NodeId>
  {
  public:
    CCFRequestAdapter(
      std::shared_ptr<HTTPNodeClient> node_client, const ccf::NodeId& nid) :
      RequestAdapter<ccf::NodeId>(),
      nid(nid),
      node_client(node_client)
    {}

    virtual ~CCFRequestAdapter() {}

    virtual bool submit_registration(
      const std::vector<uint8_t>& public_key) const override
    {
      RegisterRPC::In in = {nid, public_key};

      http::Request request(fmt::format(
        "/{}/{}",
        ccf::get_actor_prefix(ccf::ActorsType::nodes),
        "splitid/register"));
      request.set_header(
        http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);

      auto body = serdes::pack(in, serdes::Pack::Text);
      request.set_body(&body);
      return node_client->make_request(request);
    }

    virtual uint64_t sample(
      const std::vector<ccf::NodeId>& config,
      bool defensive,
      uint64_t app_id = 0) const override
    {
      SampleRPC::In in = {config, defensive, app_id};

      http::Request request(fmt::format(
        "/{}/{}",
        ccf::get_actor_prefix(ccf::ActorsType::nodes),
        "splitid/sample"));
      request.set_header(
        http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);

      auto body = serdes::pack(in, serdes::Pack::Text);
      request.set_body(&body);
      node_client->make_request(request);
      return true;
    }

    virtual bool submit_sampling_deal(
      uint64_t session_id, const EncryptedDeal& encrypted_deal) const override
    {
      SamplingDealRPC::In in = {session_id, encrypted_deal};

      http::Request request(fmt::format(
        "/{}/{}",
        ccf::get_actor_prefix(ccf::ActorsType::nodes),
        "splitid/sampling/deal"));
      request.set_header(
        http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);

      auto body = serdes::pack(in, serdes::Pack::Text);
      request.set_body(&body);
      return node_client->make_request(request);
    }

    virtual bool submit_sampling_resharing(
      uint64_t session_id,
      const EncryptedResharing& encrypted_resharing) const override
    {
      SamplingReshareRPC::In in = {session_id, encrypted_resharing};

      http::Request request(fmt::format(
        "/{}/{}",
        ccf::get_actor_prefix(ccf::ActorsType::nodes),
        "splitid/sampling/resharing"));
      request.set_header(
        http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);

      auto body = serdes::pack(in, serdes::Pack::Text);
      request.set_body(&body);
      return node_client->make_request(request);
    }

    virtual bool submit_open_key(
      uint64_t session_id, const OpenKey& open_key) const override
    {
      OpenKeyRPC::In in = {session_id, open_key};

      http::Request request(fmt::format(
        "/{}/{}",
        ccf::get_actor_prefix(ccf::ActorsType::nodes),
        "splitid/sampling/open_key"));
      request.set_header(
        http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);

      auto body = serdes::pack(in, serdes::Pack::Text);
      request.set_body(&body);
      return node_client->make_request(request);
    }

    virtual bool submit_identity(
      uint64_t session_id, const Identity& identity) const override
    {
      UpdateIdentityRPC::In in = {session_id, identity};

      http::Request request(fmt::format(
        "/{}/{}",
        ccf::get_actor_prefix(ccf::ActorsType::nodes),
        "splitid/update-identity"));
      request.set_header(
        http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);

      auto body = serdes::pack(in, serdes::Pack::Text);
      request.set_body(&body);
      return node_client->make_request(request);
    }

    virtual uint64_t sign(
      const std::vector<ccf::NodeId>& config,
      const std::vector<uint8_t>& message,
      bool defensive,
      uint64_t app_id = 0) const override
    {
      SignRPC::In in = {message, defensive, app_id};

      http::Request request(fmt::format(
        "/{}/{}",
        ccf::get_actor_prefix(ccf::ActorsType::nodes),
        "splitid/sign"));
      request.set_header(
        http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);

      auto body = serdes::pack(in, serdes::Pack::Text);
      request.set_body(&body);
      return node_client->make_request(request);
    }

    virtual bool submit_signing_deal(
      uint64_t session_id, const EncryptedDeal& encrypted_deal) const override
    {
      SigningDealRPC::In in = {session_id, encrypted_deal};

      http::Request request(fmt::format(
        "/{}/{}",
        ccf::get_actor_prefix(ccf::ActorsType::nodes),
        "splitid/signing/deal"));
      request.set_header(
        http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);

      auto body = serdes::pack(in, serdes::Pack::Text);
      request.set_body(&body);
      return node_client->make_request(request);
    }

    virtual bool submit_openk(
      uint64_t session_id, const OpenK& openk) const override
    {
      OpenKRPC::In in = {session_id, openk};

      http::Request request(fmt::format(
        "/{}/{}",
        ccf::get_actor_prefix(ccf::ActorsType::nodes),
        "splitid/signing/openk"));
      request.set_header(
        http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);

      auto body = serdes::pack(in, serdes::Pack::Text);
      request.set_body(&body);
      return node_client->make_request(request);
    }

    virtual bool submit_signature_share(
      uint64_t session_id, const SignatureShare& signature_share) const override
    {
      SignatureShareRPC::In in = {session_id, signature_share};
      http::Request request(fmt::format(
        "/{}/{}",
        ccf::get_actor_prefix(ccf::ActorsType::nodes),
        "splitid/signing/signature_share"));
      request.set_header(
        http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);

      auto body = serdes::pack(in, serdes::Pack::Text);
      request.set_body(&body);
      return node_client->make_request(request);
    }

    virtual bool submit_signature(
      uint64_t session_id, const std::vector<uint8_t>& signature) const override
    {
      SignatureRPC::In in = {session_id, signature};
      http::Request request(fmt::format(
        "/{}/{}",
        ccf::get_actor_prefix(ccf::ActorsType::nodes),
        "splitid/signing/signature"));
      request.set_header(
        http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);

      auto body = serdes::pack(in, serdes::Pack::Text);
      request.set_body(&body);
      return node_client->make_request(request);
    }

    virtual uint64_t reshare(
      const Identity& current_identity,
      const std::vector<ccf::NodeId>& config,
      const std::vector<ccf::NodeId>& next_config,
      bool defensive,
      uint64_t app_id = 0) const override
    {
      ReshareRPC::In in = {current_identity, next_config, defensive, app_id};

      http::Request request(fmt::format(
        "/{}/{}",
        ccf::get_actor_prefix(ccf::ActorsType::nodes),
        "splitid/reshare"));
      request.set_header(
        http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);

      auto body = serdes::pack(in, serdes::Pack::Text);
      request.set_body(&body);
      return node_client->make_request(request);
    }

    virtual bool submit_resharing_deal(
      uint64_t session_id, const EncryptedDeal& encrypted_deal) const override
    {
      ResharingDealRPC::In in = {session_id, encrypted_deal};

      http::Request request(fmt::format(
        "/{}/{}",
        ccf::get_actor_prefix(ccf::ActorsType::nodes),
        "splitid/resharing/deal"));
      request.set_header(
        http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);

      auto body = serdes::pack(in, serdes::Pack::Text);
      request.set_body(&body);
      return node_client->make_request(request);
    }

    virtual bool submit_resharing_resharing(
      uint64_t session_id,
      const EncryptedResharing& encrypted_resharing) const override
    {
      ResharingReshareRPC::In in = {session_id, encrypted_resharing};

      http::Request request(fmt::format(
        "/{}/{}",
        ccf::get_actor_prefix(ccf::ActorsType::nodes),
        "splitid/resharing/reshare"));
      request.set_header(
        http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);

      auto body = serdes::pack(in, serdes::Pack::Text);
      request.set_body(&body);
      return node_client->make_request(request);
    }

    virtual bool complete_resharing(uint64_t session_id) const override
    {
      CompleteResharingRPC::In ps = {session_id, false};

      http::Request request(fmt::format(
        "/{}/{}",
        ccf::get_actor_prefix(ccf::ActorsType::nodes),
        "splitid/resharing/complete"));
      request.set_header(
        http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);

      auto body = serdes::pack(ps, serdes::Pack::Text);
      request.set_body(&body);
      return node_client->make_request(request);
    }

  protected:
    ccf::NodeId nid;
    std::shared_ptr<HTTPNodeClient> node_client;
  };

  class CCFSplitIdContext : public SplitIdentity::Context<ccf::NodeId>
  {
  public:
    using PublicKeys = ccf::ServiceMap<ccf::NodeId, std::vector<uint8_t>>;
    using SamplingSessions =
      ccf::ServiceMap<size_t, SamplingSession<ccf::NodeId>>;
    using SigningSessions =
      ccf::ServiceMap<size_t, SigningSession<ccf::NodeId>>;
    using ResharingSessions =
      ccf::ServiceMap<size_t, ResharingSession<ccf::NodeId>>;
    using CurrentIdentity = ccf::ServiceMap<size_t, Identity>;

    PublicKeys public_keys;
    SamplingSessions sampling_sessions;
    SigningSessions signing_sessions;
    ResharingSessions resharing_sessions;
    CurrentIdentity current_identity;

    using LocalSigningState = ccf::ServiceMap<size_t, SigningSessionCache>;
    using LocalResharingState = ccf::ServiceMap<size_t, ResharingSessionCache>;
    using LocalSamplingState = ccf::ServiceMap<size_t, SamplingSessionCache>;
    LocalSigningState local_signing_state;
    LocalResharingState local_resharing_state;
    LocalSamplingState local_sampling_state;

    CCFSplitIdContext(
      const ccf::NodeId& nid,
      std::shared_ptr<kv::Store> store,
      std::shared_ptr<RequestAdapter<ccf::NodeId>> request_adapter,
      bool defensive = false) :
      SplitIdentity::Context<ccf::NodeId>(nid, request_adapter),
      public_keys("public:ccf.splitid.public_keys"),
      sampling_sessions("public:ccf.splitid.sampling"),
      signing_sessions("public:ccf.splitid.signing"),
      resharing_sessions("public:ccf.splitid.resharing"),
      current_identity("public:ccf.splitid.current"),
      local_signing_state("public:ccf.splitid.local.signing"),
      local_resharing_state("public:ccf.splitid.local.resharing"),
      local_sampling_state("public:ccf.splitid.local.sampling"),
      store(store),
      defensive(defensive)
    {
      store->set_map_hook(
        public_keys.get_name(),
        public_keys.wrap_map_hook(
          [this](kv::Version version, const typename PublicKeys::Write& w)
            -> kv::ConsensusHookPtr {
            return std::make_unique<PublicKeysHook>(version, w, *this);
          }));
      store->set_map_hook(
        sampling_sessions.get_name(),
        sampling_sessions.wrap_map_hook(
          [this](kv::Version version, const typename SamplingSessions::Write& w)
            -> kv::ConsensusHookPtr {
            return std::make_unique<SamplingSessionsHook>(version, w, *this);
          }));
      store->set_map_hook(
        signing_sessions.get_name(),
        signing_sessions.wrap_map_hook(
          [this](kv::Version version, const typename SigningSessions::Write& w)
            -> kv::ConsensusHookPtr {
            return std::make_unique<SigningSessionsHook>(version, w, *this);
          }));
      store->set_map_hook(
        resharing_sessions.get_name(),
        resharing_sessions.wrap_map_hook(
          [this](
            kv::Version version, const typename ResharingSessions::Write& w)
            -> kv::ConsensusHookPtr {
            return std::make_unique<ResharingSessionsHook>(version, w, *this);
          }));
      store->set_map_hook(
        current_identity.get_name(),
        current_identity.wrap_map_hook(
          [this](kv::Version version, const typename CurrentIdentity::Write& w)
            -> kv::ConsensusHookPtr {
            return std::make_unique<CurrentIdentityHook>(version, w, *this);
          }));

      static const std::unordered_set<std::string> local_tables = {};
      local_store =
        std::make_shared<kv::Store>(kv::ReplicateType::ALL, local_tables);
    }

    virtual ~CCFSplitIdContext() {}

    using SplitIdentity::Context<ccf::NodeId>::sign;
    using SplitIdentity::Context<ccf::NodeId>::sample;
    using SplitIdentity::Context<ccf::NodeId>::reshare;
    using SplitIdentity::Context<ccf::NodeId>::state;
    using SplitIdentity::Context<ccf::NodeId>::on_sampling_update;
    using SplitIdentity::Context<ccf::NodeId>::on_signing_update;
    using SplitIdentity::Context<ccf::NodeId>::on_resharing_update;

    virtual std::optional<SigningSessionCache> get_local_signing_state(
      uint64_t session_id) const override
    {
      auto tx = local_store->create_read_only_tx();
      auto tbl = tx.ro(local_signing_state);
      return tbl->get(session_id);
    }

    virtual void set_local_signing_state(
      uint64_t session_id,
      const std::optional<SigningSessionCache>& state) override
    {
      auto tx = local_store->create_tx();
      auto tbl = tx.rw(local_signing_state);
      if (state.has_value())
      {
        tbl->put(session_id, state.value());
      }
      else
      {
        tbl->remove(session_id);
      }
      if (tx.commit() != kv::CommitResult::SUCCESS)
      {
        throw std::runtime_error("local tx failed");
      }
    }

    virtual std::optional<ResharingSessionCache> get_local_resharing_state(
      uint64_t session_id) const override
    {
      auto tx = local_store->create_read_only_tx();
      auto tbl = tx.ro(local_resharing_state);
      return tbl->get(session_id);
    }

    virtual void set_local_resharing_state(
      uint64_t session_id,
      const std::optional<ResharingSessionCache>& state) override
    {
      auto tx = local_store->create_tx();
      auto tbl = tx.rw(local_resharing_state);
      if (state.has_value())
      {
        tbl->put(session_id, state.value());
      }
      else
      {
        tbl->remove(session_id);
      }
      if (tx.commit() != kv::CommitResult::SUCCESS)
      {
        throw std::runtime_error("local tx failed");
      }
    }

    virtual std::optional<SamplingSessionCache> get_local_sampling_state(
      uint64_t session_id) const override
    {
      auto tx = local_store->create_read_only_tx();
      auto tbl = tx.ro(local_sampling_state);
      return tbl->get(session_id);
    }

    virtual void set_local_sampling_state(
      uint64_t session_id,
      const std::optional<SamplingSessionCache>& state) override
    {
      auto tx = local_store->create_tx();
      auto tbl = tx.rw(local_sampling_state);
      if (state.has_value())
      {
        tbl->put(session_id, state.value());
      }
      else
      {
        tbl->remove(session_id);
      }
      if (tx.commit() != kv::CommitResult::SUCCESS)
      {
        throw std::runtime_error("local tx failed");
      }
    }

    virtual void on_rollback() override
    {
      std::pair<TxID, kv::Term> txid_term =
        store->current_txid_and_commit_term();
      local_store->rollback(txid_term.first, txid_term.second);

      // We may have rolled back to a state that has in-progress identity
      // sessions, so we need to make sure we trigger the relevant callbacks
      // for these sessions to continue.

      auto tx = store->create_read_only_tx();

      auto signing_tbl = tx.ro(signing_sessions);
      signing_tbl->foreach([this](const auto& id, const auto& session) {
        add_signing_update_task(id, session);
        return true;
      });

      auto sampling_tbl = tx.ro(sampling_sessions);
      sampling_tbl->foreach([this](const auto& id, const auto& session) {
        add_sampling_update_task(id, session);
        return true;
      });

      auto resharing_tbl = tx.ro(resharing_sessions);
      resharing_tbl->foreach([this](const auto& id, const auto& session) {
        add_resharing_update_task(id, session);
        return true;
      });
    }

    virtual void on_compact() override
    {
      local_store->compact(store->compacted_version());
    }

  protected:
    std::shared_ptr<kv::Store> store;
    bool defensive;

    class LocalStore : public kv::Store
    {
    public:
      LocalStore() : kv::Store() {}
      virtual ~LocalStore() {}

      kv::NonSerialisingTx create_tx()
      {
        return kv::NonSerialisingTx(this);
      }
    };

    std::shared_ptr<kv::Store> local_store;

    struct CheckSamplingMsg
    {
      CheckSamplingMsg(
        CCFSplitIdContext& context,
        uint64_t session_id,
        const SamplingSession<ccf::NodeId>& session) :
        context(context),
        session_id(session_id),
        session(session)
      {}

      CCFSplitIdContext& context;
      uint64_t session_id;
      SamplingSession<ccf::NodeId> session;
    };

    void add_sampling_update_task(uint64_t id, auto session)
    {
      auto msg = std::make_unique<threading::Tmsg<CheckSamplingMsg>>(
        [](std::unique_ptr<threading::Tmsg<CheckSamplingMsg>> msg) {
          msg->data.context.on_sampling_update(
            msg->data.session_id, msg->data.session);
        },
        *this,
        id,
        session);
      threading::ThreadMessaging::thread_messaging.add_task_after(
        std::move(msg), std::chrono::milliseconds(0));
    }

    class SamplingSessionsHook : public kv::ConsensusHook
    {
      CCFSplitIdContext& context;
      std::map<uint64_t, SamplingSession<ccf::NodeId>> sessions;

    public:
      SamplingSessionsHook(
        kv::Version version_,
        const typename SamplingSessions::Write& w,
        CCFSplitIdContext& context) :
        context(context)
      {
        for (auto& [id, s] : w)
        {
          if (s.has_value())
            sessions[id] = s.value();
        }
      }

      void call(kv::ConfigurableConsensus* consensus) override
      {
        for (auto& [id, session] : sessions)
        {
          context.add_sampling_update_task(id, session);
        }
      }
    };

    struct CheckSigningMsg
    {
      CheckSigningMsg(
        CCFSplitIdContext& context,
        uint64_t session_id,
        const SigningSession<ccf::NodeId>& session) :
        context(context),
        session_id(session_id),
        session(session)
      {}

      CCFSplitIdContext& context;
      uint64_t session_id;
      SigningSession<ccf::NodeId> session;
    };

    void add_signing_update_task(uint64_t id, auto session)
    {
      auto msg = std::make_unique<threading::Tmsg<CheckSigningMsg>>(
        [](std::unique_ptr<threading::Tmsg<CheckSigningMsg>> msg) {
          msg->data.context.on_signing_update(
            msg->data.session_id, msg->data.session);
        },
        *this,
        id,
        session);
      threading::ThreadMessaging::thread_messaging.add_task_after(
        std::move(msg), std::chrono::milliseconds(0));
    }

    class SigningSessionsHook : public kv::ConsensusHook
    {
      CCFSplitIdContext& context;
      std::map<uint64_t, SigningSession<ccf::NodeId>> sessions;

    public:
      SigningSessionsHook(
        kv::Version version_,
        const typename SigningSessions::Write& w,
        CCFSplitIdContext& context) :
        context(context)
      {
        for (auto& [id, s] : w)
        {
          if (s.has_value())
            sessions[id] = s.value();
        }
      }

      void call(kv::ConfigurableConsensus* consensus) override
      {
        for (auto& [id, session] : sessions)
        {
          context.add_signing_update_task(id, session);
        }
      }
    };

    struct CheckResharingMsg
    {
      CheckResharingMsg(
        CCFSplitIdContext& context,
        uint64_t session_id,
        const ResharingSession<ccf::NodeId>& session) :
        context(context),
        session_id(session_id),
        session(session)
      {}

      CCFSplitIdContext& context;
      uint64_t session_id;
      ResharingSession<ccf::NodeId> session;
    };

    void add_resharing_update_task(uint64_t id, auto session)
    {
      auto msg = std::make_unique<threading::Tmsg<CheckResharingMsg>>(
        [](std::unique_ptr<threading::Tmsg<CheckResharingMsg>> msg) {
          msg->data.context.on_resharing_update(
            msg->data.session_id, msg->data.session);
        },
        *this,
        id,
        session);
      threading::ThreadMessaging::thread_messaging.add_task_after(
        std::move(msg), std::chrono::milliseconds(0));
    }

    class ResharingSessionsHook : public kv::ConsensusHook
    {
      CCFSplitIdContext& context;
      std::map<uint64_t, ResharingSession<ccf::NodeId>> sessions;

    public:
      ResharingSessionsHook(
        kv::Version version_,
        const typename ResharingSessions::Write& w,
        CCFSplitIdContext& context) :
        context(context)
      {
        for (auto& [id, s] : w)
        {
          if (s.has_value())
            sessions[id] = s.value();
        }
      }

      void call(kv::ConfigurableConsensus* consensus) override
      {
        for (auto& [id, session] : sessions)
        {
          context.add_resharing_update_task(id, session);
        }
      }
    };

    class PublicKeysHook : public kv::ConsensusHook
    {
      CCFSplitIdContext& context;
      std::map<ccf::NodeId, std::vector<uint8_t>> to_add;
      std::unordered_set<ccf::NodeId> to_remove;

    public:
      PublicKeysHook(
        kv::Version version_,
        const typename PublicKeys::Write& w,
        CCFSplitIdContext& context) :
        context(context)
      {
        for (auto& [nid, public_key] : w)
        {
          if (public_key.has_value())
            context.state.public_keys[nid] = public_key.value();
          else
            context.state.public_keys.erase(nid);
        }
      }

      void call(kv::ConfigurableConsensus* consensus) override {}
    };

    class CurrentIdentityHook : public kv::ConsensusHook
    {
      CCFSplitIdContext& context;

    public:
      CurrentIdentityHook(
        kv::Version version_,
        const typename CurrentIdentity::Write& w,
        CCFSplitIdContext& context) :
        context(context)
      {
        for (auto& [n, identity] : w)
        {
          LOG_INFO_FMT(
            "SPLITID: split identity established at {}: public key: {} "
            "x_commits: {}",
            version_,
            identity->public_key,
            identity->x_commits);
        }
      }

      void call(kv::ConfigurableConsensus* consensus) override {}
    };
  };
}
