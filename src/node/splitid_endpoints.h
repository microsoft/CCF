// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/endpoint_context.h"
#include "ds/json.h"
#include "http/http_status.h"
#include "node/entities.h"
#include "node/network_state.h"
#include "node/rpc/error.h"
#include "node/rpc/frontend.h"
#include "node/splitid_context.h"

#include <ccf/common_auth_policies.h>
#include <ccf/common_endpoint_registry.h>
#include <ccf/endpoint.h>
#include <ccf/endpoint_registry.h>
#include <ccf/entity_id.h>
#include <ccf/json_handler.h>
#include <map>
#include <memory>
#include <splitid/splitid.h>
#include <stdexcept>
#include <string>
#include <vector>

namespace ccf
{
  template <typename T>
  class SessionTx
  {
  public:
    SessionTx(
      endpoints::EndpointContext& ectx,
      uint64_t session_id,
      ServiceMap<size_t, T>& map) :
      ectx(ectx),
      session_id(session_id)
    {
      const auto& cert_auth_ident =
        ectx.template get_caller<ccf::NodeCertAuthnIdentity>();
      from = cert_auth_ident.node_id;
      tx = ectx.tx.rw(map);
      session = tx->get(session_id);
    }

    ~SessionTx() {}

    void put()
    {
      if (session.has_value())
      {
        tx->put(session_id, session.value());
      }
    }

    endpoints::EndpointContext& ectx;
    typename ServiceMap<size_t, T>::Handle* tx;
    uint64_t session_id;
    NodeId from;
    std::optional<T> session;
  };

  inline std::shared_ptr<SplitIdContext> get_splitid_ctx(
    ccfapp::AbstractNodeContext& context)
  {
    auto ctx = context.get_node_state().get_identity_context();

    if (!ctx)
    {
      throw std::logic_error("no identity context");
    }

    return ctx;
  }

  inline void install_splitid_endpoint_handlers(
    ccf::CommonEndpointRegistry* endpoints,
    ccfapp::AbstractNodeContext& context,
    ccf::NetworkState& network)
  {
    auto splitid_register =
      [&context](auto& args, const nlohmann::json& params) {
        try
        {
          const auto in = params.get<RegisterRPC::In>();
          auto tx = args.tx.rw(get_splitid_ctx(context)->public_keys);
          auto x = tx->get(in.node_id);
          if (x.has_value())
          {
            // Node is already registered
            if (x == in.public_key)
            {
              make_success(true);
            }
            else
            {
              return make_error(
                HTTP_STATUS_BAD_REQUEST,
                ccf::errors::InternalError,
                "Node cannot change public key");
            }
          }
          tx->put(in.node_id, in.public_key);
          return make_success(true);
        }
        catch (std::exception& ex)
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST, ccf::errors::InternalError, ex.what());
        }
      };

    endpoints
      ->make_endpoint(
        "splitid/register",
        HTTP_POST,
        json_adapter(splitid_register),
        {std::make_shared<NodeCertAuthnPolicy>()})
      .set_forwarding_required(endpoints::ForwardingRequired::Always)
      .install();

    auto splitid_sample = [&context](auto& args, const nlohmann::json& params) {
      try
      {
        const auto in = params.get<SampleRPC::In>();

        if (in.config.size() < 3)
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InternalError,
            "Configuration too small, need at least 3 nodes for split "
            "identity");
        }

        auto ctx = get_splitid_ctx(context);
        auto rss = args.tx.rw(ctx->sampling_sessions);
        if (rss->size() != 0)
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InternalError,
            "Another sampling session is in progress");
        }

        auto ci = args.tx.ro(ctx->current_identity);
        if (ci->size() != 0)
        {
          return make_success(SampleRPC::Out({0, true}));
        }

        for (auto& nid : in.config)
        {
          if (!ctx->have_public_key(nid))
          {
            return make_error(
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::InternalError,
              fmt::format("Public key of {} unknown", nid));
          }
        }

        LOG_DEBUG_FMT(
          "SPLITID: new sampling session config: {} ",
          fmt::join(in.config, ", "));

        SamplingSession ns(in.config, in.defensive, in.app_id);
        auto vals = args.tx.template rw<SplitIdContext::IDs>(ctx->ids);
        auto id =
          ctx->get_next_id(vals, SplitIdContext::IdIndex::NEXT_SAMPLING_ID);
        auto sss = args.tx.rw(ctx->sampling_sessions);
        sss->put(id, ns);
        return make_success(SampleRPC::Out({id, false}));
      }
      catch (std::exception& ex)
      {
        return make_error(
          HTTP_STATUS_BAD_REQUEST, ccf::errors::InternalError, ex.what());
      }
    };

    endpoints
      ->make_endpoint(
        "splitid/sample",
        HTTP_POST,
        json_adapter(splitid_sample),
        {std::make_shared<NodeCertAuthnPolicy>()})
      .set_forwarding_required(endpoints::ForwardingRequired::Always)
      .install();

    auto splitid_reshare =
      [&context](auto& args, const nlohmann::json& params) {
        try
        {
          const auto in = params.get<ReshareRPC::In>();

          auto rtracker = context.get_node_state().get_resharing_tracker();

          if (!rtracker)
          {
            return make_error(
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::InternalError,
              "No resharing tracker");
          }

          auto ctx = get_splitid_ctx(context);
          const auto& config = rtracker->active_config();

          LOG_DEBUG_FMT("SPLITID: reshare request for [{}]", in.app_id, config);

          if (config.nodes.size() < 3)
          {
            return make_error(
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::InternalError,
              "Configuration too small, need at least 3 nodes for split "
              "identity");
          }

          auto rss = args.tx.rw(ctx->resharing_sessions);
          auto sss = args.tx.rw(ctx->sampling_sessions);
          if (rss->size() != 0 || sss->size() != 0)
          {
            return make_error(
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::InternalError,
              "Another sampling or resharing session is in progress");
          }

          if (in.identity.x_commits.empty())
          {
            throw std::logic_error(
              "cannot reshare without x_commits; finish a sampling session "
              "first");
          }

          for (auto& nid : in.next_config)
          {
            if (!ctx->have_public_key(nid))
            {
              return make_error(
                HTTP_STATUS_BAD_REQUEST,
                ccf::errors::InternalError,
                fmt::format("Public key of {} unknown", nid));
            }
          }

          LOG_DEBUG_FMT(
            "SPLITID: new resharing session identity.x_commits: {} "
            "config: {} next_config: {}",
            in.identity.x_commits,
            config,
            fmt::join(in.next_config, ", "));

          ResharingSession s(
            in.identity,
            config.to_vector(),
            in.next_config,
            in.defensive,
            in.app_id);
          auto vals = args.tx.template rw<SplitIdContext::IDs>(ctx->ids);
          auto id =
            ctx->get_next_id(vals, SplitIdContext::IdIndex::NEXT_RESHARING_ID);
          rss->put(id, s);
          return make_success(ReshareRPC::Out({id}));
        }
        catch (std::exception& ex)
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST, ccf::errors::InternalError, ex.what());
        }
      };

    endpoints
      ->make_endpoint(
        "splitid/reshare",
        HTTP_POST,
        json_adapter(splitid_reshare),
        {std::make_shared<NodeCertAuthnPolicy>()})
      .set_forwarding_required(endpoints::ForwardingRequired::Always)
      .install();

    auto splitid_sign = [&context](auto& args, const nlohmann::json& params) {
      try
      {
        const auto in = params.get<SignRPC::In>();

        auto rtracker = context.get_node_state().get_resharing_tracker();

        if (!rtracker)
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST,
            ccf::errors::InternalError,
            "No resharing tracker");
        }

        auto ctx = get_splitid_ctx(context);

        SignRPC::Out r;

        if (!args.tx.ro(ctx->current_identity)->get(0).has_value())
        {
          throw std::runtime_error("no split identity available (yet)");
        }

        auto rss = args.tx.rw(ctx->resharing_sessions);
        auto sss = args.tx.rw(ctx->sampling_sessions);
        if (rss->size() != 0 || sss->size() != 0)
        {
          return make_error(
            HTTP_STATUS_SERVICE_UNAVAILABLE,
            ccf::errors::InternalError,
            "A sampling or resharing session is in progress");
        }

        SigningSession<ccf::NodeId> ns(
          rtracker->active_config().to_vector(),
          in.message,
          in.defensive,
          in.app_id);
        auto vals = args.tx.template rw<SplitIdContext::IDs>(ctx->ids);
        auto id =
          ctx->get_next_id(vals, SplitIdContext::IdIndex::NEXT_SIGNING_ID);
        auto signing_session = args.tx.rw(ctx->signing_sessions);
        signing_session->put(id, ns);
        return make_success(SignRPC::Out({id}));
      }
      catch (std::exception& ex)
      {
        return make_error(
          HTTP_STATUS_BAD_REQUEST, ccf::errors::InternalError, ex.what());
      }
    };

    endpoints
      ->make_endpoint(
        "splitid/sign", HTTP_POST, json_adapter(splitid_sign), no_auth_required)
      .set_forwarding_required(endpoints::ForwardingRequired::Always)
      .install();

    auto splitid_get_sig = [&context](
                             auto& args, const nlohmann::json& params) {
      try
      {
        const auto in = params.get<GetSigRPC::In>();

        auto tx = args.tx.rw(get_splitid_ctx(context)->signing_sessions);
        auto s = tx->get(in.session_id);
        if (!s.has_value())
        {
          throw std::logic_error("No such session.");
        }
        auto& session = s.value();
        if (session.signature.empty())
        {
          return make_error(
            HTTP_STATUS_NOT_FOUND,
            ccf::errors::ResourceNotFound,
            fmt::format(
              "Signature for session #{} not available (yet).", in.session_id));
        }
        else
        {
          tx->remove(in.session_id);
          return make_success(GetSigRPC::Out({session.signature}));
        }
      }
      catch (std::exception& ex)
      {
        return make_error(
          HTTP_STATUS_BAD_REQUEST, ccf::errors::InternalError, ex.what());
      }
    };

    endpoints
      ->make_endpoint(
        "splitid/get-signature",
        HTTP_POST,
        json_adapter(splitid_get_sig),
        no_auth_required)
      .set_forwarding_required(endpoints::ForwardingRequired::Always)
      .install();

    auto splitid_update_identity =
      [&context, &network](auto& args, const nlohmann::json& params) {
        try
        {
          const auto in = params.get<UpdateIdentityRPC::In>();
          LOG_DEBUG_FMT(
            "SPLITID: update-identity for sampling session #{}", in.session_id);

          auto cid = args.tx.rw(get_splitid_ctx(context)->current_identity);
          cid->put(0, in.payload);

          auto ctx = context.get_node_state().get_identity_context();
          auto rss = args.tx.rw(ctx->sampling_sessions);
          auto session = rss->get(in.session_id);

          if (!session.has_value())
          {
            return make_error(
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::InternalError,
              "No such session");
          }

          LOG_DEBUG_FMT("SPLITID: update_identity app_id={}", session->app_id);

          ResharingResult rr;
          rr.seqno = 0;
          rr.reconfiguration_id = session->app_id;
          rr.splitid_session_id = in.session_id;
          auto resharings = args.tx.rw(network.resharings);
          resharings->put(rr.reconfiguration_id, rr);

          rss->remove(in.session_id);

          return make_success(true);
        }
        catch (std::exception& ex)
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST, ccf::errors::InternalError, ex.what());
        }
      };

    endpoints
      ->make_endpoint(
        "splitid/update-identity",
        HTTP_POST,
        json_adapter(splitid_update_identity),
        {std::make_shared<NodeCertAuthnPolicy>()})
      .set_forwarding_required(endpoints::ForwardingRequired::Always)
      .install();

    auto get_identity = [&context](auto& args, const nlohmann::json& params) {
      try
      {
        auto ctx = get_splitid_ctx(context);

        if (!ctx)
        {
          return make_error(
            HTTP_STATUS_NOT_FOUND,
            ccf::errors::InternalError,
            "No split identity context");
        }

        auto rss = args.tx.rw(ctx->resharing_sessions);
        auto sss = args.tx.rw(ctx->sampling_sessions);
        if (rss->size() != 0 || sss->size() != 0)
        {
          return make_error(
            HTTP_STATUS_SERVICE_UNAVAILABLE,
            ccf::errors::InternalError,
            "A sampling or resharing session is in progress");
        }

        CurrentIdRPC::Out out;
        auto cid = args.tx.ro(ctx->current_identity);
        auto r = cid->get(0);
        if (!r.has_value())
        {
          return make_error(
            HTTP_STATUS_SERVICE_UNAVAILABLE,
            ccf::errors::ResourceNotFound,
            "no identity available yet");
        }
        else
        {
          out.pem = EC::Point(r.value().public_key).to_public_pem();
          return make_success(out);
        }
      }
      catch (std::exception& ex)
      {
        return make_error(
          HTTP_STATUS_BAD_REQUEST, ccf::errors::InternalError, ex.what());
      }
    };

    endpoints
      ->make_endpoint(
        "splitid/get-identity",
        HTTP_POST,
        json_adapter(get_identity),
        no_auth_required)
      .install();

#define SPLITID_INTERNAL_ENDPOINT(URL, T, ST, TBL, F) \
  auto T##_endpoint_fun = \
    [&context](auto& args, const nlohmann::json& params) { \
      try \
      { \
        const auto in = params.get<T::In>(); \
        SessionTx<ST> stx(args, in.session_id, TBL); \
        if (!stx.session.has_value()) \
        { \
          return make_success(false); /* OK, ignore, don't retry */ \
        } \
        stx.session->F(stx.from, in.payload); \
        stx.put(); \
        return make_success(true); \
      } \
      catch (std::exception & ex) \
      { \
        return make_error( \
          HTTP_STATUS_BAD_REQUEST, ccf::errors::InternalError, ex.what()); \
      } \
    }; \
  endpoints \
    ->make_endpoint( \
      URL, \
      HTTP_POST, \
      json_adapter(T##_endpoint_fun), \
      {std::make_shared<NodeCertAuthnPolicy>()}) \
    .set_forwarding_required(endpoints::ForwardingRequired::Always) \
    .install();

    SPLITID_INTERNAL_ENDPOINT(
      "splitid/sampling/deal",
      SamplingDealRPC,
      SamplingSession<ccf::NodeId>,
      get_splitid_ctx(context)->sampling_sessions,
      add_deal);
    SPLITID_INTERNAL_ENDPOINT(
      "splitid/sampling/resharing",
      SamplingReshareRPC,
      SamplingSession<ccf::NodeId>,
      get_splitid_ctx(context)->sampling_sessions,
      add_resharing);
    SPLITID_INTERNAL_ENDPOINT(
      "splitid/sampling/open_key",
      OpenKeyRPC,
      SamplingSession<ccf::NodeId>,
      get_splitid_ctx(context)->sampling_sessions,
      add_open_key);

    SPLITID_INTERNAL_ENDPOINT(
      "splitid/signing/deal",
      SigningDealRPC,
      SigningSession<ccf::NodeId>,
      get_splitid_ctx(context)->signing_sessions,
      add_deal);
    SPLITID_INTERNAL_ENDPOINT(
      "splitid/signing/openk",
      OpenKRPC,
      SigningSession<ccf::NodeId>,
      get_splitid_ctx(context)->signing_sessions,
      add_openk);
    SPLITID_INTERNAL_ENDPOINT(
      "splitid/signing/signature_share",
      SignatureShareRPC,
      SigningSession<ccf::NodeId>,
      get_splitid_ctx(context)->signing_sessions,
      add_signature_share);
    SPLITID_INTERNAL_ENDPOINT(
      "splitid/signing/signature",
      SignatureRPC,
      SigningSession<ccf::NodeId>,
      get_splitid_ctx(context)->signing_sessions,
      add_signature);

    SPLITID_INTERNAL_ENDPOINT(
      "splitid/resharing/deal",
      ResharingDealRPC,
      ResharingSession<ccf::NodeId>,
      get_splitid_ctx(context)->resharing_sessions,
      add_deal);
    SPLITID_INTERNAL_ENDPOINT(
      "splitid/resharing/reshare",
      ResharingReshareRPC,
      ResharingSession<ccf::NodeId>,
      get_splitid_ctx(context)->resharing_sessions,
      add_resharing);

    auto complete_resharing =
      [&context, &network](auto& args, const nlohmann::json& params) {
        try
        {
          const auto in = params.get<CompleteResharingRPC::In>();

          auto ctx = context.get_node_state().get_identity_context();
          auto rss = args.tx.rw(ctx->resharing_sessions);
          auto session = rss->get(in.session_id);

          if (!session.has_value())
          {
            return make_error(
              HTTP_STATUS_BAD_REQUEST,
              ccf::errors::InternalError,
              "No such session");
          }

          ResharingResult rr;
          rr.seqno = 0;
          rr.reconfiguration_id = session->app_id;
          rr.splitid_session_id = in.session_id;
          auto resharings = args.tx.rw(network.resharings);
          resharings->put(rr.reconfiguration_id, rr);

          rss->remove(in.session_id);

          return make_success(true);
        }
        catch (std::exception& ex)
        {
          return make_error(
            HTTP_STATUS_BAD_REQUEST, ccf::errors::InternalError, ex.what());
        }
      };

    endpoints
      ->make_endpoint(
        "splitid/resharing/complete",
        HTTP_POST,
        json_adapter(complete_resharing),
        no_auth_required)
      .install();
  }
}