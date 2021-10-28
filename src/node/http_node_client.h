// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "node/node_client.h"
#include "node/rpc/node_call_types.h"
#include "node/rpc/serdes.h"
#include "node/rpc/serialization.h"

#include <chrono>

namespace ccf
{
  class HTTPNodeClient : public NodeClient
  {
  public:
    HTTPNodeClient(
      std::shared_ptr<enclave::RPCMap> rpc_map,
      crypto::KeyPairPtr node_sign_kp,
      const crypto::Pem& self_signed_node_cert_,
      const std::optional<crypto::Pem>& endorsed_node_cert_) :
      NodeClient(
        rpc_map, node_sign_kp, self_signed_node_cert_, endorsed_node_cert_)
    {}

    virtual ~HTTPNodeClient() {}

    inline bool make_request(http::Request& request)
    {
      const auto& node_cert = endorsed_node_cert.has_value() ?
        endorsed_node_cert.value() :
        self_signed_node_cert;
      auto node_cert_der = crypto::cert_pem_to_der(node_cert);
      const auto key_id = crypto::Sha256Hash(node_cert_der).hex_str();

      http::sign_request(request, node_sign_kp, key_id);

      std::vector<uint8_t> packed = request.build_request();

      auto node_session = std::make_shared<enclave::SessionContext>(
        enclave::InvalidSessionId, node_cert.raw());
      auto ctx = enclave::make_rpc_context(node_session, packed);
      ctx->execute_on_node = false;

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
        LOG_FAIL_FMT("Request failed: {}", str);
      }

      return rs == HTTP_STATUS_OK;
    }

    bool submit_orc(const NodeId& from, kv::ReconfigurationId rid) override
    {
      LOG_DEBUG_FMT("Configurations: submit ORC for #{} from {}", rid, from);

      ObservedReconfigurationCommit::In ps = {from, rid};

      http::Request request(fmt::format(
        "/{}/{}", ccf::get_actor_prefix(ccf::ActorsType::nodes), "orc"));
      request.set_header(
        http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);

      auto body = serdes::pack(ps, serdes::Pack::Text);
      request.set_body(&body);
      return make_request(request);
    }

    struct AsyncORCTaskMsg
    {
      AsyncORCTaskMsg(
        HTTPNodeClient* client_,
        const NodeId& from_,
        kv::ReconfigurationId rid_,
        size_t retries_ = SIZE_MAX) :
        client(client_),
        from(from_),
        rid(rid_),
        retries(retries_)
      {}

      HTTPNodeClient* client;
      NodeId from;
      kv::ReconfigurationId rid;
      size_t retries;
    };

    static void orc_cb(std::unique_ptr<threading::Tmsg<AsyncORCTaskMsg>> msg)
    {
      if (!msg->data.client->submit_orc(msg->data.from, msg->data.rid))
      {
        if (--msg->data.retries > 0)
        {
          threading::ThreadMessaging::thread_messaging.add_task_after(
            std::move(msg), std::chrono::milliseconds(250));
        }
        else
        {
          LOG_DEBUG_FMT(
            "Failed request; giving up as there are no more retries left");
        }
      }
    }

    virtual void schedule_submit_orc(
      const NodeId& from, kv::ReconfigurationId rid) override
    {
      auto msg = std::make_unique<threading::Tmsg<AsyncORCTaskMsg>>(
        orc_cb, this, from, rid);

      threading::ThreadMessaging::thread_messaging.add_task_after(
        std::move(msg), std::chrono::milliseconds(0));
    }
  };
}