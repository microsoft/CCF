// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/tx_id.h"
#include "http/http_builder.h"
#include "http/http_rpc_context.h"
#include "kv/kv_types.h"
#include "node/rpc/node_frontend.h"
#include "node/rpc/serdes.h"

#include <mutex>

namespace ccf
{
  class RetiredNodeCleanup
  {
  private:
    std::shared_ptr<enclave::RPCMap> rpc_map;
    crypto::KeyPairPtr node_sign_kp;
    crypto::Pem node_cert;

  public:
    RetiredNodeCleanup(
      const std::shared_ptr<enclave::RPCMap>& rpc_map,
      const crypto::KeyPairPtr& node_sign_kp,
      const crypto::Pem& node_cert) :
      rpc_map(rpc_map),
      node_sign_kp(node_sign_kp),
      node_cert(node_cert)
    {}

    void send_cleanup_retired_nodes()
    {
      http::Request request(fmt::format(
        "/{}/{}",
        ccf::get_actor_prefix(ccf::ActorsType::nodes),
        "network/nodes/cleanup"));

      auto node_cert_der = crypto::cert_pem_to_der(node_cert);
      const auto key_id = crypto::Sha256Hash(node_cert_der).hex_str();
      request.set_header(http::headers::CONTENT_LENGTH, "0");
      http::sign_request(request, node_sign_kp, key_id);
      auto packed = request.build_request();

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
      auto& frontend = frontend_opt.value();
      frontend->process(ctx);

      if (!http::status_success(ctx->get_response_status()))
      {
        LOG_FAIL_FMT(
          "Could not execute retired node cleanup: {}",
          ctx->get_response_status());
      }
    }

    struct RetiredNodeCleanupMsg
    {
      RetiredNodeCleanupMsg(RetiredNodeCleanup& self_) : self(self_) {}

      RetiredNodeCleanup& self;
    };

    void cleanup()
    {
      auto cleanup_msg =
        std::make_unique<threading::Tmsg<RetiredNodeCleanupMsg>>(
          [](std::unique_ptr<threading::Tmsg<RetiredNodeCleanupMsg>> msg) {
            msg->data.self.send_cleanup_retired_nodes();
          },
          *this);

      threading::ThreadMessaging::thread_messaging.add_task(
        threading::get_current_thread_id(), std::move(cleanup_msg));
    }
  };
}