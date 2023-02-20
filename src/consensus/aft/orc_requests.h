// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/serdes.h"
#include "ds/thread_messaging.h"
#include "kv/kv_types.h"
#include "node/node_client.h"
#include "node/rpc/rpc_context_impl.h"

#include <chrono>

namespace ccf
{
  size_t constexpr ORC_RPC_RETRY_INTERVAL_MS = 250;

  struct ObservedReconfigurationCommit
  {
    struct In
    {
      ccf::NodeId from;
      kv::ReconfigurationId reconfiguration_id;
    };

    using Out = void;
  };

  DECLARE_JSON_TYPE(ObservedReconfigurationCommit::In)
  DECLARE_JSON_REQUIRED_FIELDS(
    ObservedReconfigurationCommit::In, from, reconfiguration_id)

  inline void submit_orc(
    std::shared_ptr<ccf::NodeClient> client,
    const ccf::NodeId& from,
    kv::ReconfigurationId rid,
    ccf::RpcHandler::DoneCB&& done_cb)
  {
    LOG_DEBUG_FMT("Configurations: submit ORC for #{} from {}", rid, from);

    ObservedReconfigurationCommit::In ps = {from, rid};

    http::Request request(fmt::format(
      "/{}/{}", ccf::get_actor_prefix(ccf::ActorsType::nodes), "orc"));
    request.set_header(
      http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);

    auto body = serdes::pack(ps, serdes::Pack::Text);
    request.set_body(&body);
    client->make_request_async(request, std::move(done_cb));
  }

  struct AsyncORCTaskMsg
  {
    AsyncORCTaskMsg(
      std::shared_ptr<ccf::NodeClient> client_,
      const ccf::NodeId& from_,
      kv::ReconfigurationId rid_) :
      client(client_),
      from(from_),
      rid(rid_)
    {}

    std::shared_ptr<ccf::NodeClient> client;
    ccf::NodeId from;
    kv::ReconfigurationId rid;
  };

  inline void orc_cb(std::unique_ptr<threading::Tmsg<AsyncORCTaskMsg>> msg)
  {
    if (!submit_orc(msg->data.client, msg->data.from, msg->data.rid))
    {
      threading::ThreadMessaging::instance().add_task_after(
        std::move(msg), std::chrono::milliseconds(ORC_RPC_RETRY_INTERVAL_MS));
    }
  }

  inline void schedule_submit_orc(
    std::shared_ptr<ccf::NodeClient> client,
    const ccf::NodeId& from,
    kv::ReconfigurationId rid,
    std::chrono::milliseconds delay = std::chrono::milliseconds(0))
  {
    auto msg = std::make_unique<threading::Tmsg<AsyncORCTaskMsg>>(
      orc_cb, client, from, rid);

    threading::ThreadMessaging::instance().add_task_after(
      std::move(msg), delay);
  }
}
