// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/thread_messaging.h"
#include "node_client.h"

namespace ccf
{
  class RetiredNodeCleanup
  {
  private:
    std::shared_ptr<NodeClient> node_client;

  public:
    RetiredNodeCleanup(const std::shared_ptr<NodeClient>& node_client_) :
      node_client(node_client_)
    {}

    void send_cleanup_retired_nodes()
    {
      http::Request request(
        fmt::format(
          "/{}/{}",
          ccf::get_actor_prefix(ccf::ActorsType::nodes),
          "network/nodes/set_retired_committed"),
        HTTP_POST);
      request.set_header(http::headers::CONTENT_LENGTH, fmt::format("{}", 0));

      node_client->make_request_async(request, [](auto&& done_ctx) {
        // fire-and-forget, no error handling or reaction on the response
      });
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