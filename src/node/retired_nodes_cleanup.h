// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/thread_messaging.h"
#include "node_client.h"
#include "tasks/basic_task.h"
#include "tasks/task_system.h"

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
      ::http::Request request(
        fmt::format(
          "/{}/{}",
          ccf::get_actor_prefix(ccf::ActorsType::nodes),
          "network/nodes/set_retired_committed"),
        HTTP_POST);
      request.set_header(http::headers::CONTENT_LENGTH, fmt::format("{}", 0));

      node_client->make_request(request);
    }

    void cleanup()
    {
      ccf::tasks::add_task(ccf::tasks::make_basic_task(
        [this]() { this->send_cleanup_retired_nodes(); }));
    }
  };
}