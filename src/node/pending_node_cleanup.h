// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv/kv_types.h"
#include "node/node_client.h"
#include "tasks/basic_task.h"
#include "tasks/task_system.h"

#include <algorithm>
#include <chrono>
#include <memory>

namespace ccf
{
  class PendingNodeCleanup
    : public std::enable_shared_from_this<PendingNodeCleanup>
  {
  private:
    static constexpr auto max_cleanup_interval = std::chrono::minutes(1);

    std::shared_ptr<NodeClient> node_client;
    std::shared_ptr<ccf::kv::Consensus> consensus;
    std::chrono::milliseconds cleanup_interval;
    ccf::tasks::Task periodic_cleanup_task;

    void send_cleanup_request()
    {
      ::http::Request request(
        fmt::format(
          "/{}/{}",
          ccf::get_actor_prefix(ccf::ActorsType::nodes),
          "network/nodes/remove_expired_pending"),
        HTTP_POST);
      request.set_header(http::headers::CONTENT_LENGTH, "0");

      node_client->make_request(request);
    }

  public:
    PendingNodeCleanup(
      std::shared_ptr<NodeClient> node_client_,
      std::shared_ptr<ccf::kv::Consensus> consensus_,
      std::chrono::milliseconds pending_node_timeout) :
      node_client(std::move(node_client_)),
      consensus(std::move(consensus_)),
      cleanup_interval(std::min(
        pending_node_timeout,
        std::chrono::duration_cast<std::chrono::milliseconds>(
          max_cleanup_interval)))
    {}

    ~PendingNodeCleanup()
    {
      stop();
    }

    void start()
    {
      if (cleanup_interval <= std::chrono::milliseconds::zero())
      {
        return;
      }

      const auto self = weak_from_this();
      periodic_cleanup_task = ccf::tasks::make_basic_task([self]() {
        const auto self_sp = self.lock();
        if (self_sp == nullptr)
        {
          return;
        }

        if (self_sp->consensus->can_replicate())
        {
          self_sp->send_cleanup_request();
        }
      });

      ccf::tasks::add_periodic_task(
        periodic_cleanup_task, cleanup_interval, cleanup_interval);
    }

    void stop()
    {
      if (periodic_cleanup_task != nullptr)
      {
        periodic_cleanup_task->cancel_task();
        periodic_cleanup_task = nullptr;
      }
    }
  };
}
