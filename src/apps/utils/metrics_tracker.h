// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "apps/utils/metrics.h"
#include "ccf/common_auth_policies.h"
#include "ccf/endpoint_registry.h"
#include "ccf/json_handler.h"

namespace metrics
{
  class Tracker
  {
  private:
    metrics::Metrics metrics;

  public:
    ccf::endpoints::CommandEndpointFunction get_endpoint_handler()
    {
      auto get_metrics = [this](auto&, nlohmann::json&&) {
        auto result = metrics.get_metrics_report();
        return ccf::make_success(result);
      };

      return ccf::json_command_adapter(get_metrics);
    }

    void install_endpoint(ccf::endpoints::EndpointRegistry& reg)
    {
      reg
        .make_command_endpoint(
          "metrics", HTTP_GET, get_endpoint_handler(), ccf::no_auth_required)
        .set_auto_schema<void, metrics::Report>()
        .set_execute_outside_consensus(
          ccf::endpoints::ExecuteOutsideConsensus::Locally)
        .install();
    }

    void tick(std::chrono::milliseconds elapsed, size_t tx_count)
    {
      metrics.track_tx_rates(elapsed, tx_count);
    }
  };
}