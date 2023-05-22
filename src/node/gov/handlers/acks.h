// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/base_endpoint_registry.h"

namespace ccf::gov::endpoints
{
  void init_ack_handlers(ccf::BaseEndpointRegistry& registry)
  {
    auto get_state_digest =
      [&](auto& ctx, nlohmann::json&& params, ApiVersion api_version) {
        switch (api_version)
        {
          case ApiVersion::v0_0_1_preview:
          default:
          {
            return make_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              "This is a placeholder");
            break;
          }
        }
      };
    registry
      .make_read_only_endpoint(
        "/members/state-digests/{memberId}",
        HTTP_GET,
        json_read_only_adapter(api_version_adapter(get_state_digest)),
        no_auth_required)
      .install();
  
    auto update_state_digest =
      [&](auto& ctx, nlohmann::json&& params, ApiVersion api_version) {
        switch (api_version)
        {
          case ApiVersion::v0_0_1_preview:
          default:
          {
            return make_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              "This is a placeholder");
            break;
          }
        }
      };
    registry
      .make_endpoint(
        "/members/state-digests/{memberId}:update",
        HTTP_POST,
        json_adapter(api_version_adapter(update_state_digest)),
        no_auth_required)
      .install();
  
    auto ack_state_digest =
      [&](auto& ctx, nlohmann::json&& params, ApiVersion api_version) {
        switch (api_version)
        {
          case ApiVersion::v0_0_1_preview:
          default:
          {
            return make_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              "This is a placeholder");
            break;
          }
        }
      };
    registry
      .make_endpoint(
        "/members/state-digests/{memberId}:ack",
        HTTP_POST,
        json_adapter(api_version_adapter(ack_state_digest)),
        no_auth_required)
      .install();
  }
}