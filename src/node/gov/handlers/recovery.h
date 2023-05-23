// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/base_endpoint_registry.h"

namespace ccf::gov::endpoints
{
  void init_recovery_handlers(ccf::BaseEndpointRegistry& registry)
  {
    auto get_encrypted_share =
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
        "/recovery/encrypted-recovery-shares/{memberId}",
        HTTP_GET,
        json_read_only_adapter(json_api_version_adapter(get_encrypted_share)),
        no_auth_required)
      .install();
  
    auto submit_recovery_share =
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
        "/recovery/members/{memberId}:recover",
        HTTP_POST,
        json_adapter(json_api_version_adapter(submit_recovery_share)),
        no_auth_required)
      .install();
  }
}