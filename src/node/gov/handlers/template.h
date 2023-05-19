// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/base_endpoint_registry.h"

// TODO: Remove this
namespace ccf::gov::endpoints
{
  void init_foo_handlers(ccf::BaseEndpointRegistry& registry)
  {
    auto foo = [&](auto& ctx, nlohmann::json&& params, ApiVersion api_version) {
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
        "/foo",
        HTTP_GET,
        json_adapter(api_version_adapter(foo)),
        no_auth_required)
      .install();
  }
}