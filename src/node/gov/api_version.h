// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/http_query.h"
#include "ccf/json_handler.h"

#include <string>

namespace ccf::gov::endpoints
{
  enum class ApiVersion
  {
    preview_v1,
  };

  static constexpr std::pair<ApiVersion, char const*> api_version_strings[] = {
    {ApiVersion::preview_v1, "2023-06-01-preview"}};

  // Extracts api-version from query parameter, and passes this to the given
  // functor. Will return error responses for missing and unknown api-versions.
  // This means handler functors can safely provide a default implementation
  // without validating the given API version, so long as the behaviour is the
  // same for *all* accepted versions.
  template <typename Fn>
  auto api_version_adapter(Fn&& f)
  {
    return [f](auto& ctx) {
      const auto param_name = "api-version";
      const auto parsed_query =
        http::parse_query(ctx.rpc_ctx->get_request_query());
      const auto qit = parsed_query.find(param_name);
      if (qit == parsed_query.end())
      {
        ctx.rpc_ctx->set_error(
          HTTP_STATUS_BAD_REQUEST,
          ccf::errors::MissingApiVersionParameter,
          fmt::format(
            "The api-version query parameter (?{}=) is required for all "
            "requests.",
            param_name));
        return;
      }

      const auto it = std::find_if(
        std::begin(api_version_strings),
        std::end(api_version_strings),
        [&qit](const auto& p) { return p.second == qit->second; });
      if (it == std::end(api_version_strings))
      {
        auto message = fmt::format(
          "Unsupported api-version '{}'. The supported api-versions are: ",
          qit->second);
        auto first = true;
        for (const auto& p : api_version_strings)
        {
          if (first)
          {
            message += p.second;
            first = false;
          }
          else
          {
            message += fmt::format(", {}", p.second);
          }
        }
        ctx.rpc_ctx->set_error(
          HTTP_STATUS_BAD_REQUEST,
          ccf::errors::UnsupportedApiVersionValue,
          std::move(message));
        return;
      }

      const ApiVersion api_version = it->first;
      f(ctx, api_version);
      return;
    };
  }
}