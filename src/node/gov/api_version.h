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
    v0_0_1_preview,
  };

  static constexpr std::pair<ApiVersion, char const*> api_version_strings[] = {
    {ApiVersion::v0_0_1_preview, "0.0.1-preview"}};

  // Extracts api-version from query parameter, and passes this to the given
  // functor. Will return error responses for missing and unknown api-versions.
  // This means handler functors can safely provide a default implementation
  // without validating the given API version, if the behaviour is the same for
  // all accepted versions.
  template <typename Fn>
  auto api_version_adapter(Fn&& f)
  {
    static std::string supported_suffix;
    if (supported_suffix.empty())
    {
      supported_suffix = "Supported versions are:";
      for (const auto& [_, s] : api_version_strings)
      {
        supported_suffix += fmt::format("\n  {}", s);
      }
    }

    return [f](auto& ctx, nlohmann::json&& body) {
      const auto param_name = "api-version";
      const auto parsed_query =
        http::parse_query(ctx.rpc_ctx->get_request_query());
      const auto qit = parsed_query.find(param_name);
      if (qit == parsed_query.end())
      {
        return make_error(
          HTTP_STATUS_BAD_REQUEST,
          ccf::errors::InvalidQueryParameterValue,
          fmt::format(
            "Missing required query parameter '{}'. {}",
            param_name,
            supported_suffix));
      }

      const auto it = std::find_if(
        std::begin(api_version_strings),
        std::end(api_version_strings),
        [&qit](const auto& p) { return p.second == qit->second; });
      if (it == std::end(api_version_strings))
      {
        return make_error(
          HTTP_STATUS_BAD_REQUEST,
          ccf::errors::InvalidQueryParameterValue,
          fmt::format(
            "Invalid value for query parameter '{}' - '{}' is not recognised "
            "as a valid API version. {}",
            param_name,
            qit->second,
            supported_suffix));
      }

      const ApiVersion api_version = it->first;
      return f(ctx, std::move(body), api_version);
    };
  }
}