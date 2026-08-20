// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/http_query.h"
#include "ccf/json_handler.h"

#include <string>

namespace ccf::gov::endpoints
{
  enum class ApiVersion : uint8_t
  {
    preview_v1,
    MIN = preview_v1,

    v1,

    Latest,
  };

  static constexpr std::pair<ApiVersion, char const*> api_version_strings[] = {
    {ApiVersion::preview_v1, "2023-06-01-preview"},
    {ApiVersion::v1, "2024-07-01"},
    {ApiVersion::Latest, "latest"}};

  enum class MissingApiVersionPolicy : uint8_t
  {
    Reject,
    UseLatest,
  };

  inline bool is_api_version_accepted(
    ApiVersion api_version, ApiVersion min_accepted)
  {
    return api_version == ApiVersion::Latest || api_version >= min_accepted;
  }

  inline std::optional<ApiVersion> get_api_version(
    ccf::endpoints::CommandEndpointContext& ctx,
    ApiVersion min_accepted,
    MissingApiVersionPolicy missing_policy = MissingApiVersionPolicy::Reject)
  {
    std::string accepted_versions_suffix = "The supported api-versions are: ";
    auto first = true;
    for (const auto& p : api_version_strings)
    {
      if (!is_api_version_accepted(p.first, min_accepted))
      {
        continue;
      }

      if (first)
      {
        accepted_versions_suffix += p.second;
        first = false;
      }
      else
      {
        accepted_versions_suffix += fmt::format(", {}", p.second);
      }
    }

    const auto* const param_name = "api-version";
    const auto parsed_query =
      http::parse_query(ctx.rpc_ctx->get_request_query());
    const auto qit = parsed_query.find(param_name);
    if (qit == parsed_query.end())
    {
      if (missing_policy == MissingApiVersionPolicy::UseLatest)
      {
        return ApiVersion::Latest;
      }

      ctx.rpc_ctx->set_error(
        HTTP_STATUS_BAD_REQUEST,
        ccf::errors::MissingApiVersionParameter,
        fmt::format(
          "The api-version query parameter (?{}=) is required for this "
          "request. {}",
          param_name,
          accepted_versions_suffix));
      return std::nullopt;
    }

    const auto* const it = std::find_if(
      std::begin(api_version_strings),
      std::end(api_version_strings),
      [&qit](const auto& p) { return p.second == qit->second; });
    if (
      it == std::end(api_version_strings) ||
      !is_api_version_accepted(it->first, min_accepted))
    {
      auto message = fmt::format(
        "Unsupported api-version '{}'. {}",
        qit->second,
        accepted_versions_suffix);
      ctx.rpc_ctx->set_error(
        HTTP_STATUS_BAD_REQUEST,
        ccf::errors::UnsupportedApiVersionValue,
        std::move(message));
      return std::nullopt;
    }

    return it->first;
  }

  // Extracts api-version from the query parameter, using Latest when it is
  // omitted, and passes this to the given functor. Unknown api-versions produce
  // an error response.
  template <typename Fn>
  auto api_version_adapter(
    Fn&& f,
    ApiVersion min_accepted = ApiVersion::MIN,
    MissingApiVersionPolicy missing_policy = MissingApiVersionPolicy::UseLatest)
  {
    return [f = std::forward<Fn>(f), min_accepted, missing_policy](auto& ctx) {
      const auto api_version =
        get_api_version(ctx, min_accepted, missing_policy);
      if (api_version.has_value())
      {
        f(ctx, api_version.value());
      }

      return;
    };
  }
}