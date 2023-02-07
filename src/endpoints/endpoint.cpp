// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/endpoint.h"

namespace ccf::endpoints
{
  Endpoint& Endpoint::set_openapi_hidden(bool hidden)
  {
    openapi_hidden = hidden;
    return *this;
  }

  Endpoint& Endpoint::set_params_schema(const nlohmann::json& j)
  {
    params_schema = j;

    schema_builders.push_back(
      [](nlohmann::json& document, const Endpoint& endpoint) {
        const auto http_verb = endpoint.dispatch.verb.get_http_method();
        if (!http_verb.has_value())
        {
          return;
        }

        using namespace ds::openapi;

        auto& rb = request_body(path_operation(
          ds::openapi::path(document, endpoint.full_uri_path),
          http_verb.value()));
        schema(media_type(rb, http::headervalues::contenttype::JSON)) =
          endpoint.params_schema;
      });

    return *this;
  }

  Endpoint& Endpoint::set_result_schema(
    const nlohmann::json& j, std::optional<http_status> status)
  {
    result_schema = j;
    success_status = status.value_or(HTTP_STATUS_OK);

    schema_builders.push_back(
      [j](nlohmann::json& document, const Endpoint& endpoint) {
        const auto http_verb = endpoint.dispatch.verb.get_http_method();
        if (!http_verb.has_value())
        {
          return;
        }

        using namespace ds::openapi;
        auto& r = response(
          path_operation(
            ds::openapi::path(document, endpoint.full_uri_path),
            http_verb.value()),
          endpoint.success_status);

        schema(media_type(r, http::headervalues::contenttype::JSON)) =
          endpoint.result_schema;
      });

    return *this;
  }

  Endpoint& Endpoint::set_forwarding_required(endpoints::ForwardingRequired fr)
  {
    properties.forwarding_required = fr;
    return *this;
  }

  Endpoint& Endpoint::set_openapi_description(const std::string& description)
  {
    openapi_description = description;
    return *this;
  }

  Endpoint& Endpoint::set_openapi_summary(const std::string& summary)
  {
    openapi_summary = summary;
    return *this;
  }

  Endpoint& Endpoint::set_openapi_deprecated(bool is_deprecated)
  {
    openapi_deprecated = is_deprecated;
    return *this;
  }

  void Endpoint::install()
  {
    if (installer == nullptr)
    {
      LOG_FATAL_FMT(
        "Can't install this endpoint ({}) - it is not associated with an "
        "installer",
        full_uri_path);
    }
    else
    {
      installer->install(*this);
    }
  }
}
