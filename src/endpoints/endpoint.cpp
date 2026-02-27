// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/endpoint.h"

#include "ds/internal_logger.h"

namespace ccf::endpoints
{
  Endpoint& Endpoint::set_openapi_hidden(bool hidden)
  {
    openapi_hidden = hidden;
    return *this;
  }

  Endpoint& Endpoint::require_operator_feature(OperatorFeature feature)
  {
    required_operator_features.insert(feature);
    return *this;
  }

  Endpoint& Endpoint::set_params_schema(const nlohmann::json& j)
  {
    params_schema = j;

    schema_builders.emplace_back(
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

    schema_builders.emplace_back(
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

    // NB: Should really only override redirection_strategy if it was previously
    // implicit, not if it was set explicitly!
    switch (properties.forwarding_required)
    {
      case endpoints::ForwardingRequired::Never:
        properties.redirection_strategy = RedirectionStrategy::None;
        break;
      case endpoints::ForwardingRequired::Sometimes:
      case endpoints::ForwardingRequired::Always:
        properties.redirection_strategy = RedirectionStrategy::ToPrimary;
        break;
    }
    return *this;
  }

  Endpoint& Endpoint::set_redirection_strategy(RedirectionStrategy rs)
  {
    properties.redirection_strategy = rs;
    return *this;
  }

  Endpoint& Endpoint::set_locally_committed_function(
    const LocallyCommittedEndpointFunction& lcf)
  {
    locally_committed_func = lcf;
    return *this;
  }

  Endpoint& Endpoint::set_consensus_committed_function(
    const ConsensusCommittedEndpointFunction& ccf_)
  {
    consensus_committed_func = ccf_;
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

  Endpoint& Endpoint::set_openapi_deprecated_replaced(
    const std::string& deprecation_version, const std::string& replacement)
  {
    openapi_deprecated = true;
    openapi_description = fmt::format(
      "This endpoint is deprecated from {}. It is replaced by {}",
      deprecation_version,
      replacement);
    return *this;
  }

  void Endpoint::install()
  {
    if (installer == nullptr)
    {
      auto msg = fmt::format(
        "Can't install this endpoint ({}) - it is not associated with an "
        "installer",
        full_uri_path);
      LOG_FATAL_FMT("{}", msg);
      throw std::logic_error(msg);
    }
    installer->install(*this);
  }

  void to_json(nlohmann::json& j, const InterpreterReusePolicy& grp)
  {
    switch (grp.kind)
    {
      case InterpreterReusePolicy::Kind::KeyBased:
      {
        j = nlohmann::json::object();
        j["key"] = grp.key;
      }
    }
  }

  void from_json(const nlohmann::json& j, InterpreterReusePolicy& grp)
  {
    if (j.is_object())
    {
      const auto key_it = j.find("key");
      if (key_it != j.end())
      {
        grp.kind = InterpreterReusePolicy::Kind::KeyBased;
        grp.key = key_it->get<std::string>();
      }
    }
  }

  std::string schema_name(const InterpreterReusePolicy* policy)
  {
    (void)policy;
    return "InterpreterReusePolicy";
  }

  void fill_json_schema(
    nlohmann::json& schema, const InterpreterReusePolicy* policy)
  {
    (void)policy;
    auto one_of = nlohmann::json::array();

    {
      auto key_based = nlohmann::json::object();
      key_based["type"] = "object";

      key_based["properties"] =
        nlohmann::json::object({{"key", {{"type", "string"}}}});
      key_based["required"] = nlohmann::json::array({"key"});

      one_of.push_back(key_based);
    }

    schema = nlohmann::json::object();
    schema["oneOf"] = one_of;
  }
}
