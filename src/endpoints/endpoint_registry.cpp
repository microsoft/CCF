// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/endpoint_registry.h"

namespace ccf::endpoints
{
  namespace
  {
    void add_endpoint_to_api_document(
      nlohmann::json& document, const EndpointPtr& endpoint)
    {
      const auto http_verb = endpoint->dispatch.verb.get_http_method();
      if (!http_verb.has_value())
      {
        return;
      }

      for (const auto& builder_fn : endpoint->schema_builders)
      {
        builder_fn(document, *endpoint);
      }

      // Make sure the
      // endpoint exists with minimal documentation, even if there are no more
      // informed schema builders
      auto& path_op = ds::openapi::path_operation(
        ds::openapi::path(document, endpoint->dispatch.uri_path),
        http_verb.value());

      // Path Operation must contain at least one response - if none has been
      // defined, assume this can return 200
      if (ds::openapi::responses(path_op).empty())
      {
        ds::openapi::response(path_op, endpoint->success_status);
      }

      if (!endpoint->authn_policies.empty())
      {
        for (const auto& auth_policy : endpoint->authn_policies)
        {
          const auto opt_scheme = auth_policy->get_openapi_security_schema();
          if (opt_scheme.has_value())
          {
            auto& op_security =
              ds::openapi::access::get_array(path_op, "security");
            if (opt_scheme.value() == ccf::unauthenticated_schema)
            {
              // This auth policy is empty, allowing (optionally)
              // unauthenticated access. This is represented in OpenAPI with an
              // empty object
              op_security.push_back(nlohmann::json::object());
            }
            else
            {
              const auto& [name, scheme] = opt_scheme.value();
              ds::openapi::add_security_scheme_to_components(
                document, name, scheme);

              auto security_obj = nlohmann::json::object();
              security_obj[name] = nlohmann::json::array();
              op_security.push_back(security_obj);
            }
          }
        }
      }
    }
  }

  EndpointRegistry::Metrics& EndpointRegistry::get_metrics_for_endpoint(
    const EndpointDefinitionPtr& e)
  {
    return metrics[e->dispatch.uri_path][e->dispatch.verb.c_str()];
  }

  Endpoint EndpointRegistry::make_endpoint(
    const std::string& method,
    RESTVerb verb,
    const EndpointFunction& f,
    const AuthnPolicies& ap)
  {
    Endpoint endpoint;
    endpoint.dispatch.uri_path = method;
    endpoint.dispatch.verb = verb;
    endpoint.func = f;
    endpoint.authn_policies = ap;
    // By default, all write transactions are forwarded
    endpoint.properties.forwarding_required = ForwardingRequired::Always;
    endpoint.installer = this;
    return endpoint;
  }

  Endpoint EndpointRegistry::make_read_only_endpoint(
    const std::string& method,
    RESTVerb verb,
    const ReadOnlyEndpointFunction& f,
    const AuthnPolicies& ap)
  {
    return make_endpoint(
             method,
             verb,
             [f](EndpointContext& args) {
               ReadOnlyEndpointContext ro_args(
                 args.rpc_ctx, std::move(args.caller), args.tx);
               f(ro_args);
             },
             ap)
      .set_forwarding_required(ForwardingRequired::Sometimes);
  }

  Endpoint EndpointRegistry::make_command_endpoint(
    const std::string& method,
    RESTVerb verb,
    const CommandEndpointFunction& f,
    const AuthnPolicies& ap)
  {
    return make_endpoint(
             method, verb, [f](EndpointContext& args) { f(args); }, ap)
      .set_forwarding_required(ForwardingRequired::Sometimes)
      .set_execute_outside_consensus(
        ccf::endpoints::ExecuteOutsideConsensus::Primary);
  }

  void EndpointRegistry::install(Endpoint& endpoint)
  {
    // A single empty auth policy is semantically equivalent to no policy, but
    // no policy is faster
    if (
      endpoint.authn_policies.size() == 1 &&
      endpoint.authn_policies.back() == empty_auth_policy)
    {
      endpoint.authn_policies.pop_back();
    }

    const auto template_spec = parse_path_template(endpoint.dispatch.uri_path);
    if (template_spec.has_value())
    {
      auto templated_endpoint =
        std::make_shared<PathTemplatedEndpoint>(endpoint);
      templated_endpoint->spec = std::move(template_spec.value());
      templated_endpoints[endpoint.dispatch.uri_path][endpoint.dispatch.verb] =
        templated_endpoint;
    }
    else
    {
      fully_qualified_endpoints[endpoint.dispatch.uri_path]
                               [endpoint.dispatch.verb] =
                                 std::make_shared<Endpoint>(endpoint);
    }
  }

  void EndpointRegistry::set_default(
    EndpointFunction f, const AuthnPolicies& ap)
  {
    auto tmp = std::make_shared<Endpoint>();
    tmp->func = f;
    tmp->authn_policies = ap;

    default_endpoint = std::move(tmp);
  }

  void EndpointRegistry::build_api(nlohmann::json& document, kv::ReadOnlyTx&)
  {
    ds::openapi::server(document, fmt::format("/{}", method_prefix));

    for (const auto& [path, verb_endpoints] : fully_qualified_endpoints)
    {
      for (const auto& [verb, endpoint] : verb_endpoints)
      {
        if (endpoint->openapi_hidden)
          continue;
        add_endpoint_to_api_document(document, endpoint);
      }
    }

    for (const auto& [path, verb_endpoints] : templated_endpoints)
    {
      for (const auto& [verb, endpoint] : verb_endpoints)
      {
        if (endpoint->openapi_hidden)
          continue;
        add_endpoint_to_api_document(document, endpoint);

        for (const auto& name : endpoint->spec.template_component_names)
        {
          auto parameter = nlohmann::json::object();
          parameter["name"] = name;
          parameter["in"] = "path";
          parameter["required"] = true;
          parameter["schema"] = {{"type", "string"}};
          ds::openapi::add_path_parameter_schema(
            document, endpoint->dispatch.uri_path, parameter);
        }
      }
    }
  }

  void EndpointRegistry::init_handlers() {}

  EndpointDefinitionPtr EndpointRegistry::find_endpoint(
    kv::Tx&, enclave::RpcContext& rpc_ctx)
  {
    auto method = rpc_ctx.get_method();
    method = method.substr(method.find_first_not_of('/'));

    auto endpoints_for_exact_method = fully_qualified_endpoints.find(method);
    if (endpoints_for_exact_method != fully_qualified_endpoints.end())
    {
      auto& verb_endpoints = endpoints_for_exact_method->second;
      auto endpoints_for_verb = verb_endpoints.find(rpc_ctx.get_request_verb());
      if (endpoints_for_verb != verb_endpoints.end())
      {
        return endpoints_for_verb->second;
      }
    }

    // If that doesn't exist, look through the templated endpoints to find
    // templated matches. Exactly one is a returnable match, more is an error,
    // fewer is fallthrough.
    {
      std::vector<EndpointDefinitionPtr> matches;

      std::smatch match;
      for (auto& [original_method, verb_endpoints] : templated_endpoints)
      {
        auto templated_endpoints_for_verb =
          verb_endpoints.find(rpc_ctx.get_request_verb());
        if (templated_endpoints_for_verb != verb_endpoints.end())
        {
          auto& endpoint = templated_endpoints_for_verb->second;
          if (std::regex_match(method, match, endpoint->spec.template_regex))
          {
            // Populate the request_path_params the first-time through. If we
            // get a second match, we're just building up a list for
            // error-reporting
            if (matches.size() == 0)
            {
              auto& path_params = rpc_ctx.get_request_path_params();
              for (size_t i = 0;
                   i < endpoint->spec.template_component_names.size();
                   ++i)
              {
                const auto& template_name =
                  endpoint->spec.template_component_names[i];
                const auto& template_value = match[i + 1].str();
                path_params[template_name] = template_value;
              }
            }

            matches.push_back(endpoint);
          }
        }
      }

      if (matches.size() > 1)
      {
        report_ambiguous_templated_path(method, matches);
      }
      else if (matches.size() == 1)
      {
        return matches[0];
      }
    }

    if (default_endpoint != nullptr)
    {
      return default_endpoint;
    }

    return nullptr;
  }

  void EndpointRegistry::execute_endpoint(
    EndpointDefinitionPtr e, EndpointContext& args)
  {
    auto endpoint = dynamic_cast<const Endpoint*>(e.get());
    if (endpoint == nullptr)
    {
      throw std::logic_error(
        "Base execute_endpoint called on incorrect Endpoint type - expected "
        "derived implementation to handle derived endpoint instances");
    }

    endpoint->func(args);
  }

  std::set<RESTVerb> EndpointRegistry::get_allowed_verbs(
    const enclave::RpcContext& rpc_ctx)
  {
    auto method = rpc_ctx.get_method();
    method = method.substr(method.find_first_not_of('/'));

    std::set<RESTVerb> verbs;

    auto search = fully_qualified_endpoints.find(method);
    if (search != fully_qualified_endpoints.end())
    {
      for (const auto& [verb, endpoint] : search->second)
      {
        verbs.insert(verb);
      }
    }

    std::smatch match;
    for (const auto& [original_method, verb_endpoints] : templated_endpoints)
    {
      for (const auto& [verb, endpoint] : verb_endpoints)
      {
        if (std::regex_match(method, match, endpoint->spec.template_regex))
        {
          verbs.insert(verb);
        }
      }
    }

    return verbs;
  }

  void EndpointRegistry::report_ambiguous_templated_path(
    const std::string& path, const std::vector<EndpointDefinitionPtr>& matches)
  {
    // Log low-information error
    LOG_FAIL_FMT("Found multiple potential templated matches for request path");

    auto error_string =
      fmt::format("Multiple potential matches for path: {}", path);
    for (const auto& match : matches)
    {
      error_string += fmt::format("\n  {}", match->dispatch.uri_path);
    }
    LOG_DEBUG_FMT("{}", error_string);

    // Assume this exception is caught and reported in a useful fashion.
    // There's probably nothing the caller can do, ideally this ambiguity
    // would be caught when the endpoints were defined.
    throw std::logic_error(error_string);
  }

  // Default implementation does nothing
  void EndpointRegistry::tick(std::chrono::milliseconds, size_t) {}

  void EndpointRegistry::set_consensus(kv::Consensus* c)
  {
    consensus = c;
  }

  void EndpointRegistry::set_history(kv::TxHistory* h)
  {
    history = h;
  }

  void EndpointRegistry::increment_metrics_calls(const EndpointDefinitionPtr& e)
  {
    std::lock_guard<SpinLock> guard(metrics_lock);
    get_metrics_for_endpoint(e).calls++;
  }

  void EndpointRegistry::increment_metrics_errors(
    const EndpointDefinitionPtr& e)
  {
    std::lock_guard<SpinLock> guard(metrics_lock);
    get_metrics_for_endpoint(e).errors++;
  }

  void EndpointRegistry::increment_metrics_failures(
    const EndpointDefinitionPtr& e)
  {
    std::lock_guard<SpinLock> guard(metrics_lock);
    get_metrics_for_endpoint(e).failures++;
  }

  void EndpointRegistry::increment_metrics_retries(
    const EndpointDefinitionPtr& e)
  {
    std::lock_guard<SpinLock> guard(metrics_lock);
    get_metrics_for_endpoint(e).retries++;
  }
}