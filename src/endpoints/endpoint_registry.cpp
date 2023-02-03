// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/endpoint_registry.h"

#include "ccf/common_auth_policies.h"
#include "ccf/pal/locking.h"
#include "http/http_parser.h"
#include "node/rpc/rpc_context_impl.h"

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
        ds::openapi::path(document, endpoint->full_uri_path),
        http_verb.value());

      // Path Operation must contain at least one response - if none has been
      // defined, assume this can return 200
      if (ds::openapi::responses(path_op).empty())
      {
        ds::openapi::response(path_op, endpoint->success_status);
      }

      // Add a default error response
      ds::openapi::error_response_default(path_op);

      // Add summary and description if set
      if (endpoint->openapi_summary.has_value())
      {
        path_op["summary"] = endpoint->openapi_summary.value();
      }

      if (endpoint->openapi_deprecated.has_value())
      {
        path_op["deprecated"] = endpoint->openapi_deprecated.value();
      }

      if (endpoint->openapi_description.has_value())
      {
        path_op["description"] = endpoint->openapi_description.value();
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

      auto schema_ref_object = nlohmann::json::object();
      schema_ref_object["$ref"] = fmt::format(
        "#/components/x-ccf-forwarding/{}",
        endpoint->properties.forwarding_required);
      ds::openapi::extension(path_op, "x-ccf-forwarding") = schema_ref_object;
    }
  }

  std::optional<PathTemplateSpec> PathTemplateSpec::parse(
    const std::string_view& uri)
  {
    auto template_start = uri.find_first_of('{');
    if (template_start == std::string::npos)
    {
      return std::nullopt;
    }

    PathTemplateSpec spec;

    std::string regex_s(uri);
    template_start = regex_s.find_first_of('{');
    while (template_start != std::string::npos)
    {
      const auto template_end = regex_s.find_first_of('}', template_start);
      if (template_end == std::string::npos)
      {
        throw std::logic_error(fmt::format(
          "Invalid templated path - missing closing curly bracket: {}", uri));
      }

      spec.template_component_names.push_back(
        regex_s.substr(template_start + 1, template_end - template_start - 1));
      regex_s.replace(
        template_start, template_end - template_start + 1, "([^/]+)");
      template_start = regex_s.find_first_of('{', template_start + 1);
    }

    LOG_TRACE_FMT("Parsed a templated endpoint: {} became {}", uri, regex_s);
    LOG_TRACE_FMT(
      "Component names are: {}",
      fmt::join(spec.template_component_names, ", "));
    spec.template_regex = std::regex(regex_s);

    return spec;
  }

  EndpointRegistry::Metrics& EndpointRegistry::get_metrics_for_request(
    const std::string& method_, const std::string& verb)
  {
    auto substr_start = method_.find_first_not_of('/');
    if (substr_start == std::string::npos)
    {
      substr_start = 0;
    }
    auto method = method_.substr(substr_start);
    return metrics[method][verb];
  }

  void default_locally_committed_func(
    CommandEndpointContext& ctx, const TxID& tx_id)
  {
    ctx.rpc_ctx->set_response_header(http::headers::CCF_TX_ID, tx_id.to_str());
  }

  Endpoint EndpointRegistry::make_endpoint(
    const std::string& method,
    RESTVerb verb,
    const EndpointFunction& f,
    const AuthnPolicies& ap)
  {
    Endpoint endpoint;
    if (method.starts_with("/"))
    {
      endpoint.dispatch.uri_path = method;
    }
    else
    {
      endpoint.dispatch.uri_path = fmt::format("/{}", method);
    }
    endpoint.full_uri_path =
      fmt::format("/{}{}", method_prefix, endpoint.dispatch.uri_path);

    endpoint.dispatch.verb = verb;
    endpoint.func = f;
    endpoint.locally_committed_func = default_locally_committed_func;

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
             [f](EndpointContext& ctx) {
               ReadOnlyEndpointContext ro_ctx(ctx.rpc_ctx, ctx.tx);
               ro_ctx.caller = std::move(ctx.caller);
               f(ro_ctx);
             },
             ap)
      .set_forwarding_required(ForwardingRequired::Sometimes);
  }

  Endpoint EndpointRegistry::make_endpoint_with_local_commit_handler(
    const std::string& method,
    RESTVerb verb,
    const EndpointFunction& f,
    const LocallyCommittedEndpointFunction& l,
    const AuthnPolicies& ap)
  {
    auto endpoint = make_endpoint(method, verb, f, ap);
    endpoint.locally_committed_func = l;
    return endpoint;
  }

  Endpoint EndpointRegistry::make_read_only_endpoint_with_local_commit_handler(
    const std::string& method,
    RESTVerb verb,
    const ReadOnlyEndpointFunction& f,
    const LocallyCommittedEndpointFunction& l,
    const AuthnPolicies& ap)
  {
    auto endpoint = make_read_only_endpoint(method, verb, f, ap);
    endpoint.locally_committed_func = l;
    return endpoint;
  }

  Endpoint EndpointRegistry::make_command_endpoint(
    const std::string& method,
    RESTVerb verb,
    const CommandEndpointFunction& f,
    const AuthnPolicies& ap)
  {
    return make_endpoint(
             method, verb, [f](EndpointContext& ctx) { f(ctx); }, ap)
      .set_forwarding_required(ForwardingRequired::Sometimes);
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

    const auto template_spec =
      PathTemplateSpec::parse(endpoint.dispatch.uri_path);
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
    // Add common components:
    // - Descriptions of each kind of forwarding
    auto& forwarding_component = document["components"]["x-ccf-forwarding"];
    auto& always = forwarding_component["always"];
    always["value"] = ccf::endpoints::ForwardingRequired::Always;
    always["description"] =
      "If this request is made to a backup node, it will be forwarded to the "
      "primary node for execution.";
    auto& sometimes = forwarding_component["sometimes"];
    sometimes["value"] = ccf::endpoints::ForwardingRequired::Sometimes;
    sometimes["description"] =
      "If this request is made to a backup node, it may be forwarded to the "
      "primary node for execution. Specifically, if this request is sent as "
      "part of a session which was already forwarded, then it will also be "
      "forwarded.";
    auto& never = forwarding_component["never"];
    never["value"] = ccf::endpoints::ForwardingRequired::Never;
    never["description"] =
      "This call will never be forwarded, and is always executed on the "
      "receiving node, potentially breaking session consistency. If this "
      "attempts to write on a backup, this will fail.";

    // Add ccf OData error response schema
    auto& schemas = document["components"]["schemas"];
    schemas["CCFError"]["type"] = "object";
    schemas["CCFError"]["properties"] = nlohmann::json::object();
    schemas["CCFError"]["properties"]["error"] = nlohmann::json::object();
    schemas["CCFError"]["properties"]["error"]["type"] = "object";
    schemas["CCFError"]["properties"]["error"]["properties"] =
      nlohmann::json::object();
    auto& error_properties =
      schemas["CCFError"]["properties"]["error"]["properties"];
    error_properties["code"]["description"] =
      "Response error code. CCF error codes: "
      "https://microsoft.github.io/CCF/main/operations/"
      "troubleshooting.html#error-codes";
    error_properties["code"]["type"] = "string";
    error_properties["message"]["description"] = "Response error message";
    error_properties["message"]["type"] = "string";

    // Add a default error response definition
    auto& responses = document["components"]["responses"];
    auto& default_error = responses["default"];
    ds::openapi::schema(
      ds::openapi::media_type(default_error, "application/json"))["$ref"] =
      "#/components/schemas/CCFError";
    default_error["description"] = "An error occurred";

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
            document, endpoint->full_uri_path, parameter);
        }
      }
    }
  }

  void EndpointRegistry::init_handlers() {}

  EndpointDefinitionPtr EndpointRegistry::find_endpoint(
    kv::Tx&, ccf::RpcContext& rpc_ctx)
  {
    auto method = rpc_ctx.get_method();
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
              auto ctx_impl = static_cast<ccf::RpcContextImpl*>(&rpc_ctx);
              if (ctx_impl == nullptr)
              {
                throw std::logic_error("Unexpected type of RpcContext");
              }
              auto& path_params = ctx_impl->path_params;
              auto& decoded_path_params = ctx_impl->decoded_path_params;
              for (size_t i = 0;
                   i < endpoint->spec.template_component_names.size();
                   ++i)
              {
                const auto& template_name =
                  endpoint->spec.template_component_names[i];
                const auto& template_value = match[i + 1].str();
                auto decoded_value = http::url_decode(template_value);
                path_params[template_name] = template_value;
                decoded_path_params[template_name] = decoded_value;
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
    EndpointDefinitionPtr e, EndpointContext& ctx)
  {
    auto endpoint = dynamic_cast<const Endpoint*>(e.get());
    if (endpoint == nullptr)
    {
      throw std::logic_error(
        "Base execute_endpoint called on incorrect Endpoint type - expected "
        "derived implementation to handle derived endpoint instances");
    }

    endpoint->func(ctx);
  }

  void EndpointRegistry::execute_endpoint_locally_committed(
    EndpointDefinitionPtr e, CommandEndpointContext& ctx, const TxID& tx_id)
  {
    auto endpoint = dynamic_cast<const Endpoint*>(e.get());
    if (endpoint == nullptr)
    {
      throw std::logic_error(
        "Base execute_endpoint_locally_committed called on incorrect Endpoint "
        "type - expected derived implementation to handle derived endpoint "
        "instances");
    }

    endpoint->locally_committed_func(ctx, tx_id);
  }

  std::set<RESTVerb> EndpointRegistry::get_allowed_verbs(
    kv::Tx& tx, const ccf::RpcContext& rpc_ctx)
  {
    auto method = rpc_ctx.get_method();

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
  void EndpointRegistry::tick(std::chrono::milliseconds) {}

  void EndpointRegistry::set_consensus(kv::Consensus* c)
  {
    consensus = c;
  }

  void EndpointRegistry::set_history(kv::TxHistory* h)
  {
    history = h;
  }

  void EndpointRegistry::increment_metrics_calls(const ccf::RpcContext& rpc_ctx)
  {
    std::lock_guard<ccf::pal::Mutex> guard(metrics_lock);
    get_metrics_for_request(
      rpc_ctx.get_method(), rpc_ctx.get_request_verb().c_str())
      .calls++;
  }

  void EndpointRegistry::increment_metrics_errors(
    const ccf::RpcContext& rpc_ctx)
  {
    std::lock_guard<ccf::pal::Mutex> guard(metrics_lock);
    get_metrics_for_request(
      rpc_ctx.get_method(), rpc_ctx.get_request_verb().c_str())
      .errors++;
  }

  void EndpointRegistry::increment_metrics_failures(
    const ccf::RpcContext& rpc_ctx)
  {
    std::lock_guard<ccf::pal::Mutex> guard(metrics_lock);
    get_metrics_for_request(
      rpc_ctx.get_method(), rpc_ctx.get_request_verb().c_str())
      .failures++;
  }

  void EndpointRegistry::increment_metrics_retries(
    const ccf::RpcContext& rpc_ctx)
  {
    std::lock_guard<ccf::pal::Mutex> guard(metrics_lock);
    get_metrics_for_request(
      rpc_ctx.get_method(), rpc_ctx.get_request_verb().c_str())
      .retries++;
  }
}
