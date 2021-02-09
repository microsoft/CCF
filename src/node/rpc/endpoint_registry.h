// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/ccf_deprecated.h"
#include "ds/json_schema.h"
#include "ds/openapi.h"
#include "enclave/rpc_context.h"
#include "endpoint.h"
#include "http/authentication/cert_auth.h"
#include "http/authentication/jwt_auth.h"
#include "http/authentication/sig_auth.h"
#include "http/http_consts.h"
#include "http/ws_consts.h"
#include "kv/tx.h"
#include "node/certs.h"
#include "serialization.h"

#include <charconv>
#include <functional>
#include <llhttp/llhttp.h>
#include <nlohmann/json.hpp>
#include <regex>
#include <set>

namespace ccf
{
  using namespace endpoints;

  // Commands are endpoints which do not interact with the kv, even to read
  struct CommandEndpointContext
  {
    CommandEndpointContext(
      const std::shared_ptr<enclave::RpcContext>& r,
      std::unique_ptr<AuthnIdentity>&& c) :
      rpc_ctx(r),
      caller(std::move(c))
    {}

    std::shared_ptr<enclave::RpcContext> rpc_ctx;
    std::unique_ptr<AuthnIdentity> caller;

    template <typename T>
    const T* try_get_caller()
    {
      return dynamic_cast<const T*>(caller.get());
    }

    template <typename T>
    const T& get_caller()
    {
      const T* ident = try_get_caller<T>();
      if (ident == nullptr)
      {
        throw std::logic_error("Asked for unprovided identity type");
      }
      return *ident;
    }
  };
  using CommandEndpointFunction =
    std::function<void(CommandEndpointContext& args)>;

  struct EndpointContext : public CommandEndpointContext
  {
    EndpointContext(
      const std::shared_ptr<enclave::RpcContext>& r,
      std::unique_ptr<AuthnIdentity>&& c,
      kv::Tx& t) :
      CommandEndpointContext(r, std::move(c)),
      tx(t)
    {}

    kv::Tx& tx;
  };
  using EndpointFunction = std::function<void(EndpointContext& args)>;

  // Read-only endpoints can only get values from the kv, they cannot write
  struct ReadOnlyEndpointContext : public CommandEndpointContext
  {
    ReadOnlyEndpointContext(
      const std::shared_ptr<enclave::RpcContext>& r,
      std::unique_ptr<AuthnIdentity>&& c,
      kv::ReadOnlyTx& t) :
      CommandEndpointContext(r, std::move(c)),
      tx(t)
    {}

    kv::ReadOnlyTx& tx;
  };
  using ReadOnlyEndpointFunction =
    std::function<void(ReadOnlyEndpointContext& args)>;

  // Auth policies
  /** Perform no authentication */
  static std::shared_ptr<EmptyAuthnPolicy> empty_auth_policy =
    std::make_shared<EmptyAuthnPolicy>();
  /** Authenticate using TLS session identity, and @c public:ccf.gov.users.info
   * table */
  static std::shared_ptr<UserCertAuthnPolicy> user_cert_auth_policy =
    std::make_shared<UserCertAuthnPolicy>();
  /** Authenticate using HTTP request signature, and
   * @c public:ccf.gov.users.info table */
  static std::shared_ptr<UserSignatureAuthnPolicy> user_signature_auth_policy =
    std::make_shared<UserSignatureAuthnPolicy>();
  /** Authenticate using TLS session identity, and
   * @c public:ccf.gov.members.info table */
  static std::shared_ptr<MemberCertAuthnPolicy> member_cert_auth_policy =
    std::make_shared<MemberCertAuthnPolicy>();
  /** Authenticate using HTTP request signature, and
   * @c public:ccf.gov.members.info table */
  static std::shared_ptr<MemberSignatureAuthnPolicy>
    member_signature_auth_policy =
      std::make_shared<MemberSignatureAuthnPolicy>();
  /** Authenticate using JWT, validating the token using the
   * @c public:ccf.gov.jwt.public_signing_key_issuer and
   * @c public:ccf.gov.jwt.public_signing_keys tables */
  static std::shared_ptr<JwtAuthnPolicy> jwt_auth_policy =
    std::make_shared<JwtAuthnPolicy>();

  static AuthnPolicies no_auth_required = {};

  /** The EndpointRegistry records the user-defined endpoints for a given
   * CCF application.
   */
  class EndpointRegistry
  {
  public:
    enum ReadWrite
    {
      Read,
      Write
    };

    const std::string method_prefix;

    struct OpenApiInfo
    {
      std::string title = "Empty title";
      std::string description = "Empty description";
      std::string document_version = "0.0.1";
    } openapi_info;

    struct Metrics
    {
      size_t calls = 0;
      size_t errors = 0;
      size_t failures = 0;
      size_t retries = 0;
    };

    struct Endpoint;
    using EndpointPtr = std::shared_ptr<const Endpoint>;

    using SchemaBuilderFn =
      std::function<void(nlohmann::json&, const EndpointPtr&)>;

    /** An Endpoint represents a user-defined resource that can be invoked by
     * authorised users via HTTP requests, over TLS. An Endpoint is accessible
     * at a specific verb and URI, e.g. POST /app/accounts or GET /app/records.
     *
     * Endpoints can read from and mutate the state of the replicated key-value
     * store.
     *
     * A CCF application is a collection of Endpoints recorded in the
     * application's EndpointRegistry.
     */
    struct Endpoint : public EndpointDefinition
    {
      EndpointFunction func = {};
      EndpointRegistry* registry = nullptr;

      std::vector<SchemaBuilderFn> schema_builders = {};

      bool openapi_hidden = false;

      /** Whether the endpoint should be omitted from the OpenAPI document.
       *
       * @return This Endpoint for further modification
       */
      Endpoint& set_openapi_hidden(bool hidden)
      {
        openapi_hidden = hidden;
        return *this;
      }

      nlohmann::json params_schema = nullptr;

      /** Sets the JSON schema that the request parameters must comply with.
       *
       * @param j Request parameters JSON schema
       * @return This Endpoint for further modification
       */
      Endpoint& set_params_schema(const nlohmann::json& j)
      {
        params_schema = j;

        schema_builders.push_back([](
                                    nlohmann::json& document,
                                    const EndpointPtr& endpoint) {
          const auto http_verb = endpoint->dispatch.verb.get_http_method();
          if (!http_verb.has_value())
          {
            return;
          }

          using namespace ds::openapi;

          if (http_verb.value() == HTTP_GET || http_verb.value() == HTTP_DELETE)
          {
            add_query_parameters(
              document,
              endpoint->dispatch.uri_path,
              endpoint->params_schema,
              http_verb.value());
          }
          else
          {
            auto& rb = request_body(path_operation(
              ds::openapi::path(document, endpoint->dispatch.uri_path),
              http_verb.value()));
            schema(media_type(rb, http::headervalues::contenttype::JSON)) =
              endpoint->params_schema;
          }
        });

        return *this;
      }

      http_status success_status = HTTP_STATUS_OK;

      nlohmann::json result_schema = nullptr;

      /** Sets the JSON schema that the request response must comply with.
       *
       * @param j Request response JSON schema
       * @param status Request response status code
       * @return This Endpoint for further modification
       */
      Endpoint& set_result_schema(
        const nlohmann::json& j,
        std::optional<http_status> status = std::nullopt)
      {
        result_schema = j;
        success_status = status.value_or(HTTP_STATUS_OK);

        schema_builders.push_back(
          [j](nlohmann::json& document, const EndpointPtr& endpoint) {
            const auto http_verb = endpoint->dispatch.verb.get_http_method();
            if (!http_verb.has_value())
            {
              return;
            }

            using namespace ds::openapi;
            auto& r = response(
              path_operation(
                ds::openapi::path(document, endpoint->dispatch.uri_path),
                http_verb.value()),
              endpoint->success_status);

            schema(media_type(r, http::headervalues::contenttype::JSON)) =
              endpoint->result_schema;
          });

        return *this;
      }

      /** Sets the schema that the request parameters and response must comply
       * with based on JSON-serialisable data structures.
       *
       * \verbatim embed:rst:leading-asterisk
       * .. note::
       *  See ``DECLARE_JSON_`` serialisation macros for serialising
       *  user-defined data structures.
       * \endverbatim
       *
       * @tparam In Request parameters JSON-serialisable data structure
       * @tparam Out Request response JSON-serialisable data structure
       * @param status Request response status code
       * @return This Endpoint for further modification
       */
      template <typename In, typename Out>
      Endpoint& set_auto_schema(
        std::optional<http_status> status = std::nullopt)
      {
        if constexpr (!std::is_same_v<In, void>)
        {
          params_schema =
            ds::json::build_schema<In>(dispatch.uri_path + "/params");

          schema_builders.push_back(
            [](nlohmann::json& document, const EndpointPtr& endpoint) {
              const auto http_verb = endpoint->dispatch.verb.get_http_method();
              if (!http_verb.has_value())
              {
                // Non-HTTP (ie WebSockets) endpoints are not documented
                return;
              }

              if (
                http_verb.value() == HTTP_GET ||
                http_verb.value() == HTTP_DELETE)
              {
                add_query_parameters(
                  document,
                  endpoint->dispatch.uri_path,
                  endpoint->params_schema,
                  http_verb.value());
              }
              else
              {
                ds::openapi::add_request_body_schema<In>(
                  document,
                  endpoint->dispatch.uri_path,
                  http_verb.value(),
                  http::headervalues::contenttype::JSON);
              }
            });
        }
        else
        {
          params_schema = nullptr;
        }

        if constexpr (!std::is_same_v<Out, void>)
        {
          success_status = status.value_or(HTTP_STATUS_OK);

          result_schema =
            ds::json::build_schema<Out>(dispatch.uri_path + "/result");

          schema_builders.push_back(
            [](nlohmann::json& document, const EndpointPtr& endpoint) {
              const auto http_verb = endpoint->dispatch.verb.get_http_method();
              if (!http_verb.has_value())
              {
                return;
              }

              ds::openapi::add_response_schema<Out>(
                document,
                endpoint->dispatch.uri_path,
                http_verb.value(),
                endpoint->success_status,
                http::headervalues::contenttype::JSON);
            });
        }
        else
        {
          success_status = status.value_or(HTTP_STATUS_NO_CONTENT);
          result_schema = nullptr;
        }

        return *this;
      }

      /** Sets the schema that the request parameters and response must comply
       * with, based on a single JSON-serialisable data structure.
       *
       * \verbatim embed:rst:leading-asterisk
       * .. note::
       *   ``T`` data structure should contain two nested ``In`` and ``Out``
       *   structures for request parameters and response format, respectively.
       * \endverbatim
       *
       * @tparam T Request parameters and response JSON-serialisable data
       * structure
       * @param status Request response status code
       * @return This Endpoint for further modification
       */
      template <typename T>
      Endpoint& set_auto_schema(
        std::optional<http_status> status = std::nullopt)
      {
        return set_auto_schema<typename T::In, typename T::Out>(status);
      }

      /** Overrides whether a Endpoint is always forwarded, or whether it is
       * safe to sometimes execute on followers.
       *
       * @param fr Enum value with desired status
       * @return This Endpoint for further modification
       */
      Endpoint& set_forwarding_required(ForwardingRequired fr)
      {
        properties.forwarding_required = fr;
        return *this;
      }

      /** Indicates that the execution of the Endpoint does not require
       * consensus from other nodes in the network.
       *
       * By default, endpoints are not executed locally.
       *
       * \verbatim embed:rst:leading-asterisk
       * .. warning::
       *  Use with caution. This should only be used for non-critical endpoints
       *  that do not read or mutate the state of the key-value store.
       * \endverbatim
       *
       * @param v Enum indicating whether the Endpoint is executed locally,
       * on the node receiving the request, locally on the primary or via the
       * consensus.
       * @return This Endpoint for further modification
       */
      Endpoint& set_execute_outside_consensus(
        ccf::endpoints::ExecuteOutsideConsensus v)
      {
        properties.execute_outside_consensus = v;
        return *this;
      }

      /** Finalise and install this endpoint
       */
      void install()
      {
        if (registry == nullptr)
        {
          LOG_FATAL_FMT(
            "Can't install this endpoint ({}) - it is not associated with a "
            "registry",
            dispatch.uri_path);
        }
        else
        {
          registry->install(*this);
        }
      }
    };

    struct PathTemplateSpec
    {
      std::regex template_regex;
      std::vector<std::string> template_component_names;
    };

    struct PathTemplatedEndpoint : public Endpoint
    {
      PathTemplatedEndpoint(const Endpoint& e) : Endpoint(e) {}

      PathTemplateSpec spec;
    };

    static std::optional<PathTemplateSpec> parse_path_template(
      const std::string& uri)
    {
      auto template_start = uri.find_first_of('{');
      if (template_start == std::string::npos)
      {
        return std::nullopt;
      }

      PathTemplateSpec spec;

      std::string regex_s = uri;
      template_start = regex_s.find_first_of('{');
      while (template_start != std::string::npos)
      {
        const auto template_end = regex_s.find_first_of('}', template_start);
        if (template_end == std::string::npos)
        {
          throw std::logic_error(fmt::format(
            "Invalid templated path - missing closing '}': {}", uri));
        }

        spec.template_component_names.push_back(regex_s.substr(
          template_start + 1, template_end - template_start - 1));
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

    template <typename T>
    bool get_path_param(
      const enclave::PathParams& params,
      const std::string& param_name,
      T& value,
      std::string& error)
    {
      const auto it = params.find(param_name);
      if (it == params.end())
      {
        error = fmt::format("No parameter named '{}' in path", param_name);
        return false;
      }

      const auto param_s = it->second;
      const auto [p, ec] =
        std::from_chars(param_s.data(), param_s.data() + param_s.size(), value);
      if (ec != std::errc())
      {
        error = fmt::format(
          "Unable to parse path parameter '{}' as a {}", param_s, param_name);
        return false;
      }

      return true;
    }

    template <>
    bool get_path_param(
      const enclave::PathParams& params,
      const std::string& param_name,
      std::string& value,
      std::string& error)
    {
      const auto it = params.find(param_name);
      if (it == params.end())
      {
        error = fmt::format("No parameter named '{}' in path", param_name);
        return false;
      }

      value = it->second;
      return true;
    }

  protected:
    EndpointPtr default_endpoint;
    std::map<std::string, std::map<RESTVerb, EndpointPtr>>
      fully_qualified_endpoints;
    std::map<
      std::string,
      std::map<RESTVerb, std::shared_ptr<PathTemplatedEndpoint>>>
      templated_endpoints;

    SpinLock metrics_lock;
    std::map<std::string, std::map<std::string, Metrics>> metrics;

    kv::Consensus* consensus = nullptr;
    kv::TxHistory* history = nullptr;

    static void add_query_parameters(
      nlohmann::json& document,
      const std::string& uri,
      const nlohmann::json& schema,
      llhttp_method verb)
    {
      if (schema["type"] != "object")
      {
        throw std::logic_error(
          fmt::format("Unexpected params schema type: {}", schema.dump()));
      }

      const auto& required_parameters =
        schema.value("required", nlohmann::json::array());
      for (const auto& [name, schema] : schema["properties"].items())
      {
        auto parameter = nlohmann::json::object();
        parameter["name"] = name;
        parameter["in"] = "query";
        parameter["required"] =
          required_parameters.find(name) != required_parameters.end();
        parameter["schema"] = schema;
        ds::openapi::add_request_parameter_schema(
          document, uri, verb, parameter);
      }
    }

  public:
    EndpointRegistry(const std::string& method_prefix_) :
      method_prefix(method_prefix_)
    {}

    virtual ~EndpointRegistry() {}

    /** Create a new endpoint.
     *
     * Caller should set any additional properties on the returned Endpoint
     * object, and finally call Endpoint::install() to install it.
     *
     * @param method The URI at which this endpoint will be installed
     * @param verb The HTTP verb which this endpoint will respond to
     * @param f Functor which will be invoked for requests to VERB /method
     * @param ap Policies which will be checked against each request before the
     * endpoint is executed. @see
     * ccf::endpoints::EndpointDefinition::authn_policies
     * @return The new Endpoint for further modification
     */
    Endpoint make_endpoint(
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
      endpoint.registry = this;
      return endpoint;
    }

    /** Create a read-only endpoint.
     */
    Endpoint make_read_only_endpoint(
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

    /** Create a new command endpoint.
     *
     * Commands are endpoints which do not read or write from the KV. See
     * make_endpoint().
     */
    Endpoint make_command_endpoint(
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

    /** Install the given endpoint, using its method and verb
     *
     * If an implementation is already installed for this method and verb, it
     * will be replaced.
     * @param endpoint Endpoint object describing the new resource to install
     */
    void install(Endpoint& endpoint)
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
        parse_path_template(endpoint.dispatch.uri_path);
      if (template_spec.has_value())
      {
        auto templated_endpoint =
          std::make_shared<PathTemplatedEndpoint>(endpoint);
        templated_endpoint->spec = std::move(template_spec.value());
        templated_endpoints[endpoint.dispatch.uri_path]
                           [endpoint.dispatch.verb] = templated_endpoint;
      }
      else
      {
        fully_qualified_endpoints[endpoint.dispatch.uri_path]
                                 [endpoint.dispatch.verb] =
                                   std::make_shared<Endpoint>(endpoint);
      }
    }

    /** Set a default EndpointFunction
     *
     * The default EndpointFunction is only invoked if no specific
     * EndpointFunction was found.
     *
     * @param f Method implementation
     */
    void set_default(EndpointFunction f, const AuthnPolicies& ap)
    {
      auto tmp = std::make_shared<Endpoint>();
      tmp->func = f;
      tmp->authn_policies = ap;

      default_endpoint = std::move(tmp);
    }

    static void add_auth_policy_to_api_document() {}

    static void add_endpoint_to_api_document(
      nlohmann::json& document, const EndpointPtr& endpoint)
    {
      const auto http_verb = endpoint->dispatch.verb.get_http_method();
      if (!http_verb.has_value())
      {
        return;
      }

      for (const auto& builder_fn : endpoint->schema_builders)
      {
        builder_fn(document, endpoint);
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

    /** Populate document with all supported methods
     *
     * This is virtual since derived classes may do their own dispatch
     * internally, so must be able to populate the document
     * with the supported endpoints however it defines them.
     */
    virtual void build_api(nlohmann::json& document, kv::ReadOnlyTx&)
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

    virtual void endpoint_metrics(EndpointMetrics::Out& out)
    {
      std::lock_guard<SpinLock> guard(metrics_lock);
      for (const auto& [path, verb_metrics] : metrics)
      {
        for (const auto& [verb, metric] : verb_metrics)
        {
          out.metrics.push_back({path,
                                 verb,
                                 metric.calls,
                                 metric.errors,
                                 metric.failures,
                                 metric.retries});
        }
      }
    }

    Metrics& get_metrics(const EndpointDefinitionPtr& e)
    {
      std::lock_guard<SpinLock> guard(metrics_lock);
      return metrics[e->dispatch.uri_path][e->dispatch.verb.c_str()];
    }

    virtual void init_handlers() {}

    virtual EndpointDefinitionPtr find_endpoint(
      kv::Tx&, enclave::RpcContext& rpc_ctx)
    {
      auto method = rpc_ctx.get_method();
      method = method.substr(method.find_first_not_of('/'));

      auto endpoints_for_exact_method = fully_qualified_endpoints.find(method);
      if (endpoints_for_exact_method != fully_qualified_endpoints.end())
      {
        auto& verb_endpoints = endpoints_for_exact_method->second;
        auto endpoints_for_verb =
          verb_endpoints.find(rpc_ctx.get_request_verb());
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

    virtual void execute_endpoint(
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

    virtual std::set<RESTVerb> get_allowed_verbs(
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

    virtual void report_ambiguous_templated_path(
      const std::string& path,
      const std::vector<EndpointDefinitionPtr>& matches)
    {
      // Log low-information error
      LOG_FAIL_FMT(
        "Found multiple potential templated matches for request path");

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

    virtual void tick(std::chrono::milliseconds, kv::Consensus::Statistics) {}

    void set_consensus(kv::Consensus* c)
    {
      consensus = c;
    }

    void set_history(kv::TxHistory* h)
    {
      history = h;
    }
  };
}