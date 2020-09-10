// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/json_schema.h"
#include "ds/openapi.h"
#include "enclave/rpc_context.h"
#include "http/http_consts.h"
#include "http/ws_consts.h"
#include "kv/store.h"
#include "kv/tx.h"
#include "node/certs.h"
#include "serialization.h"

#include <functional>
#include <http-parser/http_parser.h>
#include <nlohmann/json.hpp>
#include <regex>
#include <set>

namespace ccf
{
  struct EndpointContext
  {
    std::shared_ptr<enclave::RpcContext> rpc_ctx;
    kv::Tx& tx;
    CallerId caller_id;
  };
  using EndpointFunction = std::function<void(EndpointContext& args)>;

  // Read-only endpoints can only get values from the kv, they cannot write
  struct ReadOnlyEndpointContext
  {
    std::shared_ptr<enclave::RpcContext> rpc_ctx;
    kv::ReadOnlyTx& tx;
    CallerId caller_id;
  };
  using ReadOnlyEndpointFunction =
    std::function<void(ReadOnlyEndpointContext& args)>;

  // Commands are endpoints which do not interact with the kv, even to read
  struct CommandEndpointContext
  {
    std::shared_ptr<enclave::RpcContext> rpc_ctx;
    CallerId caller_id;
  };
  using CommandEndpointFunction =
    std::function<void(CommandEndpointContext& args)>;

  enum class ForwardingRequired
  {
    Sometimes,
    Always,
    Never
  };

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

    struct Metrics
    {
      size_t calls = 0;
      size_t errors = 0;
      size_t failures = 0;
    };

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
    struct Endpoint
    {
      std::string method;
      EndpointFunction func;
      EndpointRegistry* registry = nullptr;
      Metrics metrics = {};
      nlohmann::json params_schema = nullptr;

      /** Sets the JSON schema that the request parameters must comply with.
       *
       * @param j Request parameters JSON schema
       * @return This Endpoint for further modification
       */
      Endpoint& set_params_schema(const nlohmann::json& j)
      {
        params_schema = j;
        return *this;
      }

      nlohmann::json result_schema = nullptr;

      /** Sets the JSON schema that the request response must comply with.
       *
       * @param j Request response JSON schema
       * @return This Endpoint for further modification
       */
      Endpoint& set_result_schema(const nlohmann::json& j)
      {
        result_schema = j;
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
       * @return This Endpoint for further modification
       */
      template <typename In, typename Out>
      Endpoint& set_auto_schema()
      {
        if constexpr (!std::is_same_v<In, void>)
        {
          params_schema = ds::json::build_schema<In>(method + "/params");
        }
        else
        {
          params_schema = nullptr;
        }

        if constexpr (!std::is_same_v<Out, void>)
        {
          result_schema = ds::json::build_schema<Out>(method + "/result");
        }
        else
        {
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
       * @return This Endpoint for further modification
       */
      template <typename T>
      Endpoint& set_auto_schema()
      {
        return set_auto_schema<typename T::In, typename T::Out>();
      }

      ForwardingRequired forwarding_required = ForwardingRequired::Always;

      /** Overrides whether a Endpoint is always forwarded, or whether it is
       * safe to sometimes execute on followers.
       *
       * @param fr Enum value with desired status
       * @return This Endpoint for further modification
       */
      Endpoint& set_forwarding_required(ForwardingRequired fr)
      {
        forwarding_required = fr;
        return *this;
      }

      bool require_client_signature = false;

      /** Requires that the HTTP request is cryptographically signed by
       * the calling user.
       *
       * By default, client signatures are not required.
       *
       * @param v Boolean indicating whether the request must be signed
       * @return This Endpoint for further modification
       */
      Endpoint& set_require_client_signature(bool v)
      {
        require_client_signature = v;
        return *this;
      }

      bool require_client_identity = true;

      /** Requires that the HTTPS request is emitted by a user whose public
       * identity has been registered in advance by consortium members.
       *
       * By default, a known client identity is required.
       *
       * \verbatim embed:rst:leading-asterisk
       * .. warning::
       *  If set to false, it is left to the application developer to implement
       *  the authentication and authorisation mechanisms for the Endpoint.
       * \endverbatim
       *
       * @param v Boolean indicating whether the user identity must be known
       * @return This Endpoint for further modification
       */
      Endpoint& set_require_client_identity(bool v)
      {
        if (!v && registry != nullptr && !registry->has_certs())
        {
          LOG_INFO_FMT(
            "Disabling client identity requirement on {} Endpoint has no "
            "effect "
            "since its registry does not have certificates table",
            method);
          return *this;
        }

        require_client_identity = v;
        return *this;
      }

      bool execute_locally = false;

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
       * @param v Boolean indicating whether the Endpoint is executed locally,
       * on the node receiving the request
       * @return This Endpoint for further modification
       */
      Endpoint& set_execute_locally(bool v)
      {
        execute_locally = v;
        return *this;
      }

      RESTVerb verb = HTTP_POST;

      /** Finalise and install this endpoint
       */
      void install()
      {
        registry->install(*this);
      }
    };

    struct PathTemplatedEndpoint : public Endpoint
    {
      PathTemplatedEndpoint() = default;
      PathTemplatedEndpoint(const PathTemplatedEndpoint& pte) = default;
      PathTemplatedEndpoint(const Endpoint& e) : Endpoint(e) {}

      std::regex template_regex;
      std::vector<std::string> template_component_names;
    };

  protected:
    std::optional<Endpoint> default_endpoint;
    std::map<std::string, std::map<RESTVerb, Endpoint>>
      fully_qualified_endpoints;
    std::map<std::string, std::map<RESTVerb, PathTemplatedEndpoint>>
      templated_endpoints;

    kv::Consensus* consensus = nullptr;
    kv::TxHistory* history = nullptr;

    CertDERs* certs = nullptr;

    static std::optional<PathTemplatedEndpoint> parse_path_template(
      const Endpoint& endpoint)
    {
      auto template_start = endpoint.method.find_first_of('{');
      if (template_start == std::string::npos)
      {
        return std::nullopt;
      }

      PathTemplatedEndpoint templated(endpoint);
      std::string regex_s = endpoint.method;
      template_start = regex_s.find_first_of('{');
      while (template_start != std::string::npos)
      {
        const auto template_end = regex_s.find_first_of('}', template_start);
        if (template_end == std::string::npos)
        {
          throw std::logic_error(fmt::format(
            "Invalid templated path - missing closing '}': {}",
            endpoint.method));
        }

        templated.template_component_names.push_back(regex_s.substr(
          template_start + 1, template_end - template_start - 1));
        regex_s.replace(
          template_start, template_end - template_start + 1, "([^/]+)");
        template_start = regex_s.find_first_of('{', template_start + 1);
      }

      LOG_TRACE_FMT(
        "Installed a templated endpoint: {} became {}",
        endpoint.method,
        regex_s);
      LOG_TRACE_FMT(
        "Component names are: {}",
        fmt::join(templated.template_component_names, ", "));
      templated.template_regex = std::regex(regex_s);

      return templated;
    }

  public:
    EndpointRegistry(
      const std::string& method_prefix_,
      kv::Store& tables,
      const std::string& certs_table_name = "") :
      method_prefix(method_prefix_)
    {
      if (!certs_table_name.empty())
      {
        certs = tables.get<CertDERs>(certs_table_name);
      }
    }

    virtual ~EndpointRegistry() {}

    /** Create a new endpoint.
     *
     * Caller should set any additional properties on the returned Endpoint
     * object, and finally call Endpoint::install() to install it.
     *
     * @param method The URI at which this endpoint will be installed
     * @param verb The HTTP verb which this endpoint will respond to
     * @param f Functor which will be invoked for requests to VERB /method
     * @return The new Endpoint for further modification
     */
    Endpoint make_endpoint(
      const std::string& method, RESTVerb verb, const EndpointFunction& f)
    {
      Endpoint endpoint;
      endpoint.method = method;
      endpoint.verb = verb;
      endpoint.func = f;
      // By default, all write transactions are forwarded
      endpoint.forwarding_required = ForwardingRequired::Always;
      endpoint.registry = this;
      return endpoint;
    }

    /** Create a read-only endpoint.
     */
    Endpoint make_read_only_endpoint(
      const std::string& method,
      RESTVerb verb,
      const ReadOnlyEndpointFunction& f)
    {
      return make_endpoint(
               method,
               verb,
               [f](EndpointContext& args) {
                 ReadOnlyEndpointContext ro_args{
                   args.rpc_ctx, args.tx, args.caller_id};
                 f(ro_args);
               })
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
      const CommandEndpointFunction& f)
    {
      return make_endpoint(
               method,
               verb,
               [f](EndpointContext& args) {
                 CommandEndpointContext command_args{args.rpc_ctx,
                                                     args.caller_id};
                 f(command_args);
               })
        .set_forwarding_required(ForwardingRequired::Sometimes);
    }

    /** Install the given endpoint, using its method and verb
     *
     * If an implementation is already installed for this method and verb, it
     * will be replaced.
     * @param endpoint Endpoint object describing the new resource to install
     */
    void install(const Endpoint& endpoint)
    {
      const auto templated_endpoint = parse_path_template(endpoint);
      if (templated_endpoint.has_value())
      {
        templated_endpoints[endpoint.method][endpoint.verb] =
          templated_endpoint.value();
      }
      else
      {
        fully_qualified_endpoints[endpoint.method][endpoint.verb] = endpoint;
      }
    }

    /** Set a default EndpointFunction
     *
     * The default EndpointFunction is only invoked if no specific
     * EndpointFunction was found.
     *
     * @param f Method implementation
     * @return This Endpoint for further modification
     */
    Endpoint& set_default(EndpointFunction f)
    {
      default_endpoint = {"", f, this};
      return default_endpoint.value();
    }

    /** Populate document with all supported methods
     *
     * This is virtual since derived classes may do their own dispatch
     * internally, so must be able to populate the document
     * with the supported endpoints however it defines them.
     */
    // TODO: May want the entire rpc context, not just tx?
    virtual void build_api(nlohmann::json& document, kv::Tx&)
    {
      for (const auto& [path, verb_endpoints] : fully_qualified_endpoints)
      {
        const auto full_path = fmt::format("/{}/{}", method_prefix, path);
        auto& path_object = ds::openapi::path(document, full_path);
        for (const auto& [verb, handler] : verb_endpoints)
        {
          const auto http_verb = verb.get_http_method();
          if (!http_verb.has_value())
          {
            continue;
          }

          auto& path_operation = ds::openapi::path_operation(path_object, http_verb.value());

          auto& request_body = ds::openapi::request_body(path_operation);
          auto& request_body_json = ds::openapi::media_type(request_body, http::headervalues::contenttype::JSON);
          if (!handler.params_schema.empty())
          {
            auto& request_body_json_schema = ds::openapi::schema(request_body_json);
            request_body_json_schema = handler.params_schema;
          }
          
          auto& response_ok = ds::openapi::response(
            path_operation, HTTP_STATUS_OK, "Auto-generated");
          auto& response_ok_json = ds::openapi::media_type(
            response_ok, http::headervalues::contenttype::JSON);
          if (!handler.result_schema.empty())
          {
            auto& response_ok_json_schema = ds::openapi::schema(response_ok_json);
            response_ok_json_schema = handler.result_schema;
          }
        }
      }

      // TODO
      // for (const auto& [path, verb_endpoints] : templated_endpoints)
      // {
        // for (const auto& [verb, endpoint] : verb_endpoints)
        // {
          // out.endpoints.push_back({verb.c_str(), path});
        // }
      // }
    }

    virtual void endpoint_metrics(kv::Tx&, EndpointMetrics::Out& out)
    {
      for (const auto& [path, verb_endpoints] : fully_qualified_endpoints)
      {
        std::map<std::string, EndpointMetrics::Metric> e;
        for (const auto& [verb, endpoint] : verb_endpoints)
        {
          std::string v(verb.c_str());
          e[v] = {endpoint.metrics.calls,
                  endpoint.metrics.errors,
                  endpoint.metrics.failures};
        }
        out.metrics[path] = e;
      }

      for (const auto& [path, verb_endpoints] : templated_endpoints)
      {
        std::map<std::string, EndpointMetrics::Metric> e;
        for (const auto& [verb, endpoint] : verb_endpoints)
        {
          std::string v(verb.c_str());
          e[v] = {endpoint.metrics.calls,
                  endpoint.metrics.errors,
                  endpoint.metrics.failures};
        }
        out.metrics[path] = e;
      }
    }

    virtual void init_handlers(kv::Store&) {}

    virtual Endpoint* find_endpoint(enclave::RpcContext& rpc_ctx)
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
          return &endpoints_for_verb->second;
        }
      }

      std::smatch match;
      for (auto& [original_method, verb_endpoints] : templated_endpoints)
      {
        auto templated_endpoints_for_verb =
          verb_endpoints.find(rpc_ctx.get_request_verb());
        if (templated_endpoints_for_verb != verb_endpoints.end())
        {
          auto& endpoint = templated_endpoints_for_verb->second;
          if (std::regex_match(method, match, endpoint.template_regex))
          {
            auto& path_params = rpc_ctx.get_request_path_params();
            for (size_t i = 0; i < endpoint.template_component_names.size();
                 ++i)
            {
              const auto& template_name = endpoint.template_component_names[i];
              const auto& template_value = match[i + 1].str();
              path_params[template_name] = template_value;
            }

            return &endpoint;
          }
        }
      }

      if (default_endpoint)
      {
        return &default_endpoint.value();
      }

      return nullptr;
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
          if (std::regex_match(method, match, endpoint.template_regex))
          {
            verbs.insert(verb);
          }
        }
      }

      return verbs;
    }

    virtual void tick(std::chrono::milliseconds, kv::Consensus::Statistics) {}

    bool has_certs()
    {
      return certs != nullptr;
    }

    virtual CallerId get_caller_id(
      kv::Tx& tx, const std::vector<uint8_t>& caller)
    {
      if (certs == nullptr || caller.empty())
      {
        return INVALID_ID;
      }

      auto certs_view = tx.get_view(*certs);
      auto caller_id = certs_view->get(caller);

      if (!caller_id.has_value())
      {
        return INVALID_ID;
      }

      return caller_id.value();
    }

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