// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json_schema.h"
#include "ccf/endpoint.h"
#include "ccf/endpoint_context.h"
#include "ccf/pal/locking.h"
#include "ccf/rpc_context.h"
#include "ccf/tx.h"

#include <charconv>
#include <functional>
#include <llhttp/llhttp.h>
#include <nlohmann/json.hpp>
#include <regex>
#include <set>

namespace kv
{
  class Consensus;
  class TxHistory;
}

namespace ccf::endpoints
{
  struct PathTemplateSpec
  {
    std::regex template_regex;
    std::vector<std::string> template_component_names;

    static std::optional<PathTemplateSpec> parse(const std::string_view& uri);
  };

  struct PathTemplatedEndpoint : public Endpoint
  {
    PathTemplatedEndpoint(const Endpoint& e) : Endpoint(e) {}

    PathTemplateSpec spec;
  };

  void default_locally_committed_func(
    CommandEndpointContext& ctx, const TxID& tx_id);

  /** The EndpointRegistry records the user-defined endpoints for a given
   * CCF application.
   *
   * This is the abstract base for several more complete registrys. For a
   * versioned API wrapping access to common CCF properties, see @c
   * BaseEndpointRegistry. For implementation of several common endpoints see @c
   * CommonEndpointRegistry.
   */
  class EndpointRegistry : public Endpoint::Installer
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

    template <typename T>
    bool get_path_param(
      const ccf::PathParams& params,
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
      const ccf::PathParams& params,
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

    ccf::pal::Mutex metrics_lock;
    std::map<std::string, std::map<std::string, Metrics>> metrics;

    EndpointRegistry::Metrics& get_metrics_for_request(
      const std::string& method, const std::string& verb);

    kv::Consensus* consensus = nullptr;
    kv::TxHistory* history = nullptr;

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
     * ccf::EndpointDefinition::authn_policies
     * @return The new Endpoint for further modification
     */
    virtual Endpoint make_endpoint(
      const std::string& method,
      RESTVerb verb,
      const EndpointFunction& f,
      const AuthnPolicies& ap);

    /** Create a read-only endpoint.
     */
    virtual Endpoint make_read_only_endpoint(
      const std::string& method,
      RESTVerb verb,
      const ReadOnlyEndpointFunction& f,
      const AuthnPolicies& ap);

    /** Create a new endpoint with a commit handler.
     *
     * Like make_endpoint but takes a functor to call once the transaction has
     * been committed, but before consensus has completed.
     */
    virtual Endpoint make_endpoint_with_local_commit_handler(
      const std::string& method,
      RESTVerb verb,
      const EndpointFunction& f,
      const LocallyCommittedEndpointFunction& l,
      const AuthnPolicies& ap);

    /** See make_read_only_endpoint and make_endpoint_with_local_commit_handler.
     */
    virtual Endpoint make_read_only_endpoint_with_local_commit_handler(
      const std::string& method,
      RESTVerb verb,
      const ReadOnlyEndpointFunction& f,
      const LocallyCommittedEndpointFunction& l,
      const AuthnPolicies& ap);

    /** Create a new command endpoint.
     *
     * Commands are endpoints which do not read or write from the KV. See
     * make_endpoint().
     */
    virtual Endpoint make_command_endpoint(
      const std::string& method,
      RESTVerb verb,
      const CommandEndpointFunction& f,
      const AuthnPolicies& ap);

    /** Install the given endpoint, using its method and verb
     *
     * If an implementation is already installed for this method and verb, it
     * will be replaced.
     * @param endpoint Endpoint object describing the new resource to install
     */
    void install(Endpoint& endpoint) override;

    /** Set a default EndpointFunction
     *
     * The default EndpointFunction is only invoked if no specific
     * EndpointFunction was found.
     *
     * @param f Method implementation
     * @param ap Authentication policy
     */
    void set_default(EndpointFunction f, const AuthnPolicies& ap);

    /** Populate document with all supported methods
     *
     * This is virtual since derived classes may do their own dispatch
     * internally, so must be able to populate the document
     * with the supported endpoints however it defines them.
     */
    virtual void build_api(nlohmann::json& document, kv::ReadOnlyTx&);

    virtual void init_handlers();

    virtual EndpointDefinitionPtr find_endpoint(
      kv::Tx&, ccf::RpcContext& rpc_ctx);

    virtual void execute_endpoint(
      EndpointDefinitionPtr e, EndpointContext& args);

    virtual void execute_endpoint_locally_committed(
      EndpointDefinitionPtr e, CommandEndpointContext& args, const TxID& tx_id);

    virtual std::set<RESTVerb> get_allowed_verbs(
      kv::Tx&, const ccf::RpcContext& rpc_ctx);

    virtual void report_ambiguous_templated_path(
      const std::string& path,
      const std::vector<EndpointDefinitionPtr>& matches);

    virtual void tick(std::chrono::milliseconds);

    void set_consensus(kv::Consensus* c);

    void set_history(kv::TxHistory* h);

    virtual void increment_metrics_calls(const ccf::RpcContext& rpc_ctx);
    virtual void increment_metrics_errors(const ccf::RpcContext& rpc_ctx);
    virtual void increment_metrics_failures(const ccf::RpcContext& rpc_ctx);
    virtual void increment_metrics_retries(const ccf::RpcContext& rpc_ctx);
  };
}
