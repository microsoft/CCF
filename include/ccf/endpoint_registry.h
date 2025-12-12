// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json_schema.h"
#include "ccf/endpoint.h"
#include "ccf/endpoint_context.h"
#include "ccf/rpc_context.h"
#include "ccf/tx.h"

#include <charconv>
#include <functional>
#include <llhttp/llhttp.h>
#include <nlohmann/json.hpp>
#include <regex>
#include <set>

namespace ccf::kv
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

  struct RequestCompletedEvent
  {
    std::string method;
    // This contains the path template against which the request matched. For
    // instance `/user/{user_id}` rather than `/user/Bob`. This should be safe
    // to log, though doing so still reveals (to anyone with stdout access)
    // exactly which endpoints were executed and when.
    std::string dispatch_path;
    int status = 0;
    std::chrono::milliseconds exec_time{0};
    size_t attempts = 0;
  };

  struct DispatchFailedEvent
  {
    std::string method;
    int status = 0;
  };

  void default_locally_committed_func(
    CommandEndpointContext& ctx, const TxID& tx_id);

  void default_respond_on_commit_func(
    std::shared_ptr<ccf::RpcContext> rpc_ctx,
    const TxID& tx_id,
    ccf::FinalTxStatus status);

  template <typename T>
  inline bool get_path_param(
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
  inline bool get_path_param(
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
    enum class ReadWrite : uint8_t
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

    template <typename T>
    bool get_path_param(
      const ccf::PathParams& params,
      const std::string& param_name,
      T& value,
      std::string& error)
    {
      return ccf::endpoints::get_path_param<T>(
        params, param_name, value, error);
    }

    template <>
    bool get_path_param(
      const ccf::PathParams& params,
      const std::string& param_name,
      std::string& value,
      std::string& error)
    {
      return ccf::endpoints::get_path_param(params, param_name, value, error);
    }

  protected:
    EndpointPtr default_endpoint;
    std::map<std::string, std::map<RESTVerb, EndpointPtr>>
      fully_qualified_endpoints;
    std::map<
      std::string,
      std::map<RESTVerb, std::shared_ptr<PathTemplatedEndpoint>>>
      templated_endpoints;

    ccf::kv::Consensus* consensus = nullptr;
    ccf::kv::TxHistory* history = nullptr;

  public:
    EndpointRegistry(std::string method_prefix_) :
      method_prefix(std::move(method_prefix_))
    {}

    ~EndpointRegistry() override = default;

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
    virtual void build_api(
      nlohmann::json& document, [[maybe_unused]] ccf::kv::ReadOnlyTx& tx);

    virtual void init_handlers();

    virtual EndpointDefinitionPtr find_endpoint(
      [[maybe_unused]] ccf::kv::Tx& tx, ccf::RpcContext& rpc_ctx);

    virtual void execute_endpoint(
      EndpointDefinitionPtr e, EndpointContext& ctx);

    virtual void execute_endpoint_locally_committed(
      EndpointDefinitionPtr e, CommandEndpointContext& ctx, const TxID& tx_id);

    virtual std::set<RESTVerb> get_allowed_verbs(
      [[maybe_unused]] ccf::kv::Tx& tx, const ccf::RpcContext& rpc_ctx);

    virtual bool request_needs_root(const ccf::RpcContext& rpc_ctx);

    virtual void report_ambiguous_templated_path(
      const std::string& path,
      const std::vector<EndpointDefinitionPtr>& matches);

    virtual void tick([[maybe_unused]] std::chrono::milliseconds duration);

    void set_consensus(ccf::kv::Consensus* c);

    void set_history(ccf::kv::TxHistory* h);

    // Override these methods to log or report request metrics.
    virtual void handle_event_request_completed(
      const ccf::endpoints::RequestCompletedEvent& event)
    {}

    virtual void handle_event_dispatch_failed(
      const ccf::endpoints::DispatchFailedEvent& event)
    {}

    [[nodiscard]] virtual bool apply_uncommitted_tx_backpressure() const
    {
      return true;
    }
  };
}
