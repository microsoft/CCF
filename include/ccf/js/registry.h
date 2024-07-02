// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

// CCF
#include "ccf/app_interface.h"
#include "ccf/endpoint.h"
#include "ccf/js/audit_format.h"
#include "ccf/js/bundle.h"
#include "ccf/js/core/context.h"
#include "ccf/js/interpreter_cache_interface.h"
#include "ccf/js/namespace_restrictions.h"
#include "ccf/tx.h"
#include "ccf/tx_id.h"

#include <charconv>
#define FMT_HEADER_ONLY
#include <fmt/format.h>

namespace ccf::js
{
  struct CustomJSEndpoint : public ccf::endpoints::Endpoint
  {};

  // By subclassing DynamicJSEndpointRegistry, an application gains the
  // ability to execute custom JavaScript endpoints, and exposes the ability to
  // install them via install_custom_endpoints(). The JavaScript code for these
  // endpoints is stored in the internal KV store under a namespace configured
  // in the second argument to the constructor. Calling
  // install_custom_endpoints() is logically equivalent to passing a set_js_app
  // proposal in governance, and the payload format is currently identical,
  // except the controlling logic resides in the application space.
  //
  // Known limitations:
  //
  // No auditability yet, COSE Sign1 auth is recommended, but the signature is
  // not stored.
  // No support for historical endpoints yet.
  // No support for import from external modules.
  //
  // Additional functionality compared to set_js_app:
  //
  // The KV namespace can be private, to keep the application confidential if
  // desired.
  class DynamicJSEndpointRegistry : public ccf::UserEndpointRegistry
  {
  private:
    std::shared_ptr<ccf::js::AbstractInterpreterCache> interpreter_cache =
      nullptr;
    std::string modules_map;
    std::string metadata_map;
    std::string interpreter_flush_map;
    std::string modules_quickjs_version_map;
    std::string modules_quickjs_bytecode_map;
    std::string runtime_options_map;
    std::string recent_actions_map;
    std::string audit_input_map;
    std::string audit_info_map;

    ccf::js::NamespaceRestriction namespace_restriction;

    using PreExecutionHook = std::function<void(ccf::js::core::Context&)>;

    void do_execute_request(
      const CustomJSEndpoint* endpoint,
      ccf::endpoints::EndpointContext& endpoint_ctx,
      const std::optional<PreExecutionHook>& pre_exec_hook = std::nullopt);

    void execute_request(
      const CustomJSEndpoint* endpoint,
      ccf::endpoints::EndpointContext& endpoint_ctx);

    void execute_request_locally_committed(
      const CustomJSEndpoint* endpoint,
      ccf::endpoints::CommandEndpointContext& endpoint_ctx,
      const ccf::TxID& tx_id);

  public:
    DynamicJSEndpointRegistry(
      ccf::AbstractNodeContext& context,
      const std::string& kv_prefix = "public:custom_endpoints");

    /**
     * Call this to populate the KV with JS endpoint definitions, so they can
     * later be dispatched to.
     */
    ccf::ApiResult install_custom_endpoints_v1(
      ccf::kv::Tx& tx, const ccf::js::Bundle& bundle);

    /**
     * Retrieve all endpoint definitions currently in-use. This returns the same
     * bundle written by a recent call to install_custom_endpoints. Note that
     * some values (module paths, casing of HTTP methods) may differ slightly
     * due to internal normalisation.
     */
    ccf::ApiResult get_custom_endpoints_v1(
      ccf::js::Bundle& bundle, ccf::kv::ReadOnlyTx& tx);

    /**
     * Retrieve property definition for a single JS endpoint.
     */
    ccf::ApiResult get_custom_endpoint_properties_v1(
      ccf::endpoints::EndpointProperties& properties,
      ccf::kv::ReadOnlyTx& tx,
      const ccf::RESTVerb& verb,
      const ccf::endpoints::URI& uri);

    /**
     * Retrieve content of a single JS module.
     */
    ccf::ApiResult get_custom_endpoint_module_v1(
      std::string& code,
      ccf::kv::ReadOnlyTx& tx,
      const std::string& module_name);

    /**
     * Pass a function to control which maps can be accessed by JS endpoints.
     */
    void set_js_kv_namespace_restriction(
      const ccf::js::NamespaceRestriction& restriction);

    /**
     * Set options to control JS execution. Some hard limits may be applied to
     * bound any values specified here.
     */
    ccf::ApiResult set_js_runtime_options_v1(
      ccf::kv::Tx& tx, const ccf::JSRuntimeOptions& options);

    /**
     * Get the options which currently control JS execution. If no value has
     * been populated in the KV, this will return the default runtime options
     * which will be applied instead.
     */
    ccf::ApiResult get_js_runtime_options_v1(
      ccf::JSRuntimeOptions& options, ccf::kv::ReadOnlyTx& tx);

    /**
     * Record action details by storing them in KV maps using a common format,
     * for the purposes of offline audit using the ledger.
     */
    ccf::ApiResult record_action_for_audit_v1(
      ccf::kv::Tx& tx,
      ccf::ActionFormat format,
      const std::string& user_id,
      const std::string& action_name,
      const std::vector<uint8_t>& action_body);

    /**
     * Check an action is not being replayed, by looking it up
     * in the history of recent actions. To place an upper bound on the history
     * size, an authenticated timestamp (@p created_at) is required.
     */
    ccf::ApiResult check_action_not_replayed_v1(
      ccf::kv::Tx& tx,
      uint64_t created_at,
      const std::span<const uint8_t> action,
      ccf::InvalidArgsReason& reason);

    /// \defgroup Overrides for base EndpointRegistry functions, looking up JS
    /// endpoints before delegating to base implementation.
    ///@{
    ccf::endpoints::EndpointDefinitionPtr find_endpoint(
      ccf::kv::Tx& tx, ccf::RpcContext& rpc_ctx) override;

    void execute_endpoint(
      ccf::endpoints::EndpointDefinitionPtr e,
      ccf::endpoints::EndpointContext& endpoint_ctx) override;

    void execute_endpoint_locally_committed(
      ccf::endpoints::EndpointDefinitionPtr e,
      ccf::endpoints::CommandEndpointContext& endpoint_ctx,
      const ccf::TxID& tx_id) override;

    void build_api(nlohmann::json& document, ccf::kv::ReadOnlyTx& tx) override;
    ///@}

    virtual ccf::js::extensions::Extensions get_extensions(
      const ccf::endpoints::EndpointContext& endpoint_ctx)
    {
      return {};
    };
  };
}
