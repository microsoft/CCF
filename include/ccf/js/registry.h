// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

// CCF
#include "ccf/app_interface.h"
#include "ccf/endpoint.h"
#include "ccf/js/bundle.h"
#include "ccf/js/core/context.h"
#include "ccf/js/interpreter_cache_interface.h"
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
      ccfapp::AbstractNodeContext& context,
      const std::string& kv_prefix = "public:custom_endpoints");

    /**
     * Call this to populate the KV with JS endpoint definitions, so they can
     * later be dispatched to.
     */
    ccf::ApiResult install_custom_endpoints_v1(
      kv::Tx& tx, const ccf::js::Bundle& bundle);

    ccf::ApiResult get_custom_endpoints_v1(
      ccf::js::BundleWrapper& wrapper, kv::ReadOnlyTx& tx);

    ccf::ApiResult get_custom_endpoint_properties_v1(
      ccf::endpoints::EndpointProperties& properties,
      kv::ReadOnlyTx& tx,
      const ccf::RESTVerb& verb,
      const ccf::endpoints::URI& uri);

    ccf::ApiResult get_custom_endpoint_module_v1(
      std::string& code, kv::ReadOnlyTx& tx, const std::string& module_name);

    /// \defgroup Overrides for base EndpointRegistry functions, looking up JS
    /// endpoints before delegating to base implementation.
    ///@{
    ccf::endpoints::EndpointDefinitionPtr find_endpoint(
      kv::Tx& tx, ccf::RpcContext& rpc_ctx) override;

    void execute_endpoint(
      ccf::endpoints::EndpointDefinitionPtr e,
      ccf::endpoints::EndpointContext& endpoint_ctx) override;

    void execute_endpoint_locally_committed(
      ccf::endpoints::EndpointDefinitionPtr e,
      ccf::endpoints::CommandEndpointContext& endpoint_ctx,
      const ccf::TxID& tx_id) override;
    ///@}
  };
}
