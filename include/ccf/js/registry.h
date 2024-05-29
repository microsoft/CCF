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
    void install_custom_endpoints(
      ccf::endpoints::EndpointContext& ctx,
      const ccf::js::BundleWrapper& wrapper);

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
