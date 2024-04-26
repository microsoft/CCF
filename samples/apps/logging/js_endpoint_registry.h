// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ccf/app_interface.h"
#include "ccf/crypto/key_wrap.h"
#include "ccf/crypto/rsa_key_pair.h"
#include "ccf/endpoints/authentication/all_of_auth.h"
#include "ccf/historical_queries_adapter.h"
#include "ccf/node/host_processes_interface.h"
#include "ccf/version.h"
#include "enclave/enclave_time.h"
#include "js/context.h"
#include "js/interpreter_cache_interface.h"
#include "named_auth_policies.h"
#include "node/rpc/rpc_context_impl.h"
#include "service/tables/endpoints.h"

#include <memory>
#include <quickjs/quickjs-exports.h>
#include <quickjs/quickjs.h>
#include <stdexcept>
#include <vector>

// TODO: Should this be moved to ccf namespace, public header, for public reuse?
namespace loggingapp
{
  class JSEndpointRegistry : public UserEndpointRegistry
  {
  private:
    ccfapp::AbstractNodeContext& context;
    std::shared_ptr<ccf::js::AbstractInterpreterCache> interpreter_cache =
      nullptr;

    void execute_request(
      const ccf::js::JSDynamicEndpoint* endpoint,
      ccf::endpoints::EndpointContext& endpoint_ctx)
    {
      return;
    }

    using PreExecutionHook = std::function<void(js::Context&)>;

    void do_execute_request(
      const ccf::js::JSDynamicEndpoint* endpoint,
      ccf::endpoints::EndpointContext& endpoint_ctx,
      const std::optional<PreExecutionHook>& pre_exec_hook = std::nullopt)
    {}

  public:
    JSEndpointRegistry(AbstractNodeContext& context_) : context(context_) {}

    ccf::endpoints::EndpointDefinitionPtr find_endpoint(
      kv::Tx& tx, ccf::RpcContext& rpc_ctx) override
    {
      return nullptr;
    }

    void execute_endpoint(
      ccf::endpoints::EndpointDefinitionPtr e,
      ccf::endpoints::EndpointContext& endpoint_ctx) override
    {
      return;
    }

    // TODO: Override get_allowed_verbs
    // TODO: Override build_api
  };
} // namespace loggingapp
