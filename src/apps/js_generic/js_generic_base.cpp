// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "js_generic_base.h"

#include "ccf/js/registry.h"
#include "ccf/service/tables/jsengine.h"
#include "ccf/service/tables/modules.h"

namespace ccf
{
  class JSHandlers : public ccf::js::DynamicJSEndpointRegistry
  {
  public:
    JSHandlers(AbstractNodeContext& context) :
      // Note: We do not pass a kv_prefix here, instead we explicitly, manually
      // construct each map name to match previously used values
      ccf::js::DynamicJSEndpointRegistry(context)
    {
      modules_map = ccf::Tables::MODULES;
      metadata_map = ccf::endpoints::Tables::ENDPOINTS;
      interpreter_flush_map = ccf::Tables::INTERPRETER_FLUSH;
      modules_quickjs_version_map = ccf::Tables::MODULES_QUICKJS_VERSION;
      modules_quickjs_bytecode_map = ccf::Tables::MODULES_QUICKJS_BYTECODE;
      runtime_options_map = ccf::Tables::JSENGINE;

      // TODO: Refactor hierarchy to remove these from my visibility?
      recent_actions_map;
      audit_input_map;
      audit_info_map;
    }
  };

  std::unique_ptr<ccf::endpoints::EndpointRegistry> make_user_endpoints_impl(
    ccf::AbstractNodeContext& context)
  {
    return std::make_unique<JSHandlers>(context);
  }

} // namespace ccf
