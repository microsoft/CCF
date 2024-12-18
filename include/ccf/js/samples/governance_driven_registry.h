// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ccf/js/registry.h"
#include "ccf/service/tables/jsengine.h"
#include "ccf/service/tables/modules.h"

namespace ccf::js
{
  // This sample extends the generic BaseDynamicJSEndpointRegistry to read JS
  // endpoints (code, metadata, options) from governance tables. Specifically,
  // tables populated by actions in the default sample CCF constitution
  // (set_js_app). This can be sub-classed to modify the dispatch or execution
  // behaviour, or to provide further JS extension APIs via get_extensions().
  //
  // An application running this registry with no further extensions is shipped
  // with the CCF releases as `js_generic`.
  class GovernanceDrivenJSRegistry
    : public ccf::js::BaseDynamicJSEndpointRegistry
  {
  public:
    GovernanceDrivenJSRegistry(AbstractNodeContext& context) :
      // Note: We do not pass a kv_prefix here, instead we explicitly, manually
      // construct each map name to match previously used values
      ccf::js::BaseDynamicJSEndpointRegistry(context)
    {
      modules_map = ccf::Tables::MODULES;
      metadata_map = ccf::endpoints::Tables::ENDPOINTS;
      interpreter_flush_map = ccf::Tables::INTERPRETER_FLUSH;
      modules_quickjs_version_map = ccf::Tables::MODULES_QUICKJS_VERSION;
      modules_quickjs_bytecode_map = ccf::Tables::MODULES_QUICKJS_BYTECODE;
      runtime_options_map = ccf::Tables::JSENGINE;
    }
  };
} // namespace ccf::js
