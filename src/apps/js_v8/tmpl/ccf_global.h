// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "v8.h"
#include "kv_store.h"
#include "ccf/historical_queries_interface.h"
#include "ccf/base_endpoint_registry.h"

namespace ccf::v8_tmpl
{
  class CCFGlobal
  {
  public:
    static constexpr const char* NAME = "CCF";
    static v8::Local<v8::ObjectTemplate> create_template(v8::Isolate* isolate);

    static v8::Local<v8::Object> wrap(
      v8::Local<v8::Context> context,
      TxContext& tx_ctx,
      ccf::historical::StatePtr& historical_state,
      ccf::BaseEndpointRegistry* endpoint_registry,
      ccf::historical::AbstractStateCache* state_cache);
  };

} // namespace ccf::v8_tmpl
