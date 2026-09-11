// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "js/global_class_ids.h"

#include "ccf/js/core/context.h"
#include "js/extensions/ccf/kv_map_handle_state.h"

namespace ccf::js
{
  JSClassID kv_class_id = 0;
  JSClassID kv_historical_class_id = 0;
  JSClassID kv_map_handle_class_id = 0;
  JSClassID historical_state_class_id = 0;

  JSClassDef kv_map_handle_class_def = {};

  namespace
  {
    void kv_map_handle_finalizer([[maybe_unused]] JSRuntime* rt, JSValue val)
    {
      auto* state = static_cast<extensions::kvhelpers::KVMapHandleState*>(
        JS_GetOpaque(val, kv_map_handle_class_id));
      // Ownership was transferred to this object by JS_SetOpaque, so it must be
      // released by hand here. A smart pointer cannot be used, since QuickJS
      // stores the raw pointer.
      delete state; // NOLINT(cppcoreguidelines-owning-memory)
    }
  }

  void register_class_ids()
  {
    JS_NewClassID(&kv_class_id);

    JS_NewClassID(&kv_historical_class_id);

    JS_NewClassID(&kv_map_handle_class_id);
    kv_map_handle_class_def.class_name = "KV Map Handle";
    kv_map_handle_class_def.finalizer = kv_map_handle_finalizer;
  }
}
