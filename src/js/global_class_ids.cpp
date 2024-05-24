// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "js/global_class_ids.h"

#include "js/core/context.h"

namespace ccf::js
{
  JSClassID kv_class_id = 0;
  JSClassID kv_historical_class_id = 0;
  JSClassID kv_map_handle_class_id = 0;
  JSClassID historical_state_class_id = 0;

  JSClassDef kv_map_handle_class_def = {};

  void register_class_ids()
  {
    JS_NewClassID(&kv_class_id);

    JS_NewClassID(&kv_historical_class_id);

    JS_NewClassID(&kv_map_handle_class_id);
    kv_map_handle_class_def.class_name = "KV Map Handle";
  }
}
