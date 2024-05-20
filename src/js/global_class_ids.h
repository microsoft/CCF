// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <quickjs/quickjs.h>

namespace ccf::js
{
  extern JSClassID kv_class_id;
  extern JSClassID kv_historical_class_id;
  extern JSClassID kv_map_handle_class_id;
  extern JSClassID node_class_id;
  extern JSClassID network_class_id;
  extern JSClassID rpc_class_id;
  extern JSClassID host_class_id;
  extern JSClassID consensus_class_id;
  extern JSClassID historical_class_id;
  extern JSClassID historical_state_class_id;

  extern JSClassDef kv_class_def;
  extern JSClassDef kv_historical_class_def;
  extern JSClassDef kv_map_handle_class_def;
  extern JSClassDef kv_historical_map_handle_class_def;
  extern JSClassDef node_class_def;
  extern JSClassDef network_class_def;
  extern JSClassDef rpc_class_def;
  extern JSClassDef host_class_def;
  extern JSClassDef consensus_class_def;
  extern JSClassDef historical_class_def;
  extern JSClassDef historical_state_class_def;

  // Not thread-safe, must happen exactly once
  void register_class_ids();
}
