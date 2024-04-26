// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <quickjs/quickjs.h>

namespace ccf::js
{
  static JSClassID kv_class_id = 0;
  static JSClassID kv_historical_class_id = 0;
  static JSClassID kv_map_handle_class_id = 0;
  static JSClassID body_class_id = 0;
  static JSClassID node_class_id = 0;
  static JSClassID network_class_id = 0;
  static JSClassID rpc_class_id = 0;
  static JSClassID host_class_id = 0;
  static JSClassID consensus_class_id = 0;
  static JSClassID historical_class_id = 0;
  static JSClassID historical_state_class_id = 0;

  static JSClassDef kv_class_def = {};
  static JSClassExoticMethods kv_exotic_methods = {};
  static JSClassDef kv_historical_class_def = {};
  static JSClassExoticMethods kv_historical_exotic_methods = {};
  static JSClassDef kv_map_handle_class_def = {};
  static JSClassDef kv_historical_map_handle_class_def = {};
  static JSClassDef body_class_def = {};
  static JSClassDef node_class_def = {};
  static JSClassDef network_class_def = {};
  static JSClassDef rpc_class_def = {};
  static JSClassDef host_class_def = {};
  static JSClassDef consensus_class_def = {};
  static JSClassDef historical_class_def = {};
  static JSClassDef historical_state_class_def = {};

  // Not thread-safe, must happen exactly once
  void register_class_ids();
}
