// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "./checks.h"
#include "./constants.h"
#include "./wrapped_value.h"
#include "ccf/base_endpoint_registry.h"
#include "ccf/ds/logger.h"
#include "ccf/historical_queries_interface.h"
#include "ccf/js_plugin.h"
#include "ccf/node/host_processes_interface.h"
#include "ccf/rpc_context.h"
#include "ccf/tx.h"
#include "kv/kv_types.h"
#include "node/network_state.h"
#include "node/rpc/gov_effects_interface.h"
#include "node/rpc/node_interface.h"

#include <memory>
#include <quickjs/quickjs-exports.h>
#include <quickjs/quickjs.h>

namespace ccf::js
{
  class Context;

  void register_request_body_class(JSContext* ctx);

  // TODO: Why aren't these all members?

  JSValue js_body_text(
    JSContext* ctx,
    JSValueConst this_val,
    int argc,
    [[maybe_unused]] JSValueConst* argv);

  JSValue js_body_json(
    JSContext* ctx,
    JSValueConst this_val,
    int argc,
    [[maybe_unused]] JSValueConst* argv);

  JSValue js_body_array_buffer(
    JSContext* ctx,
    JSValueConst this_val,
    int argc,
    [[maybe_unused]] JSValueConst* argv);
}
