// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "ccf/node/host_processes_interface.h"
#include "js/context.h"
#include "js/global_class_ids.h"

#include <quickjs/quickjs.h>

namespace ccf::js
{
  namespace
  {
    JSValue js_node_trigger_host_process_launch(
      JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
    {
      js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

      if (argc != 1 && argc != 2)
      {
        return JS_ThrowTypeError(
          ctx, "Passed %d arguments but expected 1 or 2", argc);
      }

      std::vector<std::string> process_args;
      std::vector<uint8_t> process_input;

      JSValue r = jsctx.get_string_array(argv[0], process_args);
      if (!JS_IsUndefined(r))
      {
        return r;
      }

      if (argc == 2)
      {
        size_t size;
        uint8_t* buf = JS_GetArrayBuffer(ctx, &size, argv[1]);
        if (!buf)
        {
          return JS_ThrowTypeError(ctx, "Argument must be an ArrayBuffer");
        }
        process_input.assign(buf, buf + size);
      }

      auto host_processes = static_cast<ccf::AbstractHostProcesses*>(
        JS_GetOpaque(this_val, host_class_id));

      try
      {
        host_processes->trigger_host_process_launch(
          process_args, process_input);
      }
      catch (const std::exception& e)
      {
        return JS_ThrowInternalError(
          ctx, "Unable to launch host process: %s", e.what());
      }

      return ccf::js::constants::Undefined;
    }
  }

  JSValue create_global_host_object(
    ccf::AbstractHostProcesses* host_processes, JSContext* ctx)
  {
    auto host = JS_NewObjectClass(ctx, host_class_id);
    JS_SetOpaque(host, host_processes);

    JS_SetPropertyStr(
      ctx,
      host,
      "triggerSubprocess",
      JS_NewCFunction(
        ctx, js_node_trigger_host_process_launch, "triggerSubprocess", 1));

    return host;
  }
}
