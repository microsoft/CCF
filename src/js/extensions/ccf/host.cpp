// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/js/extensions/ccf/host.h"

#include "ccf/js/core/context.h"

#include <quickjs/quickjs.h>

namespace ccf::js::extensions
{
  namespace
  {
    JSValue js_node_trigger_host_process_launch(
      JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
    {
      (void)this_val;

      js::core::Context& jsctx =
        *reinterpret_cast<js::core::Context*>(JS_GetContextOpaque(ctx));

      if (argc != 1 && argc != 2)
      {
        return JS_ThrowTypeError(
          ctx, "Passed %d arguments but expected 1 or 2", argc);
      }

      std::vector<std::string> process_args;
      std::vector<uint8_t> process_input;

      JSValue r = jsctx.extract_string_array(argv[0], process_args);
      if (JS_IsUndefined(r) == 0)
      {
        return r;
      }

      if (argc == 2)
      {
        size_t size = 0;
        uint8_t* buf = JS_GetArrayBuffer(ctx, &size, argv[1]);
        if (buf == nullptr)
        {
          return JS_ThrowTypeError(ctx, "Argument must be an ArrayBuffer");
        }
        process_input.assign(buf, buf + size);
      }

      auto* extension = jsctx.get_extension<HostExtension>();
      if (extension == nullptr)
      {
        return JS_ThrowInternalError(ctx, "Failed to get extension object");
      }

      auto* host_processes = extension->host_processes;
      if (host_processes == nullptr)
      {
        return JS_ThrowInternalError(
          ctx, "Failed to get host processes object");
      }

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

      return ccf::js::core::constants::Undefined;
    }
  }

  void HostExtension::install(js::core::Context& ctx)
  {
    auto host = JS_NewObject(ctx);

    JS_SetPropertyStr(
      ctx,
      host,
      "triggerSubprocess",
      JS_NewCFunction(
        ctx, js_node_trigger_host_process_launch, "triggerSubprocess", 1));

    auto ccf = ctx.get_or_create_global_property("ccf", ctx.new_obj());
    // NOLINTBEGIN(performance-move-const-arg)
    ccf.set("host", std::move(host));
    // NOLINTEND(performance-move-const-arg)
  }
}
