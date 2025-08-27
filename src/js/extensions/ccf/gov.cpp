// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/js/extensions/ccf/gov.h"

#include "ccf/js/core/context.h"

#include <iostream>
#include <quickjs/quickjs.h>

namespace ccf::js::extensions
{
  namespace
  {
    JSValue js_validate_constitution(
      JSContext* ctx,
      [[maybe_unused]] JSValueConst this_val,
      int argc,
      JSValueConst* argv)
    {
      js::core::Context& jsctx =
        *reinterpret_cast<js::core::Context*>(JS_GetContextOpaque(ctx));

      if (argc != 1)
      {
        return JS_ThrowTypeError(
          ctx, "Passed %d arguments, but expected 1", argc);
      }

      auto constitution = jsctx.to_str(argv[0]);
      if (!JS_IsString(argv[0]) || !constitution.has_value())
      {
        return JS_ThrowTypeError(ctx, "constitution is not a string");
      }

      if (constitution->size() == 0)
      {
        return JS_ThrowTypeError(ctx, "constitution is empty");
      }

      const auto path = "proposed constitution";

      for (const auto& fn_name : {"validate", "apply", "resolve"})
      {
        try
        {
          // Create a new context to lookup this function, since doing so
          // requires evaluating the model, and that must have no side effects
          // or write to the parent's global environment.
          ccf::js::core::Context sub_context(ccf::js::TxAccess::GOV_RO);
          sub_context.get_exported_function(
            constitution.value(), fn_name, path);
        }
        catch (const std::exception& e)
        {
          return JS_ThrowTypeError(
            ctx, "Did not find function %s in %s: %s", fn_name, path, e.what());
        }
      }

      return ccf::js::core::constants::True;
    }
  }

  void GovExtension::install(js::core::Context& ctx)
  {
    auto gov = JS_NewObject(ctx);

    JS_SetPropertyStr(
      ctx,
      gov,
      "validateConstitution",
      JS_NewCFunction(
        ctx, js_validate_constitution, "validateConstitution", 1));

    auto ccf = ctx.get_or_create_global_property("ccf", ctx.new_obj());
    ccf.set("gov", std::move(gov));
  }
}
