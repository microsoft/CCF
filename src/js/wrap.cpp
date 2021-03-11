// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "js/wrap.h"

#include "ds/logger.h"

#include <memory>
#include <quickjs/quickjs-exports.h>
#include <quickjs/quickjs.h>

namespace js
{
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc99-extensions"

  JSValue js_print(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
  {
    int i;
    const char* str;
    std::stringstream ss;

    for (i = 0; i < argc; i++)
    {
      if (i != 0)
        ss << ' ';
      if (!JS_IsError(ctx, argv[i]) && JS_IsObject(argv[i]))
      {
        JSValue rval = JS_JSONStringify(ctx, argv[i], JS_NULL, JS_NULL);
        str = JS_ToCString(ctx, rval);
        JS_FreeValue(ctx, rval);
      }
      else
        str = JS_ToCString(ctx, argv[i]);
      if (!str)
        return JS_EXCEPTION;
      ss << str;
      JS_FreeCString(ctx, str);
    }
    LOG_INFO << ss.str() << std::endl;
    return JS_UNDEFINED;
  }

  void js_dump_error(JSContext* ctx)
  {
    JSValue exception_val = JS_GetException(ctx);

    JSValue val;
    const char* stack;
    bool is_error;

    is_error = JS_IsError(ctx, exception_val);
    if (!is_error)
      LOG_INFO_FMT("Throw: ");
    js_print(ctx, JS_NULL, 1, (JSValueConst*)&exception_val);
    if (is_error)
    {
      val = JS_GetPropertyStr(ctx, exception_val, "stack");
      if (!JS_IsUndefined(val))
      {
        stack = JS_ToCString(ctx, val);
        LOG_INFO_FMT("{}", stack);

        JS_FreeCString(ctx, stack);
      }
      JS_FreeValue(ctx, val);
    }

    JS_FreeValue(ctx, exception_val);
  }

  JSValue Context::function(const std::string& code, const std::string& path)
  {
    JSValue module = JS_Eval(
      ctx,
      code.c_str(),
      code.size(),
      path.c_str(),
      JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_COMPILE_ONLY);

    if (JS_IsException(module))
    {
      js::js_dump_error(ctx);
      throw std::runtime_error(fmt::format("Failed to compile {}", path));
    }

    auto eval_val = JS_EvalFunction(ctx, module);
    if (JS_IsException(eval_val))
    {
      js::js_dump_error(ctx);
      JS_FreeValue(ctx, eval_val);
      throw std::runtime_error(fmt::format("Failed to execute {}", path));
    }
    JS_FreeValue(ctx, eval_val);

    // Get exported function from module
    assert(JS_VALUE_GET_TAG(module) == JS_TAG_MODULE);
    auto module_def = (JSModuleDef*)JS_VALUE_GET_PTR(module);
    if (JS_GetModuleExportEntriesCount(module_def) != 1)
    {
      throw std::runtime_error(
        "Endpoint module exports more than one function");
    }

    auto export_func = JS_GetModuleExportEntry(ctx, module_def, 0);
    if (!JS_IsFunction(ctx, export_func))
    {
      JS_FreeValue(ctx, export_func);
      throw std::runtime_error(
        "Endpoint module exports something that is not a function");
    }

    return export_func;
  }

#pragma clang diagnostic pop

}