// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ds/logger.h"

#include <memory>
#include <quickjs/quickjs-exports.h>
#include <quickjs/quickjs.h>

namespace js
{
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc99-extensions"

  static JSValue js_print(
    JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
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

  class JSAutoFreeRuntime
  {
    JSRuntime* rt;

  public:
    JSAutoFreeRuntime()
    {
      rt = JS_NewRuntime();
      if (rt == nullptr)
      {
        throw std::runtime_error("Failed to initialise QuickJS runtime");
      }
    }

    ~JSAutoFreeRuntime()
    {
      JS_FreeRuntime(rt);
    }

    operator JSRuntime*() const
    {
      return rt;
    }
  };

  class JSAutoFreeCtx
  {
    JSContext* ctx;

  public:
    JSAutoFreeCtx(JSRuntime* rt)
    {
      ctx = JS_NewContext(rt);
      if (ctx == nullptr)
      {
        throw std::runtime_error("Failed to initialise QuickJS context");
      }
      JS_SetContextOpaque(ctx, this);
    }

    ~JSAutoFreeCtx()
    {
      JS_FreeContext(ctx);
    }

    operator JSContext*() const
    {
      return ctx;
    }

    struct JSWrappedValue
    {
      JSWrappedValue(JSContext* ctx, JSValue&& val) :
        ctx(ctx),
        val(std::move(val))
      {}
      ~JSWrappedValue()
      {
        JS_FreeValue(ctx, val);
      }
      operator const JSValue&() const
      {
        return val;
      }
      JSContext* ctx;
      JSValue val;
    };

    struct JSWrappedCString
    {
      JSWrappedCString(JSContext* ctx, const char* cstr) : ctx(ctx), cstr(cstr)
      {}
      ~JSWrappedCString()
      {
        JS_FreeCString(ctx, cstr);
      }
      operator const char*() const
      {
        return cstr;
      }
      operator std::string() const
      {
        return std::string(cstr);
      }
      operator std::string_view() const
      {
        return std::string_view(cstr);
      }
      JSContext* ctx;
      const char* cstr;
    };

    JSWrappedValue operator()(JSValue&& val)
    {
      return JSWrappedValue(ctx, std::move(val));
    };

    JSWrappedCString operator()(const char* cstr)
    {
      return JSWrappedCString(ctx, cstr);
    };
  };

#pragma clang diagnostic pop

}