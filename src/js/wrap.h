// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/historical_queries_interface.h"
#include "ccf/tx.h"
#include "ds/logger.h"
#include "kv/kv_types.h"

#include <memory>
#include <quickjs/quickjs-exports.h>
#include <quickjs/quickjs.h>

namespace js
{
  extern JSClassID kv_class_id;
  extern JSClassID kv_map_handle_class_id;
  extern JSClassID body_class_id;

  extern JSClassDef kv_class_def;
  extern JSClassExoticMethods kv_exotic_methods;
  extern JSClassDef kv_map_handle_class_def;
  extern JSClassDef body_class_def;

  enum class TxAccess
  {
    APP,
    GOV_RO,
    GOV_RW
  };

  struct TxContext
  {
    kv::Tx* tx = nullptr;
    TxAccess access = js::TxAccess::APP;
  };

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc99-extensions"

  void register_class_ids();
  void register_request_body_class(JSContext* ctx);
  void populate_global_console(JSContext* ctx);
  void populate_global_ccf(
    TxContext* txctx,
    const std::optional<ccf::TxID>& transaction_id,
    ccf::historical::TxReceiptPtr receipt,
    JSContext* ctx);

  JSValue js_print(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv);
  void js_dump_error(JSContext* ctx);

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

  class Runtime
  {
    JSRuntime* rt;

  public:
    inline Runtime(
      size_t max_stack_size = 1024 * 1024,
      size_t max_heap_size = 100 * 1024 * 1024)
    {
      rt = JS_NewRuntime();
      if (rt == nullptr)
      {
        throw std::runtime_error("Failed to initialise QuickJS runtime");
      }
      JS_SetMaxStackSize(rt, max_stack_size);
      JS_SetMemoryLimit(rt, max_heap_size);
    }

    inline ~Runtime()
    {
      JS_FreeRuntime(rt);
    }

    inline operator JSRuntime*() const
    {
      return rt;
    }

    void add_ccf_classdefs();
  };

  class Context
  {
    JSContext* ctx;

  public:
    inline Context(JSRuntime* rt)
    {
      ctx = JS_NewContext(rt);
      if (ctx == nullptr)
      {
        throw std::runtime_error("Failed to initialise QuickJS context");
      }
      JS_SetContextOpaque(ctx, this);
    }

    inline ~Context()
    {
      JS_FreeContext(ctx);
    }

    inline operator JSContext*() const
    {
      return ctx;
    }

    struct JSWrappedValue
    {
      inline JSWrappedValue(JSContext* ctx, JSValue&& val) :
        ctx(ctx),
        val(std::move(val))
      {}
      inline ~JSWrappedValue()
      {
        JS_FreeValue(ctx, val);
      }
      inline operator const JSValue&() const
      {
        return val;
      }
      JSContext* ctx;
      JSValue val;
    };

    struct JSWrappedCString
    {
      inline JSWrappedCString(JSContext* ctx, const char* cstr) :
        ctx(ctx),
        cstr(cstr)
      {}
      inline ~JSWrappedCString()
      {
        JS_FreeCString(ctx, cstr);
      }
      inline operator const char*() const
      {
        return cstr;
      }
      inline operator std::string() const
      {
        return std::string(cstr);
      }
      inline operator std::string_view() const
      {
        return std::string_view(cstr);
      }
      JSContext* ctx;
      const char* cstr;
    };

    inline JSWrappedValue operator()(JSValue&& val)
    {
      return JSWrappedValue(ctx, std::move(val));
    };

    inline JSWrappedCString operator()(const char* cstr)
    {
      return JSWrappedCString(ctx, cstr);
    };

    JSValue function(const std::string& code, const std::string& path);
    JSValue function(
      const std::string& code,
      const std::string& func,
      const std::string& path);
  };

#pragma clang diagnostic pop

}