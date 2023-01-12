// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

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
  extern JSClassID kv_class_id;
  extern JSClassID kv_read_only_class_id;
  extern JSClassID kv_map_handle_class_id;
  extern JSClassID body_class_id;
  extern JSClassID node_class_id;
  extern JSClassID network_class_id;
  extern JSClassID consensus_class_id;
  extern JSClassID historical_class_id;
  extern JSClassID historical_state_class_id;

  extern JSClassDef kv_class_def;
  extern JSClassExoticMethods kv_exotic_methods;
  extern JSClassDef kv_read_only_class_def;
  extern JSClassExoticMethods kv_read_only_exotic_methods;
  extern JSClassDef kv_map_handle_class_def;
  extern JSClassDef body_class_def;
  extern JSClassDef node_class_def;
  extern JSClassDef network_class_def;

  const std::chrono::milliseconds default_max_execution_time{1000};
  const size_t default_stack_size = 1024 * 1024;
  const size_t default_heap_size = 100 * 1024 * 1024;

  /// Describes the context in which JS script is currently executing. Used to
  /// determine which KV tables should be accessible.
  enum class TxAccess
  {
    /// Application code, during evaluation of an endpoint handler function
    APP,

    /// Read-only governance execution, during evaluation of ballots, and of the
    /// 'validate' and 'resolve' functions in the constitution
    GOV_RO,

    /// Read-write governance execution, during evaluation of the 'apply'
    /// function in the constitution
    GOV_RW
  };

  struct TxContext
  {
    kv::Tx* tx = nullptr;
  };

  struct ReadOnlyTxContext
  {
    kv::ReadOnlyTx* tx = nullptr;
  };

  struct HistoricalStateContext
  {
    ccf::historical::StatePtr state;
    kv::ReadOnlyTx tx;
    ReadOnlyTxContext tx_ctx;
  };

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc99-extensions"

  class Context;

  struct JSWrappedValue
  {
    JSWrappedValue() : ctx(NULL), val(JS_NULL) {}
    JSWrappedValue(JSContext* ctx, JSValue&& val) :
      ctx(ctx),
      val(std::move(val))
    {}
    JSWrappedValue(JSContext* ctx, const JSValue& value) : ctx(ctx)
    {
      val = JS_DupValue(ctx, value);
    }
    JSWrappedValue(const JSWrappedValue& other) : ctx(other.ctx)
    {
      val = JS_DupValue(ctx, other.val);
    }
    JSWrappedValue(JSWrappedValue&& other) : ctx(other.ctx)
    {
      val = other.val;
      other.val = JS_NULL;
    }
    ~JSWrappedValue()
    {
      if (ctx && JS_VALUE_GET_TAG(val) != JS_TAG_MODULE)
      {
        JS_FreeValue(ctx, val);
      }
    }

    operator const JSValue&() const
    {
      return val;
    }

    JSWrappedValue& operator=(const JSWrappedValue& other)
    {
      ctx = other.ctx;
      val = JS_DupValue(ctx, other.val);
      return *this;
    }

    JSWrappedValue operator[](const char* prop) const
    {
      return JSWrappedValue(ctx, JS_GetPropertyStr(ctx, val, prop));
    }

    JSWrappedValue operator[](const std::string& prop) const
    {
      return (*this)[prop.c_str()];
    }

    JSWrappedValue operator[](uint32_t i) const
    {
      return JSWrappedValue(ctx, JS_GetPropertyUint32(ctx, val, i));
    }

    JSWrappedValue get_property(JSAtom prop) const
    {
      return JSWrappedValue(ctx, JS_GetProperty(ctx, val, prop));
    }

    void set(const char* prop, const JSWrappedValue& value) const
    {
      JS_SetPropertyStr(ctx, val, prop, JS_DupValue(ctx, value.val));
    }

    void set(const char* prop, JSWrappedValue&& value) const
    {
      JS_SetPropertyStr(ctx, val, prop, value.val);
      value.val = JS_NULL;
    }

    void set(const std::string& prop, const JSWrappedValue& value) const
    {
      set(prop.c_str(), value);
    }

    void set(const std::string& prop, JSWrappedValue&& value) const
    {
      set(prop.c_str(), value);
    }

    void set(const std::string& prop, JSValue&& value) const
    {
      JS_SetPropertyStr(ctx, val, prop.c_str(), value);
    }

    void set(const std::string& prop, const JSValue& value) const
    {
      JS_SetPropertyStr(ctx, val, prop.c_str(), JS_DupValue(ctx, value));
    }

    JSValue take()
    {
      JSValue r = val;
      val = JS_NULL;
      return r;
    }

    JSContext* ctx;
    JSValue val;
  };

  void register_ffi_plugins(const std::vector<ccf::js::FFIPlugin>& plugins);
  void register_class_ids();
  void register_request_body_class(JSContext* ctx);
  void populate_global(
    TxContext* txctx,
    ReadOnlyTxContext* historical_txctx,
    ccf::RpcContext* rpc_ctx,
    const std::optional<ccf::TxID>& transaction_id,
    ccf::TxReceiptImplPtr receipt,
    ccf::AbstractGovernanceEffects* gov_effects,
    ccf::AbstractHostProcesses* host_processes,
    ccf::NetworkState* network_state,
    ccf::historical::AbstractStateCache* historical_state,
    ccf::BaseEndpointRegistry* endpoint_registry,
    Context& ctx);

  JSValue js_print(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv);
  void js_dump_error(JSContext* ctx);
  std::pair<std::string, std::optional<std::string>> js_error_message(
    Context& ctx);

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

  JSModuleDef* js_app_module_loader(
    JSContext* ctx, const char* module_name, void* opaque);

  JSWrappedValue load_app_module(
    JSContext* ctx, const char* module_name, kv::Tx* tx);

  struct UntrustedHostTime
  {
    std::chrono::microseconds start_time;
    std::chrono::milliseconds max_execution_time;
    bool request_timed_out = false;
  };

  class Runtime
  {
    JSRuntime* rt = nullptr;

  public:
    Runtime(kv::Tx* tx);
    ~Runtime();

    operator JSRuntime*() const
    {
      return rt;
    }

    void add_ccf_classdefs();
  };

  class Context
  {
    JSContext* ctx;

  public:
    const TxAccess access;
    UntrustedHostTime host_time;

    Context(JSRuntime* rt, TxAccess acc) : access(acc)
    {
      ctx = JS_NewContext(rt);
      if (ctx == nullptr)
      {
        throw std::runtime_error("Failed to initialise QuickJS context");
      }
      JS_SetContextOpaque(ctx, this);
    }

    ~Context()
    {
      JS_SetInterruptHandler(JS_GetRuntime(ctx), NULL, NULL);
      JS_FreeContext(ctx);
    }

    operator JSContext*() const
    {
      return ctx;
    }

    JSWrappedValue operator()(JSValue&& val) const
    {
      return W(std::move(val));
    };

    JSWrappedValue new_obj() const
    {
      return W(JS_NewObject(ctx));
    }

    JSWrappedValue new_obj_class(JSClassID class_id) const
    {
      return W(JS_NewObjectClass(ctx, class_id));
    }

    JSWrappedValue get_global_obj() const
    {
      return W(JS_GetGlobalObject(ctx));
    }

    JSWrappedValue stringify(
      const JSWrappedValue& obj,
      const JSWrappedValue& replacer,
      const JSWrappedValue& space0) const
    {
      return W(JS_JSONStringify(ctx, obj, replacer, space0));
    }

    JSWrappedValue json_stringify(const JSWrappedValue& obj) const
    {
      return W(JS_JSONStringify(ctx, obj, JS_NULL, JS_NULL));
    }

    JSWrappedValue new_array() const
    {
      return W(JS_NewArray(ctx));
    }

    JSWrappedValue new_array_buffer(
      uint8_t* buf,
      size_t len,
      JSFreeArrayBufferDataFunc* free_func,
      void* opaque,
      bool is_shared) const
    {
      return JSWrappedValue(
        ctx,
        JS_NewArrayBuffer(
          ctx, (uint8_t*)buf, len, free_func, opaque, is_shared));
    }

    JSWrappedValue new_array_buffer_copy(
      const uint8_t* buf, size_t buf_len) const
    {
      return JSWrappedValue(ctx, JS_NewArrayBufferCopy(ctx, buf, buf_len));
    }

    JSWrappedValue new_array_buffer_copy(const char* buf, size_t buf_len) const
    {
      return JSWrappedValue(
        ctx, JS_NewArrayBufferCopy(ctx, (uint8_t*)buf, buf_len));
    }

    JSWrappedValue new_string(const char* str) const
    {
      return W(JS_NewString(ctx, str));
    }

    JSWrappedValue new_string_len(const char* buf, size_t buf_len) const
    {
      return W(JS_NewStringLen(ctx, buf, buf_len));
    }

    JSWrappedValue new_type_error(const char* fmt, ...) const
    {
      va_list ap;
      va_start(ap, fmt);
      auto r = W(JS_ThrowTypeError(ctx, fmt, ap));
      va_end(ap);
      return r;
    }

    JSWrappedValue new_tag_value(int tag, int32_t val = 0) const
    {
      return W((JSValue){(JSValueUnion){.int32 = val}, tag});
    }

    JSWrappedValue null() const
    {
      return W(JS_NULL);
    }

    JSWrappedValue undefined() const
    {
      return W(JS_UNDEFINED);
    }

    JSWrappedValue new_c_function(
      JSCFunction* func, const char* name, int length) const
    {
      return W(JS_NewCFunction(ctx, func, name, length));
    }

    JSWrappedValue eval(
      const char* input,
      size_t input_len,
      const char* filename,
      int eval_flags) const
    {
      return W(JS_Eval(ctx, input, input_len, filename, eval_flags));
    }

    JSWrappedValue eval_function(const JSWrappedValue& module) const
    {
      return W(JS_EvalFunction(ctx, module));
    }

    JSWrappedValue default_function(
      const std::string& code, const std::string& path);

    JSWrappedValue function(
      const std::string& code,
      const std::string& func,
      const std::string& path);

    JSWrappedValue function(
      const JSWrappedValue& module,
      const std::string& func,
      const std::string& path);

    JSWrappedValue get_module_export_entry(JSModuleDef* m, int idx) const
    {
      return W(JS_GetModuleExportEntry(ctx, m, idx));
    }

    JSWrappedValue read_object(
      const uint8_t* buf, size_t buf_len, int flags) const
    {
      return W(JS_ReadObject(ctx, buf, buf_len, flags));
    }

    JSWrappedValue get_exception() const
    {
      return W(JS_GetException(ctx));
    }

    JSWrappedValue call(
      const JSWrappedValue& f, const std::vector<js::JSWrappedValue>& argv);

    JSWrappedValue parse_json(const nlohmann::json& j) const
    {
      const auto buf = j.dump();
      return W(JS_ParseJSON(ctx, buf.data(), buf.size(), "<json>"));
    }

    JSWrappedValue parse_json(
      const char* buf, size_t buf_len, const char* filename) const
    {
      return W(JS_ParseJSON(ctx, buf, buf_len, filename));
    }

    JSWrappedValue get_typed_array_buffer(
      const JSWrappedValue& obj,
      size_t* pbyte_offset,
      size_t* pbyte_length,
      size_t* pbytes_per_element) const
    {
      return W(JS_GetTypedArrayBuffer(
        ctx, obj, pbyte_offset, pbyte_length, pbytes_per_element));
    }

    std::optional<std::string> to_str(const JSWrappedValue& x) const
    {
      auto val = JS_ToCString(ctx, x);
      if (!val)
      {
        new_type_error("value is not a string");
        return std::nullopt;
      }
      std::string r(val);
      JS_FreeCString(ctx, val);
      return r;
    }

    std::optional<std::string> to_str(const JSValue& x) const
    {
      auto val = JS_ToCString(ctx, x);
      if (!val)
      {
        new_type_error("value is not a string");
        return std::nullopt;
      }
      std::string r(val);
      JS_FreeCString(ctx, val);
      return r;
    }

    std::optional<std::string> to_str(const JSValue& x, size_t& len) const
    {
      auto val = JS_ToCStringLen(ctx, &len, x);
      if (!val)
      {
        new_type_error("value is not a string");
        return std::nullopt;
      }
      std::string r(val);
      JS_FreeCString(ctx, val);
      return r;
    }

    std::optional<std::string> to_str(const JSAtom& atom) const
    {
      auto val = JS_AtomToCString(ctx, atom);
      if (!val)
      {
        new_type_error("atom is not a string");
        return std::nullopt;
      }
      std::string r(val);
      JS_FreeCString(ctx, val);
      return r;
    }

  protected:
    JSWrappedValue W(JSValue&& x) const
    {
      return JSWrappedValue(ctx, std::move(x));
    }
  };

  class JSWrappedAtom
  {
  public:
    JSWrappedAtom() : ctx(NULL), val(JS_ATOM_NULL) {}
    JSWrappedAtom(JSContext* ctx, JSAtom&& val) : ctx(ctx), val(std::move(val))
    {}
    JSWrappedAtom(JSContext* ctx, const JSAtom& value) : ctx(ctx)
    {
      val = JS_DupAtom(ctx, value);
    }
    JSWrappedAtom(const JSWrappedAtom& other) : ctx(other.ctx)
    {
      val = JS_DupAtom(ctx, other.val);
    }
    JSWrappedAtom(JSWrappedAtom&& other) : ctx(other.ctx)
    {
      val = other.val;
      other.val = JS_ATOM_NULL;
    }
    ~JSWrappedAtom()
    {
      if (ctx)
      {
        JS_FreeAtom(ctx, val);
      }
    }

    operator const JSAtom&() const
    {
      return val;
    }

    JSContext* ctx;
    JSAtom val;
  };

  class JSWrappedPropertyEnum
  {
  public:
    JSWrappedPropertyEnum(JSContext* ctx, const JSWrappedValue& value)
    {
      if (!JS_IsObject(value))
      {
        throw std::logic_error(
          fmt::format("object value required for property enum"));
      }

      JSPropertyEnum* prop_enum;
      uint32_t prop_count;

      if (
        JS_GetOwnPropertyNames(
          ctx,
          &prop_enum,
          &prop_count,
          value,
          JS_GPN_STRING_MASK | JS_GPN_ENUM_ONLY) == -1)
      {
        throw std::logic_error(
          fmt::format("Could not extract property names of enum"));
      }
      for (size_t i = 0; i < prop_count; i++)
        properties.push_back(JSWrappedAtom(ctx, prop_enum[i].atom));
      for (uint32_t i = 0; i < prop_count; i++)
        JS_FreeAtom(ctx, prop_enum[i].atom);
      js_free(ctx, prop_enum);
    }
    ~JSWrappedPropertyEnum() {}

    JSWrappedAtom operator[](size_t i) const
    {
      return properties[i];
    }

    size_t size() const
    {
      return properties.size();
    }

    JSContext* ctx;
    std::vector<JSWrappedAtom> properties;
  };

#pragma clang diagnostic pop
}
