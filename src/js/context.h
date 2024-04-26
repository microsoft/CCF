// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/pal/locking.h"
#include "js/tx_access.h"
#include "runtime.h"
#include "wrapped_value.h"

#include <chrono>
#include <quickjs/quickjs-exports.h>
#include <quickjs/quickjs.h>

// TODO: Only required while globals is public
#include "ccf/tx.h"
#include "kv/untyped_map.h"

// Forward declarations
namespace ccf
{
  class AbstractGovernanceEffects;
  class AbstractHostProcesses;
  struct NetworkState;
  class RpcContext;
  class BaseEndpointRegistry;

  namespace historical
  {
    class AbstractStateCache;
    struct State;

    using StatePtr = std::shared_ptr<State>;
  }

  namespace js
  {
    class ContextImpl;
  }
}

namespace ccf::js
{
  struct InterruptData
  {
    std::chrono::microseconds start_time;
    std::chrono::milliseconds max_execution_time;
    ccf::js::TxAccess access;
    bool request_timed_out = false;
  };

  class Context
  {
  private:
    std::unique_ptr<ContextImpl> pimpl;

    JSContext* ctx;
    Runtime rt;

    // The interpreter can cache loaded modules so they do not need to be loaded
    // from the KV for every execution, which is particularly useful when
    // re-using interpreters. A module can only be loaded once per interpreter,
    // and the entire interpreter should be thrown away if _any_ of its modules
    // needs to be refreshed.
    std::map<std::string, JSWrappedValue> loaded_modules_cache;

    void init_globals();

  public:
    // TODO TODO: Would _really_ like to hide this in impl...
    // State which may be set by calls to populate_global_ccf_*. Likely
    // references transaction-scoped entries, so should be cleared between
    // calls. Retained handles to these globals must not access the previous
    // values.
    struct
    {
      kv::Tx* tx = nullptr;
      std::unordered_map<std::string, kv::untyped::Map::Handle*> kv_handles;

      struct HistoricalHandle
      {
        ccf::historical::StatePtr state;
        std::unique_ptr<kv::ReadOnlyTx> tx;
        std::unordered_map<std::string, kv::untyped::Map::ReadOnlyHandle*>
          kv_handles = {};
      };
      std::unordered_map<ccf::SeqNo, HistoricalHandle> historical_handles;

      ccf::RpcContext* rpc_ctx = nullptr;

      const std::vector<uint8_t>* current_request_body = nullptr;
    } globals;

    ccf::pal::Mutex lock;

    const TxAccess access;
    InterruptData interrupt_data;
    bool implement_untrusted_time = false;
    bool log_execution_metrics = true;

    Context(TxAccess acc);

    ~Context();

    // Delete copy and assignment operators, since this assumes sole ownership
    // of underlying rt and ctx
    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;

    Runtime& runtime()
    {
      return rt;
    }

    operator JSContext*() const
    {
      return ctx;
    }

    std::optional<JSWrappedValue> get_module_from_cache(
      const std::string& module_name)
    {
      auto module = loaded_modules_cache.find(module_name);
      if (module == loaded_modules_cache.end())
      {
        return std::nullopt;
      }

      return module->second;
    }

    void load_module_to_cache(
      const std::string& module_name, const JSWrappedValue& module)
    {
      if (get_module_from_cache(module_name).has_value())
      {
        throw std::logic_error(fmt::format(
          "Module '{}' is already loaded in interpreter cache", module_name));
      }
      loaded_modules_cache[module_name] = module;
    }

    JSWrappedValue operator()(JSValue&& val) const
    {
      return W(std::move(val));
    };

    JSWrappedValue wrap(JSValue&& val) const
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

    JSWrappedValue get_global_property(const char* s) const
    {
      auto g = get_global_obj();
      return W(JS_GetPropertyStr(ctx, g.val, s));
    }

    JSValue get_string_array(JSValueConst& argv, std::vector<std::string>& out)
    {
      auto args = JSWrappedValue(ctx, argv);

      if (!JS_IsArray(ctx, argv))
      {
        return JS_ThrowTypeError(ctx, "First argument must be an array");
      }

      auto len_val = args["length"];
      uint32_t len = 0;
      if (JS_ToUint32(ctx, &len, len_val.val))
      {
        return ccf::js::constants::Exception;
      }

      if (len == 0)
      {
        return JS_ThrowRangeError(
          ctx, "First argument must be a non-empty array");
      }

      for (uint32_t i = 0; i < len; i++)
      {
        auto arg_val = args[i];
        if (!arg_val.is_str())
        {
          return JS_ThrowTypeError(
            ctx,
            "First argument must be an array of strings, found non-string");
        }
        auto s = to_str(arg_val);
        if (!s)
        {
          return JS_ThrowTypeError(
            ctx, "Failed to extract C string from JS string at position %d", i);
        }
        out.push_back(*s);
      }

      return ccf::js::constants::Undefined;
    }

    JSWrappedValue json_stringify(const JSWrappedValue& obj) const
    {
      return W(JS_JSONStringify(
        ctx, obj.val, ccf::js::constants::Null, ccf::js::constants::Null));
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

    JSWrappedValue new_array_buffer_copy(std::span<const uint8_t> data) const
    {
      return JSWrappedValue(
        ctx, JS_NewArrayBufferCopy(ctx, data.data(), data.size()));
    }

    JSWrappedValue new_string(const std::string& str) const
    {
      return W(JS_NewStringLen(ctx, str.data(), str.size()));
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

    JSValue new_internal_error(const char* fmt, ...) const
    {
      va_list ap;
      va_start(ap, fmt);
      auto r = JS_ThrowInternalError(ctx, fmt, ap);
      va_end(ap);
      return r;
    }

    JSWrappedValue new_tag_value(int tag, int32_t val = 0) const
    {
// "compound literals are a C99-specific feature"
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc99-extensions"
      return W((JSValue){(JSValueUnion){.int32 = val}, tag});
#pragma clang diagnostic pop
    }

    JSWrappedValue null() const
    {
      return W(ccf::js::constants::Null);
    }

    JSWrappedValue undefined() const
    {
      return W(ccf::js::constants::Undefined);
    }

    JSWrappedValue new_c_function(
      JSCFunction* func, const char* name, int length) const
    {
      return W(JS_NewCFunction(ctx, func, name, length));
    }

    JSWrappedValue new_getter_c_function(
      JSCFunction* func, const char* name) const
    {
      return W(JS_NewCFunction2(
        ctx, func, name, 0, JS_CFUNC_getter, JS_CFUNC_getter_magic));
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
      return W(JS_EvalFunction(ctx, module.val));
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

    JSWrappedValue call_with_rt_options(
      const JSWrappedValue& f,
      const std::vector<js::JSWrappedValue>& argv,
      kv::Tx* tx,
      RuntimeLimitsPolicy policy);

    // Call a JS function _without_ any stack, heap or execution time limits.
    // Only to be used, as the name indicates, for calls inside an already
    // invoked JS function, where the caller has already set up the necessary
    // limits.
    JSWrappedValue inner_call(
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
        ctx, obj.val, pbyte_offset, pbyte_length, pbytes_per_element));
    }

    std::optional<std::string> to_str(const JSWrappedValue& x) const
    {
      auto val = JS_ToCString(ctx, x.val);
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

    // Reset any state that has been stored on the ctx object to implement
    // globals. This should be called at the end of any invocation where the
    // globals may point to locally-scoped memory, and the Context itself (the
    // interpreter) may live longer and be reused for future calls. Those calls
    // must re-populate the globals appropriately, pointing to their own local
    // instances of state as required.
    void invalidate_globals();

    void populate_global_ccf_kv(kv::Tx& tx);
    // TODO: Forward declare all of these
    void populate_global_ccf_node(ccf::AbstractGovernanceEffects* gov_effects);
    void populate_global_ccf_host(ccf::AbstractHostProcesses* host_processes);
    void populate_global_ccf_network(ccf::NetworkState* network_state);
    void populate_global_ccf_rpc(ccf::RpcContext* rpc_ctx);
    void populate_global_ccf_consensus(
      ccf::BaseEndpointRegistry* endpoint_registry);
    void populate_global_ccf_historical(
      ccf::historical::AbstractStateCache* historical_state);
    void populate_global_ccf_gov_actions();

    void register_request_body_class();

    JSValue create_historical_state_object(ccf::historical::StatePtr state);

    std::pair<std::string, std::optional<std::string>> error_message();

  protected:
    JSWrappedValue W(JSValue&& x) const
    {
      return JSWrappedValue(ctx, std::move(x));
    }

    JSWrappedValue W(const JSValue& x) const
    {
      return JSWrappedValue(ctx, x);
    }
  };
}
