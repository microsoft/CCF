// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/js/core/context.h"

#include "ccf/ds/hex.h"
#include "ccf/js/core/runtime.h"
#include "ccf/js/core/wrapped_value.h"
#include "ccf/js/extensions/console.h"
#include "ccf/js/tx_access.h"
#include "enclave/enclave_time.h"
#include "js/global_class_ids.h"

#include <chrono>
#include <cstdarg>
#include <quickjs/quickjs.h>

namespace ccf::js::core
{
  namespace
  {
    inline JSModuleDef* load_module_via_context(
      JSContext* ctx, const char* module_name, void* opaque)
    {
      auto* context = reinterpret_cast<Context*>(opaque);

      try
      {
        auto opt_module = context->get_module(module_name);
        if (!opt_module.has_value())
        {
          return nullptr;
        }
        return reinterpret_cast<JSModuleDef*>(
          JS_VALUE_GET_PTR(opt_module->val));
      }
      catch (const std::exception& exc)
      {
        JS_ThrowReferenceError(ctx, "%s", exc.what());
        js::core::Context& jsctx =
          *reinterpret_cast<js::core::Context*>(JS_GetContextOpaque(ctx));
        auto [reason, trace] = jsctx.error_message();

        auto& rt = jsctx.runtime();
        if (rt.log_exception_details)
        {
          CCF_APP_FAIL(
            "Failed to load module '{}': {} {}",
            module_name,
            reason,
            trace.value_or("<no trace>"));
        }
        return nullptr;
      }
    }
  }

  Context::Context(TxAccess acc) : access(acc)
  {
    ctx = JS_NewContext(rt);
    if (ctx == nullptr)
    {
      throw std::runtime_error("Failed to initialise QuickJS context");
    }
    JS_SetContextOpaque(ctx, this);

    JS_SetModuleLoaderFunc(rt, nullptr, load_module_via_context, this);
  }

  Context::~Context()
  {
    JS_SetInterruptHandler(JS_GetRuntime(ctx), nullptr, nullptr);
    JS_FreeContext(ctx);
  }

  std::optional<JSWrappedValue> Context::get_module(
    std::string_view module_name)
  {
    auto it = loaded_modules_cache.find(module_name);
    if (it == loaded_modules_cache.end())
    {
      LOG_TRACE_FMT("Module cache miss for '{}'", module_name);

      // If not currently in cache, ask configured loader
      if (module_loader == nullptr)
      {
        LOG_FAIL_FMT("Unable to load module: No module loader configured");
        return std::nullopt;
      }

      auto module_val = module_loader->get_module(module_name, *this);
      if (module_val.has_value())
      {
        // If returned a new module:
        // - store it in cache
        loaded_modules_cache.emplace_hint(it, module_name, *module_val);

        // - ensure its dependencies are resolved
        if (JS_ResolveModule(ctx, module_val->val) < 0)
        {
          auto [reason, trace] = error_message();

          if (rt.log_exception_details)
          {
            CCF_APP_FAIL("{}: {}", reason, trace.value_or("<no trace>"));
          }

          throw std::runtime_error(fmt::format(
            "Failed to resolve dependencies for module '{}': {}",
            module_name,
            reason));
        }
      }

      return module_val;
    }
    LOG_TRACE_FMT("Module cache hit for '{}'", module_name);

    return it->second;
  }

  JSWrappedValue Context::wrap(JSValue&& val) const
  {
    // NOLINTBEGIN(performance-move-const-arg)
    return {ctx, std::move(val)};
    // NOLINTEND(performance-move-const-arg)
  };

  JSWrappedValue Context::wrap(const JSValue& val) const
  {
    return {ctx, val};
  };

  JSValue Context::extract_string_array(
    JSValueConst& argv, std::vector<std::string>& out)
  {
    auto args = wrap(argv);

    if (JS_IsArray(ctx, argv) == 0)
    {
      return JS_ThrowTypeError(ctx, "First argument must be an array");
    }

    auto len_val = args["length"];
    uint32_t len = 0;
    if (JS_ToUint32(ctx, &len, len_val.val) != 0)
    {
      return ccf::js::core::constants::Exception;
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
          ctx, "First argument must be an array of strings, found non-string");
      }
      auto s = to_str(arg_val);
      if (!s)
      {
        return JS_ThrowTypeError(
          ctx, "Failed to extract C string from JS string at position %d", i);
      }
      out.push_back(*s);
    }

    return ccf::js::core::constants::Undefined;
  }

  std::pair<std::string, std::optional<std::string>> Context::error_message()
  {
    auto exception_val = wrap(JS_GetException(ctx));
    std::optional<std::string> message;
    bool is_error = exception_val.is_error();
    if (!is_error && exception_val.is_obj())
    {
      auto rval = json_stringify(exception_val);
      message = to_str(rval);
    }
    else
    {
      message = to_str(exception_val);
    }

    std::optional<std::string> trace = std::nullopt;
    if (is_error)
    {
      auto val = exception_val["stack"];
      if (!val.is_undefined())
      {
        trace = to_str(val);
      }
    }
    return {message.value_or(""), trace};
  }

  JSWrappedValue Context::get_property(
    JSValue object, char const* property_name) const
  {
    return wrap(JS_GetPropertyStr(ctx, object, property_name));
  }

  JSWrappedValue Context::get_global_obj() const
  {
    return wrap(JS_GetGlobalObject(ctx));
  }

  JSWrappedValue Context::get_global_property(const char* s) const
  {
    auto g = Context::get_global_obj();
    return wrap(JS_GetPropertyStr(ctx, g.val, s));
  }

  JSWrappedValue Context::get_or_create_global_property(
    const char* s, JSWrappedValue default_value) const
  {
    auto g = Context::get_global_obj();
    auto val = wrap(JS_GetPropertyStr(ctx, g.val, s));
    if (val.is_undefined())
    {
      val = default_value;
      g.set(s, std::move(default_value));
    }

    return val;
  }

  JSWrappedValue Context::get_typed_array_buffer(
    const JSWrappedValue& obj,
    size_t* pbyte_offset,
    size_t* pbyte_length,
    size_t* pbytes_per_element) const
  {
    return wrap(JS_GetTypedArrayBuffer(
      ctx, obj.val, pbyte_offset, pbyte_length, pbytes_per_element));
  }

  JSWrappedValue Context::get_exported_function(
    const std::string& code, const std::string& func, const std::string& path)
  {
    auto module = eval(
      code.c_str(),
      code.size(),
      path.c_str(),
      JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_COMPILE_ONLY);

    if (module.is_exception())
    {
      throw std::runtime_error(fmt::format("Failed to compile {}", path));
    }

    return get_exported_function(module, func, path);
  }

  JSWrappedValue Context::get_exported_function(
    const JSWrappedValue& module,
    const std::string& func,
    const std::string& path)
  {
    auto eval_val = wrap(JS_EvalFunction(ctx, module.val));

    if (eval_val.is_exception())
    {
      auto [reason, trace] = error_message();

      if (rt.log_exception_details)
      {
        CCF_APP_FAIL("{}: {}", reason, trace.value_or("<no trace>"));
      }
      throw std::runtime_error(
        fmt::format("Failed to execute {}: {}", path, reason));
    }

    // Get exported function from module
    assert(JS_VALUE_GET_TAG(module.val) == JS_TAG_MODULE);
    auto* module_def =
      reinterpret_cast<JSModuleDef*>(JS_VALUE_GET_PTR(module.val));
    auto export_count = JS_GetModuleExportEntriesCount(module_def);
    for (auto i = 0; i < export_count; i++)
    {
      auto export_name_atom = JS_GetModuleExportEntryName(ctx, module_def, i);
      auto export_name = to_str(export_name_atom);
      JS_FreeAtom(ctx, export_name_atom);
      if (export_name.value_or("") == func)
      {
        auto export_func = wrap(JS_GetModuleExportEntry(ctx, module_def, i));
        if (JS_IsFunction(ctx, export_func.val) == 0)
        {
          throw std::runtime_error(fmt::format(
            "Export '{}' of module '{}' is not a function", func, path));
        }
        return export_func;
      }
    }

    throw std::runtime_error(
      fmt::format("Failed to find export '{}' in module '{}'", func, path));
  }

  JSWrappedValue Context::null() const
  {
    return wrap(ccf::js::core::constants::Null);
  }

  JSWrappedValue Context::undefined() const
  {
    return wrap(ccf::js::core::constants::Undefined);
  }

  JSWrappedValue Context::new_obj() const
  {
    return wrap(JS_NewObject(ctx));
  }

  JSWrappedValue Context::new_obj_class(JSClassID class_id) const
  {
    return wrap(JS_NewObjectClass(ctx, class_id));
  }

  JSWrappedValue Context::new_array() const
  {
    return wrap(JS_NewArray(ctx));
  }

  JSWrappedValue Context::new_array_buffer_copy(
    const uint8_t* buf, size_t buf_len) const
  {
    return wrap(JS_NewArrayBufferCopy(ctx, buf, buf_len));
  }

  JSWrappedValue Context::new_array_buffer_copy(
    const char* buf, size_t buf_len) const
  {
    return {
      ctx,
      JS_NewArrayBufferCopy(
        ctx, reinterpret_cast<const uint8_t*>(buf), buf_len)};
  }

  JSWrappedValue Context::new_array_buffer_copy(
    std::span<const uint8_t> data) const
  {
    return {ctx, JS_NewArrayBufferCopy(ctx, data.data(), data.size())};
  }

  JSWrappedValue Context::new_string(const std::string_view& str) const
  {
    return new_string_len(str.data(), str.size());
  }

  JSWrappedValue Context::new_string_len(const char* buf, size_t buf_len) const
  {
    return wrap(JS_NewStringLen(ctx, buf, buf_len));
  }

  JSWrappedValue Context::new_string_len(
    const std::span<const uint8_t> buf) const
  {
    return wrap(JS_NewStringLen(
      ctx, reinterpret_cast<const char*>(buf.data()), buf.size()));
  }

  JSWrappedValue Context::new_type_error(const char* fmt, ...) const
  {
    va_list ap;
    va_start(ap, fmt);
    auto r = wrap(JS_ThrowTypeError(ctx, fmt, ap));
    va_end(ap);
    return r;
  }

  JSWrappedValue Context::new_internal_error(const char* fmt, ...) const
  {
    va_list ap;
    va_start(ap, fmt);
    auto r = wrap(JS_ThrowInternalError(ctx, fmt, ap));
    va_end(ap);
    return r;
  }

  JSWrappedValue Context::new_tag_value(int tag, int32_t val) const
  {
// "compound literals are a C99-specific feature"
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc99-extensions"
    return wrap((JSValue){(JSValueUnion){.int32 = val}, tag});
#pragma clang diagnostic pop
  }

  JSWrappedValue Context::new_c_function(
    JSCFunction* func, const char* name, int length) const
  {
    return wrap(JS_NewCFunction(ctx, func, name, length));
  }

  JSWrappedValue Context::new_getter_c_function(
    JSCFunction* func, const char* name, size_t arg_count) const
  {
    return wrap(JS_NewCFunction2(
      ctx, func, name, arg_count, JS_CFUNC_getter, JS_CFUNC_getter_magic));
  }

  JSWrappedValue Context::duplicate_value(JSValueConst original) const
  {
    return wrap(JS_DupValue(ctx, original));
  }

  JSWrappedValue Context::eval(
    const char* input,
    size_t input_len,
    const char* filename,
    int eval_flags) const
  {
    return wrap(JS_Eval(ctx, input, input_len, filename, eval_flags));
  }

  JSWrappedValue Context::read_object(
    const uint8_t* buf, size_t buf_len, int flags) const
  {
    return wrap(JS_ReadObject(ctx, buf, buf_len, flags));
  }

  static int js_custom_interrupt_handler(JSRuntime* rt, void* opaque)
  {
    (void)rt;
    auto* inter = reinterpret_cast<InterruptData*>(opaque);
    auto now = ccf::get_enclave_time();
    auto elapsed_time = now - inter->start_time;
    auto elapsed_ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(elapsed_time);
    if (elapsed_ms.count() >= inter->max_execution_time.count())
    {
      extensions::ConsoleExtension::log_info_with_tag(
        inter->access,
        fmt::format(
          "JS execution has timed out after {}ms (max is {}ms)",
          elapsed_ms.count(),
          inter->max_execution_time.count()));
      inter->request_timed_out = true;
      return 1;
    }
    return 0;
  }

  JSWrappedValue Context::call_with_rt_options(
    const JSWrappedValue& f,
    const std::vector<JSWrappedValue>& argv,
    const std::optional<ccf::JSRuntimeOptions>& options,
    RuntimeLimitsPolicy policy)
  {
    rt.set_runtime_options(options, policy);
    const auto curr_time = ccf::get_enclave_time();
    interrupt_data.start_time = curr_time;
    interrupt_data.max_execution_time = rt.get_max_exec_time();
    JS_SetInterruptHandler(rt, js_custom_interrupt_handler, &interrupt_data);

    auto rv = inner_call(f, argv);

    JS_SetInterruptHandler(rt, nullptr, nullptr);
    rt.reset_runtime_options();

    return rv;
  }

  JSWrappedValue Context::inner_call(
    const JSWrappedValue& f, const std::vector<JSWrappedValue>& argv)
  {
    std::vector<JSValue> argvn;
    argvn.reserve(argv.size());
    for (auto& a : argv)
    {
      argvn.push_back(a.val);
    }

    return wrap(JS_Call(
      ctx,
      f.val,
      ccf::js::core::constants::Undefined,
      argv.size(),
      argvn.data()));
  }

  JSWrappedValue Context::json_stringify(const JSWrappedValue& obj) const
  {
    return wrap(JS_JSONStringify(
      ctx,
      obj.val,
      ccf::js::core::constants::Null,
      ccf::js::core::constants::Null));
  }

  JSWrappedValue Context::parse_json(const nlohmann::json& j) const
  {
    const auto buf = j.dump();
    return wrap(JS_ParseJSON(ctx, buf.data(), buf.size(), "<json>"));
  }

  JSWrappedValue Context::parse_json(
    const char* buf, size_t buf_len, const char* filename) const
  {
    return wrap(JS_ParseJSON(ctx, buf, buf_len, filename));
  }

  std::optional<std::string> Context::to_str(const JSWrappedValue& x) const
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

  std::optional<std::string> Context::to_str(const JSValue& x) const
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

  std::optional<std::string> Context::to_str(
    const JSValue& x, size_t& len) const
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

  std::optional<std::string> Context::to_str(const JSAtom& atom) const
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

  void Context::add_extension(const js::extensions::ExtensionPtr& extension)
  {
    extensions.push_back(extension);
    extension->install(*this);
  }

  bool Context::remove_extension(const js::extensions::ExtensionPtr& extension)
  {
    auto it = std::find(extensions.begin(), extensions.end(), extension);
    if (it != extensions.end())
    {
      extensions.erase(it);
      return true;
    }
    return false;
  }
}

extern "C"
{
  int qjs_gettimeofday(struct JSContext* ctx, struct timeval* tv, void* tz)
  {
    if (tv != NULL)
    {
      // Opaque may be null, when this is called during Context construction
      const ccf::js::core::Context* jsctx =
        reinterpret_cast<ccf::js::core::Context*>(JS_GetContextOpaque(ctx));
      if (jsctx != nullptr && jsctx->implement_untrusted_time)
      {
        const auto microseconds_since_epoch = ccf::get_enclave_time();
        tv->tv_sec = std::chrono::duration_cast<std::chrono::seconds>(
                       microseconds_since_epoch)
                       .count();
        tv->tv_usec = microseconds_since_epoch.count() % std::micro::den;
      }
      else
      {
        memset(tv, 0, sizeof(struct timeval));
      }
    }
    return 0;
  }
}
