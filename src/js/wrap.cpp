// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "js/wrap.h"

#include "ccf/ds/logger.h"
#include "ccf/rpc_context.h"
#include "ccf/service/tables/jwt.h"
#include "ccf/tx_id.h"
#include "ccf/version.h"
#include "crypto/certs.h"
#include "enclave/enclave_time.h"
#include "js/consensus.cpp"
#include "js/conv.cpp"
#include "js/crypto.cpp"
#include "js/historical.cpp"
#include "js/no_plugins.cpp"
#include "kv/untyped_map.h"
#include "node/rpc/call_types.h"
#include "node/rpc/gov_effects_interface.h"
#include "node/rpc/gov_logging.h"
#include "node/rpc/jwt_management.h"
#include "node/rpc/node_interface.h"

#include <algorithm>
#include <memory>
#include <quickjs/quickjs-exports.h>
#include <quickjs/quickjs.h>
#include <span>

#define JS_CHECK_HANDLE(h) \
  do \
  { \
    if (h == nullptr) \
    { \
      return JS_ThrowInternalError( \
        ctx, "Internal: Unable to access MapHandle"); \
    } \
  } while (0)

namespace ccf::js
{
// "mixture of designated and non-designated initializers in the same
// initializer list is a C99 extension"
// Used heavily by QuickJS, including in macros (such as JS_CFUNC_DEF) repeated
// here
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc99-extensions"

  using KVMap = kv::untyped::Map;

  JSClassID kv_class_id = 0;
  JSClassID kv_historical_class_id = 0;
  JSClassID kv_map_handle_class_id = 0;
  JSClassID body_class_id = 0;
  JSClassID node_class_id = 0;
  JSClassID network_class_id = 0;
  JSClassID rpc_class_id = 0;
  JSClassID host_class_id = 0;
  JSClassID consensus_class_id = 0;
  JSClassID historical_class_id = 0;
  JSClassID historical_state_class_id = 0;

  JSClassDef kv_class_def = {};
  JSClassExoticMethods kv_exotic_methods = {};
  JSClassDef kv_historical_class_def = {};
  JSClassExoticMethods kv_historical_exotic_methods = {};
  JSClassDef kv_map_handle_class_def = {};
  JSClassDef kv_historical_map_handle_class_def = {};
  JSClassDef body_class_def = {};
  JSClassDef node_class_def = {};
  JSClassDef network_class_def = {};
  JSClassDef rpc_class_def = {};
  JSClassDef host_class_def = {};
  JSClassDef consensus_class_def = {};
  JSClassDef historical_class_def = {};
  JSClassDef historical_state_class_def = {};

  std::vector<FFIPlugin> ffi_plugins;

  static void register_ffi_plugin(const FFIPlugin& plugin)
  {
    if (plugin.ccf_version != std::string(ccf::ccf_version))
    {
      throw std::runtime_error(fmt::format(
        "CCF version mismatch in JS FFI plugin '{}': expected={} != actual={}",
        plugin.name,
        plugin.ccf_version,
        ccf::ccf_version));
    }
    LOG_DEBUG_FMT("JS FFI plugin registered: {}", plugin.name);
    ffi_plugins.push_back(plugin);
  }

  void register_ffi_plugins(const std::vector<FFIPlugin>& plugins)
  {
    for (const auto& plugin : plugins)
    {
      register_ffi_plugin(plugin);
    }
  }

  static void log_info_with_tag(
    const ccf::js::TxAccess access, std::string_view s)
  {
    switch (access)
    {
      case (js::TxAccess::APP_RO):
      case (js::TxAccess::APP_RW):
      {
        CCF_APP_INFO("{}", s);
        break;
      }

      case (js::TxAccess::GOV_RO):
      case (js::TxAccess::GOV_RW):
      {
        GOV_INFO_FMT("{}", s);
        break;
      }

      default:
      {
        LOG_INFO_FMT("{}", s);
        break;
      }
    }
  }

  static int js_custom_interrupt_handler(JSRuntime* rt, void* opaque)
  {
    InterruptData* inter = reinterpret_cast<InterruptData*>(opaque);
    auto now = ccf::get_enclave_time();
    auto elapsed_time = now - inter->start_time;
    auto elapsed_ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(elapsed_time);
    if (elapsed_ms.count() >= inter->max_execution_time.count())
    {
      log_info_with_tag(
        inter->access,
        fmt::format(
          "JS execution has timed out after {}ms (max is {}ms)",
          elapsed_ms.count(),
          inter->max_execution_time.count()));
      inter->request_timed_out = true;
      return 1;
    }
    else
    {
      return 0;
    }
  }

  JSWrappedValue Context::inner_call(
    const JSWrappedValue& f, const std::vector<js::JSWrappedValue>& argv)
  {
    std::vector<JSValue> argvn;
    argvn.reserve(argv.size());
    for (auto& a : argv)
    {
      argvn.push_back(a.val);
    }

    return W(JS_Call(
      ctx, f.val, ccf::js::constants::Undefined, argv.size(), argvn.data()));
  }

  JSWrappedValue Context::call_with_rt_options(
    const JSWrappedValue& f,
    const std::vector<js::JSWrappedValue>& argv,
    kv::Tx* tx,
    RuntimeLimitsPolicy policy)
  {
    rt.set_runtime_options(tx, policy);
    const auto curr_time = ccf::get_enclave_time();
    interrupt_data.start_time = curr_time;
    interrupt_data.max_execution_time = rt.get_max_exec_time();
    JS_SetInterruptHandler(rt, js_custom_interrupt_handler, &interrupt_data);

    auto rv = inner_call(f, argv);

    rt.reset_runtime_options();

    return rv;
  }

  Runtime::Runtime()
  {
    rt = JS_NewRuntime();
    if (rt == nullptr)
    {
      throw std::runtime_error("Failed to initialise QuickJS runtime");
    }

    JS_SetRuntimeOpaque(rt, this);

    add_ccf_classdefs();
  }

  Runtime::~Runtime()
  {
    JS_FreeRuntime(rt);
  }

  static KVMap::Handle* _get_map_handle(
    js::Context& jsctx, JSValueConst _this_val)
  {
    JSWrappedValue this_val = jsctx(JS_DupValue(jsctx, _this_val));
    auto map_name_val = this_val["_map_name"];
    auto map_name = jsctx.to_str(map_name_val);

    if (!map_name.has_value())
    {
      LOG_FAIL_FMT("No map name stored on handle");
      return nullptr;
    }

    auto& handles = jsctx.globals.kv_handles;
    auto it = handles.find(map_name.value());
    if (it == handles.end())
    {
      it = handles.emplace_hint(it, map_name.value(), nullptr);
    }

    if (it->second == nullptr)
    {
      kv::Tx* tx = jsctx.globals.tx;
      if (tx == nullptr)
      {
        LOG_FAIL_FMT("Can't rehydrate MapHandle - no transaction context");
        return nullptr;
      }
      it->second = tx->rw<KVMap>(map_name.value());
    }

    return it->second;
  }

  using HandleGetter =
    KVMap::ReadOnlyHandle* (*)(js::Context& jsctx, JSValueConst this_val);

  static KVMap::ReadOnlyHandle* _get_map_handle_current(
    js::Context& jsctx, JSValueConst this_val)
  {
    // NB: This creates (and stores) a writeable handle internally, but converts
    // to the (subtype) ReadOnlyHandle* in return here. This means that if we
    // call has() and then put(), we'll correctly have a writeable handle for
    // the put() despite reading initially.
    return _get_map_handle(jsctx, this_val);
  }

  static KVMap::ReadOnlyHandle* _get_map_handle_historical(
    js::Context& jsctx, JSValueConst _this_val)
  {
    JSWrappedValue this_val = jsctx(JS_DupValue(jsctx, _this_val));
    auto map_name_val = this_val["_map_name"];
    auto map_name = jsctx.to_str(map_name_val);

    if (!map_name.has_value())
    {
      LOG_FAIL_FMT("No map name stored on handle");
      return nullptr;
    }

    const auto seqno = reinterpret_cast<ccf::SeqNo>(
      JS_GetOpaque(_this_val, kv_map_handle_class_id));

    // Handle to historical KV
    auto it = jsctx.globals.historical_handles.find(seqno);
    if (it == jsctx.globals.historical_handles.end())
    {
      LOG_FAIL_FMT(
        "Unable to retrieve any historical handles for state at {}", seqno);
      return nullptr;
    }

    auto& handles = it->second.kv_handles;
    auto hit = handles.find(map_name.value());
    if (hit == handles.end())
    {
      hit = handles.emplace_hint(hit, map_name.value(), nullptr);
    }

    if (hit->second == nullptr)
    {
      kv::ReadOnlyTx* tx = it->second.tx.get();
      if (tx == nullptr)
      {
        LOG_FAIL_FMT("Can't rehydrate MapHandle - no transaction");
        return nullptr;
      }

      hit->second = tx->ro<KVMap>(map_name.value());
    }

    return hit->second;
  }

  template <HandleGetter handle_getter_>
  static JSValue js_kv_map_has(
    JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    if (argc != 1)
    {
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 1", argc);
    }

    size_t key_size;
    uint8_t* key = JS_GetArrayBuffer(ctx, &key_size, argv[0]);

    if (!key)
    {
      return JS_ThrowTypeError(ctx, "Argument must be an ArrayBuffer");
    }

    auto handle = handle_getter_(jsctx, this_val);
    JS_CHECK_HANDLE(handle);

    auto has = handle->has({key, key + key_size});

    return JS_NewBool(ctx, has);
  }

  template <HandleGetter handle_getter_>
  static JSValue js_kv_map_get(
    JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    if (argc != 1)
    {
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 1", argc);
    }

    size_t key_size;
    uint8_t* key = JS_GetArrayBuffer(ctx, &key_size, argv[0]);

    if (!key)
    {
      return JS_ThrowTypeError(ctx, "Argument must be an ArrayBuffer");
    }

    auto handle = handle_getter_(jsctx, this_val);
    JS_CHECK_HANDLE(handle);

    auto val = handle->get({key, key + key_size});

    if (!val.has_value())
    {
      return ccf::js::constants::Undefined;
    }

    auto buf =
      jsctx.new_array_buffer_copy(val.value().data(), val.value().size());
    JS_CHECK_EXC(buf);

    return buf.take();
  }

  template <HandleGetter handle_getter_>
  static JSValue js_kv_get_version_of_previous_write(
    JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    if (argc != 1)
    {
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 1", argc);
    }

    size_t key_size;
    uint8_t* key = JS_GetArrayBuffer(ctx, &key_size, argv[0]);

    if (!key)
    {
      return JS_ThrowTypeError(ctx, "Argument must be an ArrayBuffer");
    }

    auto handle = handle_getter_(jsctx, this_val);
    JS_CHECK_HANDLE(handle);

    auto val = handle->get_version_of_previous_write({key, key + key_size});

    if (!val.has_value())
    {
      return ccf::js::constants::Undefined;
    }

    return JS_NewInt64(ctx, val.value());
  }

  template <HandleGetter handle_getter_>
  static JSValue js_kv_map_size_getter(
    JSContext* ctx, JSValueConst this_val, int argc, JSValueConst*)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    auto handle = handle_getter_(jsctx, this_val);
    JS_CHECK_HANDLE(handle);

    const uint64_t size = handle->size();
    if (size > INT64_MAX)
    {
      return JS_ThrowInternalError(
        ctx, "Map size (%lu) is too large to represent in int64", size);
    }

    return JS_NewInt64(ctx, (int64_t)size);
  }

  static JSValue js_kv_map_delete(
    JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    if (argc != 1)
    {
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 1", argc);
    }

    size_t key_size;
    uint8_t* key = JS_GetArrayBuffer(ctx, &key_size, argv[0]);

    if (!key)
    {
      return JS_ThrowTypeError(ctx, "Argument must be an ArrayBuffer");
    }

    auto handle = _get_map_handle(jsctx, this_val);
    JS_CHECK_HANDLE(handle);

    handle->remove({key, key + key_size});

    return ccf::js::constants::Undefined;
  }

  static JSValue js_kv_map_set(
    JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    if (argc != 2)
    {
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 2", argc);
    }

    size_t key_size;
    uint8_t* key = JS_GetArrayBuffer(ctx, &key_size, argv[0]);

    size_t val_size;
    uint8_t* val = JS_GetArrayBuffer(ctx, &val_size, argv[1]);

    if (!key || !val)
    {
      return JS_ThrowTypeError(ctx, "Arguments must be ArrayBuffers");
    }

    auto handle = _get_map_handle(jsctx, this_val);
    JS_CHECK_HANDLE(handle);

    handle->put({key, key + key_size}, {val, val + val_size});

    return JS_DupValue(ctx, this_val);
  }

  static JSValue js_kv_map_clear(
    JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    if (argc != 0)
    {
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 0", argc);
    }

    auto handle = _get_map_handle(jsctx, this_val);
    JS_CHECK_HANDLE(handle);

    handle->clear();

    return ccf::js::constants::Undefined;
  }

  template <HandleGetter handle_getter_>
  static JSValue js_kv_map_foreach(
    JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    if (argc != 1)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 1", argc);

    JSWrappedValue func(ctx, argv[0]);
    JSWrappedValue obj(ctx, this_val);

    if (!JS_IsFunction(ctx, func.val))
    {
      return JS_ThrowTypeError(ctx, "Argument must be a function");
    }

    auto handle = handle_getter_(jsctx, this_val);
    JS_CHECK_HANDLE(handle);

    bool failed = false;
    handle->foreach(
      [&jsctx, &obj, &func, &failed](const auto& k, const auto& v) {
        auto value = jsctx.new_array_buffer_copy(v.data(), v.size());
        if (value.is_exception())
        {
          failed = true;
          return false;
        }
        auto key = jsctx.new_array_buffer_copy(k.data(), k.size());
        if (key.is_exception())
        {
          failed = true;
          return false;
        }
        // JS forEach expects (v, k, map) rather than (k, v)
        std::vector<JSWrappedValue> args = {value, key, obj};

        auto val = jsctx.inner_call(func, args);

        if (val.is_exception())
        {
          failed = true;
          return false;
        }

        return true;
      });

    if (failed)
    {
      return ccf::js::constants::Exception;
    }

    return ccf::js::constants::Undefined;
  }

  enum class MapAccessPermissions
  {
    READ_WRITE,
    READ_ONLY,
    ILLEGAL
  };

  static constexpr char const* access_permissions_explanation_url =
    "https://microsoft.github.io/CCF/main/audit/read_write_restrictions.html";

  static MapAccessPermissions _check_kv_map_access(
    TxAccess execution_context, const std::string& table_name)
  {
    // Enforce the restrictions described in the read_write_restrictions page in
    // the docs. Note that table is more readable, so should be considered the
    // source of truth for these restrictions. This code is formatted to attempt
    // to make it clear how it maps directly to that table.
    const auto [privacy_of_table, namespace_of_table] =
      kv::parse_map_name(table_name);

    switch (privacy_of_table)
    {
      case (kv::SecurityDomain::PRIVATE):
      {
        // The only time private tables can be used, is on private application
        // tables in an application context. Governance should neither read from
        // nor write to private tables, and if private governance or internal
        // tables exist then applications should not be able to read them.
        if (
          execution_context == TxAccess::APP_RW &&
          namespace_of_table == kv::AccessCategory::APPLICATION)
        {
          return MapAccessPermissions::READ_WRITE;
        }
        else if (
          execution_context == TxAccess::APP_RO &&
          namespace_of_table == kv::AccessCategory::APPLICATION)
        {
          return MapAccessPermissions::READ_ONLY;
        }
        else
        {
          return MapAccessPermissions::ILLEGAL;
        }
      }

      case (kv::SecurityDomain::PUBLIC):
      {
        switch (namespace_of_table)
        {
          case kv::AccessCategory::INTERNAL:
          {
            return MapAccessPermissions::READ_ONLY;
          }

          case kv::AccessCategory::GOVERNANCE:
          {
            if (execution_context == TxAccess::GOV_RW)
            {
              return MapAccessPermissions::READ_WRITE;
            }
            else
            {
              return MapAccessPermissions::READ_ONLY;
            }
          }

          case kv::AccessCategory::APPLICATION:
          {
            switch (execution_context)
            {
              case (TxAccess::APP_RW):
              {
                return MapAccessPermissions::READ_WRITE;
              }
              case (TxAccess::APP_RO):
              {
                return MapAccessPermissions::READ_ONLY;
              }
              default:
              {
                return MapAccessPermissions::ILLEGAL;
              }
            }
          }
        }
      }

      case (kv::SecurityDomain::SECURITY_DOMAIN_MAX):
      {
        throw std::logic_error(fmt::format(
          "Unexpected security domain (max) for table {}", table_name));
      }
    }
  }

#define JS_KV_PERMISSION_ERROR_HELPER(C_FUNC_NAME, JS_METHOD_NAME) \
  static JSValue C_FUNC_NAME( \
    JSContext* ctx, JSValueConst this_val, int, JSValueConst*) \
  { \
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx); \
    const auto table_name = \
      jsctx.to_str(JS_GetPropertyStr(jsctx, this_val, "_map_name")) \
        .value_or(""); \
    if (table_name.empty()) \
    { \
      return JS_ThrowTypeError(ctx, "Internal: No map name stored on handle"); \
    } \
    const auto permission = _check_kv_map_access(jsctx.access, table_name); \
    char const* table_kind = permission == MapAccessPermissions::READ_ONLY ? \
      "read-only" : \
      "inaccessible"; \
    char const* exec_context = "unknown"; \
    switch (jsctx.access) \
    { \
      case (TxAccess::APP_RW): \
      { \
        exec_context = "application"; \
        break; \
      } \
      case (TxAccess::APP_RO): \
      { \
        exec_context = "read-only application"; \
        break; \
      } \
      case (TxAccess::GOV_RO): \
      { \
        exec_context = "read-only governance"; \
        break; \
      } \
      case (TxAccess::GOV_RW): \
      { \
        exec_context = "read-write governance"; \
        break; \
      } \
    } \
    return JS_ThrowTypeError( \
      ctx, \
      "Cannot call " #JS_METHOD_NAME \
      " on %s table named %s in %s execution context. See %s for more " \
      "detail.", \
      table_kind, \
      table_name.c_str(), \
      exec_context, \
      access_permissions_explanation_url); \
  }

  JS_KV_PERMISSION_ERROR_HELPER(js_kv_map_has_denied, "has")
  JS_KV_PERMISSION_ERROR_HELPER(js_kv_map_get_denied, "get")
  JS_KV_PERMISSION_ERROR_HELPER(js_kv_map_size_denied, "size")
  JS_KV_PERMISSION_ERROR_HELPER(js_kv_map_set_denied, "set")
  JS_KV_PERMISSION_ERROR_HELPER(js_kv_map_delete_denied, "delete")
  JS_KV_PERMISSION_ERROR_HELPER(js_kv_map_clear_denied, "clear")
  JS_KV_PERMISSION_ERROR_HELPER(js_kv_map_foreach_denied, "foreach")
  JS_KV_PERMISSION_ERROR_HELPER(js_kv_map_get_version_denied, "get_version")
#undef JS_KV_PERMISSION_ERROR_HELPER

  template <HandleGetter HG>
  static JSValue _create_kv_map_handle(
    js::Context& ctx,
    const std::string& map_name,
    MapAccessPermissions access_permission)
  {
    // This follows the interface of Map:
    // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Map
    // Keys and values are ArrayBuffers. Keys are matched based on their
    // contents.
    auto view_val = ctx.new_obj_class(kv_map_handle_class_id);
    JS_CHECK_EXC(view_val);

    // Store (owning) copy of map_name in a property on this JSValue
    auto map_name_val = ctx.new_string(map_name);
    JS_CHECK_EXC(map_name_val);
    JS_CHECK_SET(view_val.set("_map_name", std::move(map_name_val)));

    // Add methods to handle object. Note that this is done once, when this
    // object is created, because jsctx.access is constant. If the access
    // restrictions could vary between invocations, then this object's
    // properties would need to be updated as well.

    auto has_fn = js_kv_map_has<HG>;
    auto get_fn = js_kv_map_get<HG>;
    auto size_fn = js_kv_map_size_getter<HG>;
    auto set_fn = js_kv_map_set;
    auto delete_fn = js_kv_map_delete;
    auto clear_fn = js_kv_map_clear;
    auto foreach_fn = js_kv_map_foreach<HG>;
    auto get_version_fn = js_kv_get_version_of_previous_write<HG>;

    if (access_permission == MapAccessPermissions::ILLEGAL)
    {
      has_fn = js_kv_map_has_denied;
      get_fn = js_kv_map_get_denied;
      size_fn = js_kv_map_size_denied;
      set_fn = js_kv_map_set_denied;
      delete_fn = js_kv_map_delete_denied;
      clear_fn = js_kv_map_clear_denied;
      foreach_fn = js_kv_map_foreach_denied;
      get_version_fn = js_kv_map_get_version_denied;
    }
    else if (access_permission == MapAccessPermissions::READ_ONLY)
    {
      set_fn = js_kv_map_set_denied;
      delete_fn = js_kv_map_delete_denied;
      clear_fn = js_kv_map_clear_denied;
    }

    auto has_fn_val = ctx.new_c_function(has_fn, "has", 1);
    JS_CHECK_EXC(has_fn_val);
    JS_CHECK_SET(view_val.set("has", std::move(has_fn_val)));

    auto get_fn_val = ctx.new_c_function(get_fn, "get", 1);
    JS_CHECK_EXC(get_fn_val);
    JS_CHECK_SET(view_val.set("get", std::move(get_fn_val)));

    auto get_size_fn_val = ctx.new_getter_c_function(size_fn, "size");
    JS_CHECK_EXC(get_size_fn_val);
    JS_CHECK_SET(view_val.set_getter("size", std::move(get_size_fn_val)));

    auto set_fn_val = ctx.new_c_function(set_fn, "set", 2);
    JS_CHECK_EXC(set_fn_val);
    JS_CHECK_SET(view_val.set("set", std::move(set_fn_val)));

    auto delete_fn_val = ctx.new_c_function(delete_fn, "delete", 1);
    JS_CHECK_EXC(delete_fn_val);
    JS_CHECK_SET(view_val.set("delete", std::move(delete_fn_val)));

    auto clear_fn_val = ctx.new_c_function(clear_fn, "clear", 0);
    JS_CHECK_EXC(clear_fn_val);
    JS_CHECK_SET(view_val.set("clear", std::move(clear_fn_val)));

    auto foreach_fn_val = ctx.new_c_function(foreach_fn, "forEach", 1);
    JS_CHECK_EXC(foreach_fn_val);
    JS_CHECK_SET(view_val.set("forEach", std::move(foreach_fn_val)));

    auto get_version_fn_val =
      ctx.new_c_function(get_version_fn, "getVersionOfPreviousWrite", 1);
    JS_CHECK_EXC(get_version_fn_val);
    JS_CHECK_SET(
      view_val.set("getVersionOfPreviousWrite", std::move(get_version_fn_val)));

    return view_val.take();
  }

  static int js_kv_lookup(
    JSContext* ctx,
    JSPropertyDescriptor* desc,
    JSValueConst this_val,
    JSAtom property)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);
    const auto map_name = jsctx.to_str(property).value_or("");
    LOG_TRACE_FMT("Looking for kv map '{}'", map_name);

    const auto access_permission = _check_kv_map_access(jsctx.access, map_name);
    auto handle_val = _create_kv_map_handle<_get_map_handle_current>(
      jsctx, map_name, access_permission);
    if (JS_IsException(handle_val))
    {
      return -1;
    }

    desc->flags = 0;
    desc->value = handle_val;

    return true;
  }

  static int js_historical_kv_lookup(
    JSContext* ctx,
    JSPropertyDescriptor* desc,
    JSValueConst this_val,
    JSAtom property)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);
    const auto map_name = jsctx.to_str(property).value_or("");
    auto seqno = reinterpret_cast<ccf::SeqNo>(
      JS_GetOpaque(this_val, kv_historical_class_id));
    LOG_TRACE_FMT(
      "Looking for historical kv map '{}' at seqno {}", map_name, seqno);

    // Ignore evaluated access permissions - all tables are read-only
    const auto access_permission = MapAccessPermissions::READ_ONLY;
    auto handle_val = _create_kv_map_handle<_get_map_handle_historical>(
      jsctx, map_name, access_permission);
    if (JS_IsException(handle_val))
    {
      return -1;
    }

    // Copy seqno from kv to handle
    JS_SetOpaque(handle_val, reinterpret_cast<void*>(seqno));

    desc->flags = 0;
    desc->value = handle_val;

    return true;
  }

  JSValue js_body_text(
    JSContext* ctx,
    JSValueConst this_val,
    int argc,
    [[maybe_unused]] JSValueConst* argv)
  {
    if (argc != 0)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected none", argc);

    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);
    auto body = jsctx.globals.current_request_body;
    if (body == nullptr)
    {
      return JS_ThrowInternalError(ctx, "No request body set");
    }

    auto body_ = JS_NewStringLen(ctx, (const char*)body->data(), body->size());
    return body_;
  }

  JSValue js_body_json(
    JSContext* ctx,
    JSValueConst this_val,
    int argc,
    [[maybe_unused]] JSValueConst* argv)
  {
    if (argc != 0)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected none", argc);

    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);
    auto body = jsctx.globals.current_request_body;
    if (body == nullptr)
    {
      return JS_ThrowTypeError(ctx, "No request body set");
    }

    std::string body_str(body->begin(), body->end());
    auto body_ = JS_ParseJSON(ctx, body_str.c_str(), body->size(), "<body>");
    return body_;
  }

  JSValue js_body_array_buffer(
    JSContext* ctx,
    JSValueConst this_val,
    int argc,
    [[maybe_unused]] JSValueConst* argv)
  {
    if (argc != 0)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected none", argc);

    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);
    auto body = jsctx.globals.current_request_body;
    if (body == nullptr)
    {
      return JS_ThrowTypeError(ctx, "No request body set");
    }

    auto body_ = JS_NewArrayBufferCopy(ctx, body->data(), body->size());
    return body_;
  }

  JSValue js_node_trigger_ledger_rekey(
    JSContext* ctx,
    JSValueConst this_val,
    int argc,
    [[maybe_unused]] JSValueConst* argv)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);
    if (argc != 0)
    {
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments but expected none", argc);
    }

    auto gov_effects = static_cast<ccf::AbstractGovernanceEffects*>(
      JS_GetOpaque(this_val, node_class_id));

    auto tx_ptr = jsctx.globals.tx;

    if (tx_ptr == nullptr)
    {
      return JS_ThrowInternalError(
        ctx, "No transaction available to rekey ledger");
    }

    try
    {
      bool result = gov_effects->rekey_ledger(*tx_ptr);
      if (!result)
      {
        return JS_ThrowInternalError(ctx, "Could not rekey ledger");
      }
    }
    catch (const std::exception& e)
    {
      GOV_FAIL_FMT("Failed to rekey ledger: {}", e.what());
      return JS_ThrowInternalError(ctx, "Failed to rekey ledger: %s", e.what());
    }

    return ccf::js::constants::Undefined;
  }

  JSValue js_node_transition_service_to_open(
    JSContext* ctx,
    JSValueConst this_val,
    int argc,
    [[maybe_unused]] JSValueConst* argv)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    if (argc != 2)
    {
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments but expected two", argc);
    }

    auto gov_effects = static_cast<ccf::AbstractGovernanceEffects*>(
      JS_GetOpaque(this_val, node_class_id));

    if (gov_effects == nullptr)
    {
      return JS_ThrowInternalError(ctx, "Node state is not set");
    }

    auto tx_ptr = jsctx.globals.tx;

    if (tx_ptr == nullptr)
    {
      return JS_ThrowInternalError(
        ctx, "No transaction available to open service");
    }

    try
    {
      AbstractGovernanceEffects::ServiceIdentities identities;

      size_t prev_bytes_sz = 0;
      uint8_t* prev_bytes = nullptr;
      if (!JS_IsUndefined(argv[0]))
      {
        prev_bytes = JS_GetArrayBuffer(ctx, &prev_bytes_sz, argv[0]);
        if (!prev_bytes)
        {
          return JS_ThrowTypeError(
            ctx, "Previous service identity argument is not an array buffer");
        }
        identities.previous = crypto::Pem(prev_bytes, prev_bytes_sz);
        GOV_DEBUG_FMT(
          "previous service identity: {}", identities.previous->str());
      }

      if (JS_IsUndefined(argv[1]))
      {
        return JS_ThrowInternalError(
          ctx, "Proposal requires a service identity");
      }

      size_t next_bytes_sz = 0;
      uint8_t* next_bytes = JS_GetArrayBuffer(ctx, &next_bytes_sz, argv[1]);

      if (!next_bytes)
      {
        return JS_ThrowTypeError(
          ctx, "Next service identity argument is not an array buffer");
      }

      identities.next = crypto::Pem(next_bytes, next_bytes_sz);
      GOV_DEBUG_FMT("next service identity: {}", identities.next.str());

      gov_effects->transition_service_to_open(*tx_ptr, identities);
    }
    catch (const std::exception& e)
    {
      GOV_FAIL_FMT("Unable to open service: {}", e.what());
      return JS_ThrowInternalError(ctx, "Unable to open service: %s", e.what());
    }

    return ccf::js::constants::Undefined;
  }

  JSValue js_network_generate_endorsed_certificate(
    JSContext* ctx,
    JSValueConst this_val,
    int argc,
    [[maybe_unused]] JSValueConst* argv)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    if (argc != 3)
    {
      return JS_ThrowTypeError(ctx, "Passed %d arguments but expected 3", argc);
    }

    auto network =
      static_cast<ccf::NetworkState*>(JS_GetOpaque(this_val, network_class_id));
    if (network == nullptr)
    {
      return JS_ThrowInternalError(ctx, "Network state is not set");
    }

    auto csr_cstr = jsctx.to_str(argv[0]);
    if (!csr_cstr)
    {
      return ccf::js::constants::Exception;
    }
    crypto::Pem csr;
    try
    {
      csr = crypto::Pem(*csr_cstr);
    }
    catch (const std::exception& e)
    {
      return JS_ThrowInternalError(ctx, "CSR is not valid PEM: %s", e.what());
    }

    auto valid_from_str = jsctx.to_str(argv[1]);
    if (!valid_from_str)
    {
      return ccf::js::constants::Exception;
    }
    auto valid_from = *valid_from_str;

    size_t validity_period_days = 0;
    if (JS_ToIndex(ctx, &validity_period_days, argv[2]) < 0)
    {
      return ccf::js::constants::Exception;
    }

    try
    {
      auto endorsed_cert = create_endorsed_cert(
        csr,
        valid_from,
        validity_period_days,
        network->identity->priv_key,
        network->identity->cert);

      return JS_NewString(ctx, endorsed_cert.str().c_str());
    }
    catch (const std::exception& e)
    {
      return JS_ThrowInternalError(
        ctx, "Failed to create endorsed cert: %s", e.what());
    }
  }

  JSValue js_network_generate_certificate(
    JSContext* ctx,
    JSValueConst this_val,
    int argc,
    [[maybe_unused]] JSValueConst* argv)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    if (argc != 2)
    {
      return JS_ThrowTypeError(ctx, "Passed %d arguments but expected 2", argc);
    }

    auto network =
      static_cast<ccf::NetworkState*>(JS_GetOpaque(this_val, network_class_id));
    if (network == nullptr)
    {
      return JS_ThrowInternalError(ctx, "Network state is not set");
    }

    auto valid_from_str = jsctx.to_str(argv[0]);
    if (!valid_from_str)
    {
      return ccf::js::constants::Exception;
    }
    auto valid_from = *valid_from_str;

    size_t validity_period_days = 0;
    if (JS_ToIndex(ctx, &validity_period_days, argv[1]) < 0)
    {
      return ccf::js::constants::Exception;
    }

    try
    {
      auto renewed_cert =
        network->identity->issue_certificate(valid_from, validity_period_days);

      return JS_NewString(ctx, renewed_cert.str().c_str());
    }
    catch (std::exception& exc)
    {
      return JS_ThrowInternalError(ctx, "Error: %s", exc.what());
    }
  }

  JSValue js_network_latest_ledger_secret_seqno(
    JSContext* ctx,
    JSValueConst this_val,
    int argc,
    [[maybe_unused]] JSValueConst* argv)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    if (argc != 0)
    {
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments but expected none", argc);
    }

    auto network =
      static_cast<ccf::NetworkState*>(JS_GetOpaque(this_val, network_class_id));

    if (network == nullptr)
    {
      return JS_ThrowInternalError(ctx, "Network state is not set");
    }

    auto tx_ptr = jsctx.globals.tx;

    if (tx_ptr == nullptr)
    {
      return JS_ThrowInternalError(
        ctx, "No transaction available to fetch latest ledger secret seqno");
    }

    int64_t latest_ledger_secret_seqno = 0;

    try
    {
      latest_ledger_secret_seqno =
        network->ledger_secrets->get_latest(*tx_ptr).first;
    }
    catch (const std::exception& e)
    {
      return JS_ThrowInternalError(
        ctx, "Failed to fetch latest ledger secret seqno: %s", e.what());
    }

    return JS_NewInt64(ctx, latest_ledger_secret_seqno);
  }

  JSValue js_rpc_set_apply_writes(
    JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    if (argc != 1)
    {
      return JS_ThrowTypeError(ctx, "Passed %d arguments but expected 1", argc);
    }

    auto rpc_ctx = jsctx.globals.rpc_ctx;
    if (rpc_ctx == nullptr)
    {
      return JS_ThrowInternalError(ctx, "RPC context is not set");
    }

    int val = JS_ToBool(ctx, argv[0]);
    if (val == -1)
    {
      return ccf::js::constants::Exception;
    }

    rpc_ctx->set_apply_writes(val);
    return ccf::js::constants::Undefined;
  }

  JSValue js_rpc_set_claims_digest(
    JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    if (argc != 1)
    {
      return JS_ThrowTypeError(ctx, "Passed %d arguments but expected 1", argc);
    }

    auto rpc_ctx = jsctx.globals.rpc_ctx;
    if (rpc_ctx == nullptr)
    {
      return JS_ThrowInternalError(ctx, "RPC context is not set");
    }

    size_t digest_size;
    uint8_t* digest = JS_GetArrayBuffer(ctx, &digest_size, argv[0]);

    if (!digest)
    {
      return JS_ThrowTypeError(ctx, "Argument must be an ArrayBuffer");
    }

    if (digest_size != ccf::ClaimsDigest::Digest::SIZE)
    {
      return JS_ThrowTypeError(
        ctx,
        "Argument must be an ArrayBuffer of the right size: %zu",
        ccf::ClaimsDigest::Digest::SIZE);
    }

    std::span<uint8_t, ccf::ClaimsDigest::Digest::SIZE> digest_bytes(
      digest, ccf::ClaimsDigest::Digest::SIZE);
    rpc_ctx->set_claims_digest(
      ccf::ClaimsDigest::Digest::from_span(digest_bytes));

    return ccf::js::constants::Undefined;
  }

  JSValue js_gov_set_jwt_public_signing_keys(
    JSContext* ctx,
    [[maybe_unused]] JSValueConst this_val,
    int argc,
    JSValueConst* argv)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    if (argc != 3)
    {
      return JS_ThrowTypeError(ctx, "Passed %d arguments but expected 3", argc);
    }

    auto tx_ptr = jsctx.globals.tx;

    if (tx_ptr == nullptr)
    {
      return JS_ThrowInternalError(ctx, "No transaction available");
    }

    auto& tx = *tx_ptr;

    auto issuer = jsctx.to_str(argv[0]);
    if (!issuer)
    {
      return JS_ThrowTypeError(ctx, "issuer argument is not a string");
    }

    auto metadata_val = jsctx.json_stringify(JSWrappedValue(ctx, argv[1]));
    if (metadata_val.is_exception())
    {
      return JS_ThrowTypeError(ctx, "metadata argument is not a JSON object");
    }
    auto metadata_json = jsctx.to_str(metadata_val);
    if (!metadata_json)
    {
      return JS_ThrowTypeError(
        ctx, "Failed to convert metadata JSON to string");
    }

    auto jwks_val = jsctx.json_stringify(JSWrappedValue(ctx, argv[2]));
    if (jwks_val.is_exception())
    {
      return JS_ThrowTypeError(ctx, "jwks argument is not a JSON object");
    }
    auto jwks_json = jsctx.to_str(jwks_val);
    if (!jwks_json)
    {
      return JS_ThrowTypeError(ctx, "Failed to convert JWKS JSON to string");
    }

    try
    {
      auto metadata =
        nlohmann::json::parse(*metadata_json).get<ccf::JwtIssuerMetadata>();
      auto jwks = nlohmann::json::parse(*jwks_json).get<ccf::JsonWebKeySet>();
      auto success =
        ccf::set_jwt_public_signing_keys(tx, "<js>", *issuer, metadata, jwks);
      if (!success)
      {
        return JS_ThrowInternalError(
          ctx, "set_jwt_public_signing_keys() failed");
      }
    }
    catch (std::exception& exc)
    {
      return JS_ThrowInternalError(
        ctx, "Error setting JWT public signing keys: %s", exc.what());
    }
    return ccf::js::constants::Undefined;
  }

  JSValue js_gov_remove_jwt_public_signing_keys(
    JSContext* ctx,
    [[maybe_unused]] JSValueConst this_val,
    int argc,
    JSValueConst* argv)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    if (argc != 1)
    {
      return JS_ThrowTypeError(ctx, "Passed %d arguments but expected 1", argc);
    }

    auto tx_ptr = jsctx.globals.tx;

    if (tx_ptr == nullptr)
    {
      return JS_ThrowInternalError(ctx, "No transaction available");
    }

    auto issuer = jsctx.to_str(argv[0]);
    if (!issuer)
    {
      return JS_ThrowTypeError(ctx, "issuer argument is not a string");
    }

    try
    {
      auto& tx = *tx_ptr;
      ccf::remove_jwt_public_signing_keys(tx, *issuer);
    }
    catch (std::exception& exc)
    {
      return JS_ThrowInternalError(
        ctx, "Failed to remove JWT public signing keys: %s", exc.what());
    }
    return ccf::js::constants::Undefined;
  }

  JSValue js_node_trigger_recovery_shares_refresh(
    JSContext* ctx,
    JSValueConst this_val,
    int argc,
    [[maybe_unused]] JSValueConst* argv)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    if (argc != 0)
    {
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments but expected none", argc);
    }

    auto gov_effects = static_cast<ccf::AbstractGovernanceEffects*>(
      JS_GetOpaque(this_val, node_class_id));
    auto tx_ptr = jsctx.globals.tx;

    if (tx_ptr == nullptr)
    {
      return JS_ThrowInternalError(
        ctx, "No transaction available to open service");
    }

    try
    {
      gov_effects->trigger_recovery_shares_refresh(*tx_ptr);
    }
    catch (const std::exception& e)
    {
      GOV_FAIL_FMT("Unable to trigger recovery shares refresh: {}", e.what());
      return JS_ThrowInternalError(
        ctx, "Unable to trigger recovery shares refresh: %s", e.what());
    }

    return ccf::js::constants::Undefined;
  }

  JSValue js_trigger_ledger_chunk(
    JSContext* ctx,
    JSValueConst this_val,
    [[maybe_unused]] int argc,
    [[maybe_unused]] JSValueConst* argv)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    auto gov_effects = static_cast<ccf::AbstractGovernanceEffects*>(
      JS_GetOpaque(this_val, node_class_id));
    auto tx_ptr = jsctx.globals.tx;

    if (tx_ptr == nullptr)
    {
      return JS_ThrowInternalError(ctx, "No transaction available");
    }

    try
    {
      gov_effects->trigger_ledger_chunk(*tx_ptr);
    }
    catch (const std::exception& e)
    {
      GOV_FAIL_FMT("Unable to force ledger chunk: {}", e.what());
      return JS_ThrowInternalError(
        ctx, "Unable to force ledger chunk: %s", e.what());
    }

    return ccf::js::constants::Undefined;
  }

  JSValue js_trigger_snapshot(
    JSContext* ctx,
    JSValueConst this_val,
    [[maybe_unused]] int argc,
    [[maybe_unused]] JSValueConst* argv)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    auto gov_effects = static_cast<ccf::AbstractGovernanceEffects*>(
      JS_GetOpaque(this_val, node_class_id));
    auto tx_ptr = jsctx.globals.tx;

    if (tx_ptr == nullptr)
    {
      return JS_ThrowInternalError(ctx, "No transaction available");
    }

    try
    {
      gov_effects->trigger_snapshot(*tx_ptr);
    }
    catch (const std::exception& e)
    {
      GOV_FAIL_FMT("Unable to request snapshot: {}", e.what());
      return JS_ThrowInternalError(
        ctx, "Unable to request snapshot: %s", e.what());
    }

    return ccf::js::constants::Undefined;
  }

  JSValue get_string_array(
    JSContext* ctx, JSValueConst& argv, std::vector<std::string>& out)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);
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
          ctx, "First argument must be an array of strings, found non-string");
      }
      auto s = jsctx.to_str(arg_val);
      if (!s)
      {
        return JS_ThrowTypeError(
          ctx, "Failed to extract C string from JS string at position %d", i);
      }
      out.push_back(*s);
    }

    return ccf::js::constants::Undefined;
  }

  JSValue js_trigger_acme_refresh(
    JSContext* ctx,
    JSValueConst this_val,
    [[maybe_unused]] int argc,
    [[maybe_unused]] JSValueConst* argv)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    auto gov_effects = static_cast<ccf::AbstractGovernanceEffects*>(
      JS_GetOpaque(this_val, node_class_id));
    auto tx_ptr = jsctx.globals.tx;

    if (tx_ptr == nullptr)
    {
      return JS_ThrowInternalError(ctx, "No transaction available");
    }

    try
    {
      std::optional<std::vector<std::string>> opt_interfaces = std::nullopt;

      if (argc > 0)
      {
        std::vector<std::string> interfaces;
        JSValue r = get_string_array(ctx, argv[0], interfaces);

        if (!JS_IsUndefined(r))
        {
          return r;
        }

        opt_interfaces = interfaces;
      }

      gov_effects->trigger_acme_refresh(*tx_ptr, opt_interfaces);
    }
    catch (const std::exception& e)
    {
      GOV_FAIL_FMT("Unable to request snapshot: {}", e.what());
      return JS_ThrowInternalError(
        ctx, "Unable to request snapshot: %s", e.what());
    }

    return ccf::js::constants::Undefined;
  }

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

    JSValue r = get_string_array(ctx, argv[0], process_args);
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
      host_processes->trigger_host_process_launch(process_args, process_input);
    }
    catch (const std::exception& e)
    {
      return JS_ThrowInternalError(
        ctx, "Unable to launch host process: %s", e.what());
    }

    return ccf::js::constants::Undefined;
  }

  JSWrappedValue load_app_module(
    JSContext* ctx, const char* module_name, kv::Tx* tx)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    std::string module_name_kv(module_name);
    if (module_name_kv[0] != '/')
    {
      module_name_kv.insert(0, "/");
    }
    // conforms to quickjs' default module filename normalizer
    auto module_name_quickjs = module_name_kv.c_str() + 1;

    auto loaded_module = jsctx.get_module_from_cache(module_name_quickjs);
    if (loaded_module.has_value())
    {
      LOG_TRACE_FMT("Using module from interpreter cache '{}'", module_name_kv);
      return loaded_module.value();
    }

    const auto modules = tx->ro<ccf::Modules>(ccf::Tables::MODULES);

    std::optional<std::vector<uint8_t>> bytecode;
    const auto modules_quickjs_bytecode = tx->ro<ccf::ModulesQuickJsBytecode>(
      ccf::Tables::MODULES_QUICKJS_BYTECODE);
    bytecode = modules_quickjs_bytecode->get(module_name_kv);
    if (bytecode)
    {
      auto modules_quickjs_version = tx->ro<ccf::ModulesQuickJsVersion>(
        ccf::Tables::MODULES_QUICKJS_VERSION);
      if (modules_quickjs_version->get() != std::string(ccf::quickjs_version))
        bytecode = std::nullopt;
    }

    JSWrappedValue module_val;

    if (!bytecode)
    {
      LOG_TRACE_FMT("Loading module '{}'", module_name_kv);

      auto module = modules->get(module_name_kv);
      auto& js = module.value();

      const char* buf = js.c_str();
      size_t buf_len = js.size();
      module_val = jsctx.eval(
        buf,
        buf_len,
        module_name_quickjs,
        JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_COMPILE_ONLY);
      if (module_val.is_exception())
      {
        auto [reason, trace] = js::js_error_message(jsctx);

        auto& rt = jsctx.runtime();
        if (rt.log_exception_details)
        {
          CCF_APP_FAIL("{}: {}", reason, trace.value_or("<no trace>"));
        }

        throw std::runtime_error(fmt::format(
          "Failed to compile module '{}': {}", module_name, reason));
      }
    }
    else
    {
      LOG_TRACE_FMT("Loading module from bytecode cache '{}'", module_name_kv);

      module_val = jsctx.read_object(
        bytecode->data(), bytecode->size(), JS_READ_OBJ_BYTECODE);
      if (module_val.is_exception())
      {
        auto [reason, trace] = js::js_error_message(jsctx);

        auto& rt = jsctx.runtime();
        if (rt.log_exception_details)
        {
          CCF_APP_FAIL("{}: {}", reason, trace.value_or("<no trace>"));
        }

        throw std::runtime_error(fmt::format(
          "Failed to deserialize bytecode for module '{}': {}",
          module_name,
          reason));
      }
      if (JS_ResolveModule(ctx, module_val.val) < 0)
      {
        auto [reason, trace] = js::js_error_message(jsctx);

        auto& rt = jsctx.runtime();
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

    LOG_TRACE_FMT("Adding module to interpreter cache '{}'", module_name_kv);
    jsctx.load_module_to_cache(module_name_quickjs, module_val);

    return module_val;
  }

  JSModuleDef* js_app_module_loader(
    JSContext* ctx, const char* module_name, void* opaque)
  {
    auto tx = (kv::Tx*)opaque;

    try
    {
      auto module_val = load_app_module(ctx, module_name, tx);
      return (JSModuleDef*)JS_VALUE_GET_PTR(module_val.val);
    }
    catch (const std::exception& exc)
    {
      JS_ThrowReferenceError(ctx, "%s", exc.what());
      js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);
      auto [reason, trace] = js::js_error_message(jsctx);

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

  JSValue js_refresh_app_bytecode_cache(
    JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    if (argc != 0)
    {
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments but expected none", argc);
    }

    auto tx_ptr = jsctx.globals.tx;

    if (tx_ptr == nullptr)
    {
      return JS_ThrowInternalError(ctx, "No transaction available");
    }

    auto& tx = *tx_ptr;

    js::Context ctx2(js::TxAccess::APP_RW);
    ctx2.runtime().set_runtime_options(
      tx_ptr, js::RuntimeLimitsPolicy::NO_LOWER_THAN_DEFAULTS);
    JS_SetModuleLoaderFunc(
      ctx2.runtime(), nullptr, js::js_app_module_loader, &tx);

    auto modules = tx.ro<ccf::Modules>(ccf::Tables::MODULES);
    auto quickjs_version =
      tx.wo<ccf::ModulesQuickJsVersion>(ccf::Tables::MODULES_QUICKJS_VERSION);
    auto quickjs_bytecode =
      tx.wo<ccf::ModulesQuickJsBytecode>(ccf::Tables::MODULES_QUICKJS_BYTECODE);

    quickjs_version->put(ccf::quickjs_version);
    quickjs_bytecode->clear();

    try
    {
      modules->foreach([&](const auto& name, const auto& src) {
        auto module_val = load_app_module(ctx2, name.c_str(), &tx);

        uint8_t* out_buf;
        size_t out_buf_len;
        int flags = JS_WRITE_OBJ_BYTECODE;
        out_buf = JS_WriteObject(ctx2, &out_buf_len, module_val.val, flags);
        if (!out_buf)
        {
          throw std::runtime_error(fmt::format(
            "Unable to serialize bytecode for JS module '{}'", name));
        }

        quickjs_bytecode->put(name, {out_buf, out_buf + out_buf_len});

        js_free(ctx2, out_buf);

        return true;
      });
    }
    catch (std::runtime_error& exc)
    {
      return JS_ThrowInternalError(
        ctx, "Failed to refresh bytecode: %s", exc.what());
    }

    return ccf::js::constants::Undefined;
  }

  // Partially replicates https://developer.mozilla.org/en-US/docs/Web/API/Body
  // with a synchronous interface.
  static const JSCFunctionListEntry js_body_proto_funcs[] = {
    JS_CFUNC_DEF("text", 0, js_body_text),
    JS_CFUNC_DEF("json", 0, js_body_json),
    JS_CFUNC_DEF("arrayBuffer", 0, js_body_array_buffer),
  };

  // Not thread-safe, must happen exactly once
  void register_class_ids()
  {
    JS_NewClassID(&kv_class_id);
    kv_exotic_methods.get_own_property = js_kv_lookup;
    kv_class_def.class_name = "KV Tables";
    kv_class_def.exotic = &kv_exotic_methods;

    JS_NewClassID(&kv_historical_class_id);
    kv_historical_exotic_methods.get_own_property = js_historical_kv_lookup;
    kv_historical_class_def.class_name = "Read-only Historical KV Tables";
    kv_historical_class_def.exotic = &kv_historical_exotic_methods;

    JS_NewClassID(&kv_map_handle_class_id);
    kv_map_handle_class_def.class_name = "KV Map Handle";

    JS_NewClassID(&body_class_id);
    body_class_def.class_name = "Current Request Body";

    JS_NewClassID(&node_class_id);
    node_class_def.class_name = "Node";

    JS_NewClassID(&network_class_id);
    network_class_def.class_name = "Network";

    JS_NewClassID(&rpc_class_id);
    rpc_class_def.class_name = "RPC";

    JS_NewClassID(&host_class_id);
    host_class_def.class_name = "Host";

    JS_NewClassID(&consensus_class_id);
    consensus_class_def.class_name = "Consensus";

    JS_NewClassID(&historical_class_id);
    historical_class_def.class_name = "Historical";

    JS_NewClassID(&historical_state_class_id);
    historical_state_class_def.class_name = "HistoricalState";
  }

  std::optional<std::stringstream> stringify_args(
    JSContext* ctx, int argc, JSValueConst* argv)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    int i;
    std::optional<std::string> str;
    std::stringstream ss;

    for (i = 0; i < argc; i++)
    {
      if (i != 0)
      {
        ss << ' ';
      }
      if (!JS_IsError(ctx, argv[i]) && JS_IsObject(argv[i]))
      {
        auto rval = jsctx.json_stringify(JSWrappedValue(ctx, argv[i]));
        str = jsctx.to_str(rval);
      }
      else
      {
        str = jsctx.to_str(argv[i]);
      }
      if (!str)
      {
        return std::nullopt;
      }
      ss << *str;
    }
    return ss;
  }

  JSValue js_info(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
  {
    const auto ss = stringify_args(ctx, argc, argv);
    if (!ss.has_value())
    {
      return ccf::js::constants::Exception;
    }

    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);
    log_info_with_tag(jsctx.access, ss->str());
    return ccf::js::constants::Undefined;
  }

  JSValue js_fail(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
  {
    const auto ss = stringify_args(ctx, argc, argv);
    if (!ss.has_value())
    {
      return ccf::js::constants::Exception;
    }

    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);
    switch (jsctx.access)
    {
      case (js::TxAccess::APP_RO):
      case (js::TxAccess::APP_RW):
      {
        CCF_APP_FAIL("{}", ss->str());
        break;
      }

      case (js::TxAccess::GOV_RO):
      case (js::TxAccess::GOV_RW):
      {
        GOV_FAIL_FMT("{}", ss->str());
        break;
      }

      default:
      {
        LOG_FAIL_FMT("{}", ss->str());
        break;
      }
    }
    return ccf::js::constants::Undefined;
  }

  JSValue js_fatal(JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
  {
    const auto ss = stringify_args(ctx, argc, argv);
    if (!ss.has_value())
    {
      return ccf::js::constants::Exception;
    }

    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);
    switch (jsctx.access)
    {
      case (js::TxAccess::APP_RO):
      case (js::TxAccess::APP_RW):
      {
        CCF_APP_FATAL("{}", ss->str());
        break;
      }

      case (js::TxAccess::GOV_RO):
      case (js::TxAccess::GOV_RW):
      {
        GOV_FATAL_FMT("{}", ss->str());
        break;
      }

      default:
      {
        LOG_FATAL_FMT("{}", ss->str());
        break;
      }
    }
    return ccf::js::constants::Undefined;
  }

  std::pair<std::string, std::optional<std::string>> js_error_message(
    Context& ctx)
  {
    auto exception_val = ctx.get_exception();
    std::optional<std::string> message;
    bool is_error = exception_val.is_error();
    if (!is_error && exception_val.is_obj())
    {
      auto rval = ctx.json_stringify(exception_val);
      message = ctx.to_str(rval);
    }
    else
    {
      message = ctx.to_str(exception_val);
    }

    std::optional<std::string> trace = std::nullopt;
    if (is_error)
    {
      auto val = exception_val["stack"];
      if (!val.is_undefined())
      {
        trace = ctx.to_str(val);
      }
    }
    return {message.value_or(""), trace};
  }

  static JSValue js_enable_untrusted_date_time(
    JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
  {
    if (argc != 1)
    {
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 1", argc);
    }

    const auto v = argv[0];
    if (!JS_IsBool(v))
    {
      return JS_ThrowTypeError(ctx, "First argument must be a boolean");
    }
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    const auto previous = jsctx.implement_untrusted_time;
    jsctx.implement_untrusted_time = JS_ToBool(ctx, v);

    return JS_NewBool(ctx, previous);
  }

  static JSValue js_enable_metrics_logging(
    JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
  {
    if (argc != 1)
    {
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 1", argc);
    }

    const auto v = argv[0];
    if (!JS_IsBool(v))
    {
      return JS_ThrowTypeError(ctx, "First argument must be a boolean");
    }

    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);
    const auto previous = jsctx.log_execution_metrics;
    jsctx.log_execution_metrics = JS_ToBool(ctx, v);

    return JS_NewBool(ctx, previous);
  }

  JSWrappedValue Context::default_function(
    const std::string& code, const std::string& path)

  {
    return function(code, "default", path);
  }

  JSWrappedValue Context::function(
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

    return function(module, func, path);
  }

  JSWrappedValue Context::function(
    const JSWrappedValue& module,
    const std::string& func,
    const std::string& path)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);
    auto eval_val = eval_function(module);

    if (eval_val.is_exception())
    {
      auto [reason, trace] = js::js_error_message(jsctx);

      if (rt.log_exception_details)
      {
        CCF_APP_FAIL("{}: {}", reason, trace.value_or("<no trace>"));
      }
      throw std::runtime_error(
        fmt::format("Failed to execute {}: {}", path, reason));
    }

    // Get exported function from module
    assert(JS_VALUE_GET_TAG(module.val) == JS_TAG_MODULE);
    auto module_def = (JSModuleDef*)JS_VALUE_GET_PTR(module.val);
    auto export_count = JS_GetModuleExportEntriesCount(module_def);
    for (auto i = 0; i < export_count; i++)
    {
      auto export_name_atom = JS_GetModuleExportEntryName(ctx, module_def, i);
      auto export_name = jsctx.to_str(export_name_atom);
      JS_FreeAtom(ctx, export_name_atom);
      if (export_name.value_or("") == func)
      {
        auto export_func = get_module_export_entry(module_def, i);
        if (!JS_IsFunction(ctx, export_func.val))
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

  void register_request_body_class(JSContext* ctx)
  {
    // Set prototype for request body class
    JSValue body_proto = JS_NewObject(ctx);
    size_t func_count =
      sizeof(js_body_proto_funcs) / sizeof(js_body_proto_funcs[0]);
    JS_SetPropertyFunctionList(
      ctx, body_proto, js_body_proto_funcs, func_count);
    JS_SetClassProto(ctx, body_class_id, body_proto);
  }

  static JSWrappedValue create_console_obj(JSContext* ctx)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);
    auto console = jsctx.new_obj();

    console.set("log", jsctx.new_c_function(js_info, "log", 1));
    console.set("info", jsctx.new_c_function(js_info, "info", 1));
    console.set("warn", jsctx.new_c_function(js_fail, "warn", 1));
    console.set("error", jsctx.new_c_function(js_fatal, "error", 1));

    return console;
  }

  void populate_global_console(Context& ctx)
  {
    auto global_obj = ctx.get_global_obj();
    global_obj.set("console", create_console_obj(ctx));
  }

  void populate_global_ccf(js::Context& ctx)
  {
    auto ccf = ctx.new_obj();

    ccf.set("strToBuf", ctx.new_c_function(js_str_to_buf, "strToBuf", 1));
    ccf.set("bufToStr", ctx.new_c_function(js_buf_to_str, "bufToStr", 1));

    ccf.set(
      "jsonCompatibleToBuf",
      ctx.new_c_function(js_json_compatible_to_buf, "jsonCompatibleToBuf", 1));
    ccf.set(
      "bufToJsonCompatible",
      ctx.new_c_function(js_buf_to_json_compatible, "bufToJsonCompatible", 1));

    ccf.set(
      "enableUntrustedDateTime",
      ctx.new_c_function(
        js_enable_untrusted_date_time, "enableUntrustedDateTime", 1));

    ccf.set(
      "enableMetricsLogging",
      ctx.new_c_function(js_enable_metrics_logging, "enableMetricsLogging", 1));

    ccf.set("pemToId", ctx.new_c_function(js_pem_to_id, "pemToId", 1));

    auto global_obj = ctx.get_global_obj();
    global_obj.set("ccf", std::move(ccf));
  }

  static JSValue js_random_impl(
    JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
  {
    crypto::EntropyPtr entropy = crypto::get_entropy();

    // Generate a random 64 bit unsigned int, and transform that to a double
    // between 0 and 1. Note this is non-uniform, and not cryptographically
    // sound.
    union
    {
      double d;
      uint64_t u;
    } u;
    try
    {
      u.u = entropy->random64();
    }
    catch (const std::exception& e)
    {
      return JS_ThrowInternalError(
        ctx, "Failed to generate random number: %s", e.what());
    }
    // From QuickJS - set exponent to 1, and shift random bytes to fractional
    // part, producing 1.0 <= u.d < 2
    u.u = ((uint64_t)1023 << 52) | (u.u >> 12);

    return JS_NewFloat64(ctx, u.d - 1.0);
  }

  void override_builtin_funcs(js::Context& ctx)
  {
    // Overriding built-in Math.random
    auto math_val = ctx.get_global_property("Math");
    math_val.set("random", ctx.new_c_function(js_random_impl, "random", 0));
  }

  void populate_global_ccf_crypto(js::Context& ctx)
  {
    auto crypto = JS_NewObject(ctx);

    JS_SetPropertyStr(
      ctx, crypto, "sign", JS_NewCFunction(ctx, js_sign, "sign", 3));
    JS_SetPropertyStr(
      ctx,
      crypto,
      "verifySignature",
      JS_NewCFunction(ctx, js_verify_signature, "verifySignature", 4));
    JS_SetPropertyStr(
      ctx,
      crypto,
      "pubPemToJwk",
      JS_NewCFunction(
        ctx, js_pem_to_jwk<crypto::JsonWebKeyECPublic>, "pubPemToJwk", 1));
    JS_SetPropertyStr(
      ctx,
      crypto,
      "pemToJwk",
      JS_NewCFunction(
        ctx, js_pem_to_jwk<crypto::JsonWebKeyECPrivate>, "pemToJwk", 1));
    JS_SetPropertyStr(
      ctx,
      crypto,
      "pubRsaPemToJwk",
      JS_NewCFunction(
        ctx, js_pem_to_jwk<crypto::JsonWebKeyRSAPublic>, "pubRsaPemToJwk", 1));
    JS_SetPropertyStr(
      ctx,
      crypto,
      "rsaPemToJwk",
      JS_NewCFunction(
        ctx, js_pem_to_jwk<crypto::JsonWebKeyRSAPrivate>, "rsaPemToJwk", 1));
    JS_SetPropertyStr(
      ctx,
      crypto,
      "pubEddsaPemToJwk",
      JS_NewCFunction(
        ctx,
        js_pem_to_jwk<crypto::JsonWebKeyEdDSAPublic>,
        "pubEddsaPemToJwk",
        1));
    JS_SetPropertyStr(
      ctx,
      crypto,
      "eddsaPemToJwk",
      JS_NewCFunction(
        ctx,
        js_pem_to_jwk<crypto::JsonWebKeyEdDSAPrivate>,
        "eddsaPemToJwk",
        1));
    JS_SetPropertyStr(
      ctx,
      crypto,
      "pubJwkToPem",
      JS_NewCFunction(
        ctx, js_jwk_to_pem<crypto::JsonWebKeyECPublic>, "pubJwkToPem", 1));
    JS_SetPropertyStr(
      ctx,
      crypto,
      "jwkToPem",
      JS_NewCFunction(
        ctx, js_jwk_to_pem<crypto::JsonWebKeyECPrivate>, "jwkToPem", 1));
    JS_SetPropertyStr(
      ctx,
      crypto,
      "pubRsaJwkToPem",
      JS_NewCFunction(
        ctx, js_jwk_to_pem<crypto::JsonWebKeyRSAPublic>, "pubRsaJwkToPem", 1));
    JS_SetPropertyStr(
      ctx,
      crypto,
      "rsaJwkToPem",
      JS_NewCFunction(
        ctx, js_jwk_to_pem<crypto::JsonWebKeyRSAPrivate>, "rsaJwkToPem", 1));
    JS_SetPropertyStr(
      ctx,
      crypto,
      "pubEddsaJwkToPem",
      JS_NewCFunction(
        ctx,
        js_jwk_to_pem<crypto::JsonWebKeyEdDSAPublic>,
        "pubEddsaJwkToPem",
        1));
    JS_SetPropertyStr(
      ctx,
      crypto,
      "eddsaJwkToPem",
      JS_NewCFunction(
        ctx,
        js_jwk_to_pem<crypto::JsonWebKeyEdDSAPrivate>,
        "eddsaJwkToPem",
        1));
    JS_SetPropertyStr(
      ctx,
      crypto,
      "generateAesKey",
      JS_NewCFunction(ctx, js_generate_aes_key, "generateAesKey", 1));
    JS_SetPropertyStr(
      ctx,
      crypto,
      "generateRsaKeyPair",
      JS_NewCFunction(ctx, js_generate_rsa_key_pair, "generateRsaKeyPair", 1));
    JS_SetPropertyStr(
      ctx,
      crypto,
      "generateEcdsaKeyPair",
      JS_NewCFunction(
        ctx, js_generate_ecdsa_key_pair, "generateEcdsaKeyPair", 1));
    JS_SetPropertyStr(
      ctx,
      crypto,
      "generateEddsaKeyPair",
      JS_NewCFunction(
        ctx, js_generate_eddsa_key_pair, "generateEddsaKeyPair", 1));
    JS_SetPropertyStr(
      ctx, crypto, "wrapKey", JS_NewCFunction(ctx, js_wrap_key, "wrapKey", 3));
    JS_SetPropertyStr(
      ctx,
      crypto,
      "unwrapKey",
      JS_NewCFunction(ctx, js_unwrap_key, "unwrapKey", 3));
    JS_SetPropertyStr(
      ctx, crypto, "digest", JS_NewCFunction(ctx, js_digest, "digest", 2));
    JS_SetPropertyStr(
      ctx,
      crypto,
      "isValidX509CertBundle",
      JS_NewCFunction(
        ctx, js_is_valid_x509_cert_bundle, "isValidX509CertBundle", 1));
    JS_SetPropertyStr(
      ctx,
      crypto,
      "isValidX509CertChain",
      JS_NewCFunction(
        ctx, js_is_valid_x509_cert_chain, "isValidX509CertChain", 2));

    auto ccf = ctx.get_global_property("ccf");
    ccf.set("crypto", std::move(crypto));
  }

  void init_globals(js::Context& ctx)
  {
    populate_global_ccf(ctx);

    // Always available, no other dependencies
    populate_global_ccf_crypto(ctx);
    populate_global_console(ctx);

    override_builtin_funcs(ctx);

    for (auto& plugin : ffi_plugins)
    {
      plugin.extend(ctx);
    }
  }

  void populate_global_ccf_kv(kv::Tx& tx, js::Context& ctx)
  {
    auto kv = ctx.new_obj_class(kv_class_id);
    ctx.globals.tx = &tx;

    auto ccf = ctx.get_global_property("ccf");
    ccf.set("kv", std::move(kv));
  }

  JSValue create_historical_state_object(
    js::Context& jsctx, ccf::historical::StatePtr state)
  {
    auto js_state = jsctx.new_obj_class(historical_state_class_id);
    JS_CHECK_EXC(js_state);

    const auto transaction_id = state->transaction_id;
    auto transaction_id_s = jsctx.new_string(transaction_id.to_str());
    JS_CHECK_EXC(transaction_id_s);
    JS_CHECK_SET(js_state.set("transactionId", std::move(transaction_id_s)));

    // NB: ccf_receipt_to_js returns a JSValue (unwrapped), due to its use of
    // macros. So we must rewrap it here, immediately after returning
    auto js_receipt = jsctx(ccf_receipt_to_js(jsctx, state->receipt));
    JS_CHECK_EXC(js_receipt);
    JS_CHECK_SET(js_state.set("receipt", std::move(js_receipt)));

    auto kv = jsctx.new_obj_class(kv_historical_class_id);
    JS_CHECK_EXC(kv);
    JS_SetOpaque(kv.val, reinterpret_cast<void*>(transaction_id.seqno));
    JS_CHECK_SET(js_state.set("kv", std::move(kv)));

    try
    {
      // Create a tx which will be used to access this state
      auto tx = state->store->create_read_only_tx_ptr();
      // Extend lifetime of state and tx, by storing on the ctx
      jsctx.globals.historical_handles[transaction_id.seqno] = {
        state, std::move(tx)};
    }
    catch (const std::exception& e)
    {
      return JS_ThrowInternalError(
        jsctx, "Failed to create read-only historical tx: %s", e.what());
    }

    return js_state.take();
  }

  void populate_global_ccf_node(
    ccf::AbstractGovernanceEffects* gov_effects, js::Context& ctx)
  {
    auto node = JS_NewObjectClass(ctx, node_class_id);
    JS_SetOpaque(node, gov_effects);
    JS_SetPropertyStr(
      ctx,
      node,
      "triggerLedgerRekey",
      JS_NewCFunction(
        ctx, js_node_trigger_ledger_rekey, "triggerLedgerRekey", 0));
    JS_SetPropertyStr(
      ctx,
      node,
      "transitionServiceToOpen",
      JS_NewCFunction(
        ctx, js_node_transition_service_to_open, "transitionServiceToOpen", 2));
    JS_SetPropertyStr(
      ctx,
      node,
      "triggerRecoverySharesRefresh",
      JS_NewCFunction(
        ctx,
        js_node_trigger_recovery_shares_refresh,
        "triggerRecoverySharesRefresh",
        0));
    JS_SetPropertyStr(
      ctx,
      node,
      "triggerLedgerChunk",
      JS_NewCFunction(ctx, js_trigger_ledger_chunk, "triggerLedgerChunk", 0));
    JS_SetPropertyStr(
      ctx,
      node,
      "triggerSnapshot",
      JS_NewCFunction(ctx, js_trigger_snapshot, "triggerSnapshot", 0));
    JS_SetPropertyStr(
      ctx,
      node,
      "triggerACMERefresh",
      JS_NewCFunction(ctx, js_trigger_acme_refresh, "triggerACMERefresh", 0));

    auto ccf = ctx.get_global_property("ccf");
    ccf.set("node", std::move(node));
  }

  void populate_global_ccf_gov_actions(js::Context& ctx)
  {
    auto ccf = ctx.get_global_property("ccf");

    ccf.set(
      "refreshAppBytecodeCache",
      ctx.new_c_function(
        js_refresh_app_bytecode_cache, "refreshAppBytecodeCache", 0));
    ccf.set(
      "setJwtPublicSigningKeys",
      ctx.new_c_function(
        js_gov_set_jwt_public_signing_keys, "setJwtPublicSigningKeys", 3));
    ccf.set(
      "removeJwtPublicSigningKeys",
      ctx.new_c_function(
        js_gov_remove_jwt_public_signing_keys,
        "removeJwtPublicSigningKeys",
        1));
  }

  void populate_global_ccf_host(
    ccf::AbstractHostProcesses* host_processes, js::Context& ctx)
  {
    auto host = JS_NewObjectClass(ctx, host_class_id);
    JS_SetOpaque(host, host_processes);

    JS_SetPropertyStr(
      ctx,
      host,
      "triggerSubprocess",
      JS_NewCFunction(
        ctx, js_node_trigger_host_process_launch, "triggerSubprocess", 1));

    auto ccf = ctx.get_global_property("ccf");
    ccf.set("host", std::move(host));
  }

  void populate_global_ccf_network(
    ccf::NetworkState* network_state, js::Context& ctx)
  {
    auto network = JS_NewObjectClass(ctx, network_class_id);
    JS_SetOpaque(network, network_state);

    JS_SetPropertyStr(
      ctx,
      network,
      "getLatestLedgerSecretSeqno",
      JS_NewCFunction(
        ctx,
        js_network_latest_ledger_secret_seqno,
        "getLatestLedgerSecretSeqno",
        0));
    JS_SetPropertyStr(
      ctx,
      network,
      "generateEndorsedCertificate",
      JS_NewCFunction(
        ctx,
        js_network_generate_endorsed_certificate,
        "generateEndorsedCertificate",
        0));
    JS_SetPropertyStr(
      ctx,
      network,
      "generateNetworkCertificate",
      JS_NewCFunction(
        ctx, js_network_generate_certificate, "generateNetworkCertificate", 0));

    auto ccf = ctx.get_global_property("ccf");
    ccf.set("network", std::move(network));
  }

  void populate_global_ccf_rpc(ccf::RpcContext* rpc_ctx, js::Context& ctx)
  {
    auto rpc = JS_NewObjectClass(ctx, rpc_class_id);
    ctx.globals.rpc_ctx = rpc_ctx;
    JS_SetPropertyStr(
      ctx,
      rpc,
      "setApplyWrites",
      JS_NewCFunction(ctx, js_rpc_set_apply_writes, "setApplyWrites", 1));
    JS_SetPropertyStr(
      ctx,
      rpc,
      "setClaimsDigest",
      JS_NewCFunction(ctx, js_rpc_set_claims_digest, "setClaimsDigest", 1));

    auto ccf = ctx.get_global_property("ccf");
    ccf.set("rpc", std::move(rpc));
  }

  void populate_global_ccf_consensus(
    ccf::BaseEndpointRegistry* endpoint_registry, js::Context& ctx)
  {
    auto consensus = JS_NewObjectClass(ctx, consensus_class_id);
    JS_SetOpaque(consensus, endpoint_registry);

    JS_SetPropertyStr(
      ctx,
      consensus,
      "getLastCommittedTxId",
      JS_NewCFunction(
        ctx, js_consensus_get_last_committed_txid, "getLastCommittedTxId", 0));
    JS_SetPropertyStr(
      ctx,
      consensus,
      "getStatusForTxId",
      JS_NewCFunction(
        ctx, js_consensus_get_status_for_txid, "getStatusForTxId", 2));
    JS_SetPropertyStr(
      ctx,
      consensus,
      "getViewForSeqno",
      JS_NewCFunction(
        ctx, js_consensus_get_view_for_seqno, "getViewForSeqno", 1));

    auto ccf = ctx.get_global_property("ccf");
    ccf.set("consensus", std::move(consensus));
  }

  void populate_global_ccf_historical(
    ccf::historical::AbstractStateCache* historical_state, js::Context& ctx)
  {
    auto historical = JS_NewObjectClass(ctx, historical_class_id);

    JS_SetOpaque(historical, historical_state);
    JS_SetPropertyStr(
      ctx,
      historical,
      "getStateRange",
      JS_NewCFunction(ctx, js_historical_get_state_range, "getStateRange", 4));
    JS_SetPropertyStr(
      ctx,
      historical,
      "dropCachedStates",
      JS_NewCFunction(
        ctx, js_historical_drop_cached_states, "dropCachedStates", 1));

    auto ccf = ctx.get_global_property("ccf");
    ccf.set("historical", std::move(historical));
  }

  void invalidate_globals(js::Context& ctx)
  {
    // Reset any state that has been stored on the ctx object to implement
    // globals. This should be called at the end of any invocation where the
    // globals may point to locally-scoped memory, and the Context itself (the
    // interpreter) may live longer and be reused for future calls. Those calls
    // must re-populate the globals appropriately, pointing to their own local
    // instances of state as required.

    ctx.globals.tx = nullptr;

    // Any KV handles which have been created with reference to this tx should
    // no longer be accessed. Any future calls on these JSValues will
    // re-populate this map with fresh KVMap::Handle*s
    ctx.globals.kv_handles.clear();

    ctx.globals.historical_handles.clear();

    ctx.globals.rpc_ctx = nullptr;
  }

  void Runtime::add_ccf_classdefs()
  {
    std::vector<std::pair<JSClassID, JSClassDef*>> classes{
      {kv_class_id, &kv_class_def},
      {kv_historical_class_id, &kv_historical_class_def},
      {kv_map_handle_class_id, &kv_map_handle_class_def},
      {body_class_id, &body_class_def},
      {node_class_id, &node_class_def},
      {network_class_id, &network_class_def},
      {rpc_class_id, &rpc_class_def},
      {host_class_id, &host_class_def},
      {consensus_class_id, &consensus_class_def},
      {historical_class_id, &historical_class_def},
      {historical_state_class_id, &historical_state_class_def}};
    for (auto [class_id, class_def] : classes)
    {
      auto ret = JS_NewClass(rt, class_id, class_def);
      if (ret != 0)
        throw std::logic_error(fmt::format(
          "Failed to register JS class definition {}", class_def->class_name));
    }
  }

  void Runtime::reset_runtime_options()
  {
    JS_SetMaxStackSize(rt, 0);
    JS_SetMemoryLimit(rt, -1);
    JS_SetInterruptHandler(rt, NULL, NULL);
  }

  void Runtime::set_runtime_options(kv::Tx* tx, RuntimeLimitsPolicy policy)
  {
    size_t stack_size = default_stack_size;
    size_t heap_size = default_heap_size;

    const auto jsengine = tx->ro<ccf::JSEngine>(ccf::Tables::JSENGINE);
    const std::optional<JSRuntimeOptions> js_runtime_options = jsengine->get();

    if (js_runtime_options.has_value())
    {
      bool no_lower_than_defaults =
        policy == RuntimeLimitsPolicy::NO_LOWER_THAN_DEFAULTS;

      heap_size = std::max(
        js_runtime_options.value().max_heap_bytes,
        no_lower_than_defaults ? default_heap_size : 0);
      stack_size = std::max(
        js_runtime_options.value().max_stack_bytes,
        no_lower_than_defaults ? default_stack_size : 0);
      max_exec_time = std::max(
        std::chrono::milliseconds{
          js_runtime_options.value().max_execution_time_ms},
        no_lower_than_defaults ? default_max_execution_time :
                                 std::chrono::milliseconds{0});
      log_exception_details = js_runtime_options.value().log_exception_details;
      return_exception_details =
        js_runtime_options.value().return_exception_details;
    }

    JS_SetMaxStackSize(rt, stack_size);
    JS_SetMemoryLimit(rt, heap_size);
  }

#pragma clang diagnostic pop
}

extern "C"
{
  int qjs_gettimeofday(struct JSContext* ctx, struct timeval* tv, void* tz)
  {
    if (tv != NULL)
    {
      // Opaque may be null, when this is called during Context construction
      const ccf::js::Context* jsctx =
        (ccf::js::Context*)JS_GetContextOpaque(ctx);
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
