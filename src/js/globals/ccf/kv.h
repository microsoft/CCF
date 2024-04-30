// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "js/checks.h"
#include "js/core/context.h"
#include "js/global_class_ids.h"
#include "js/map_access_permissions.h"
#include "js/tx_access.h"
#include "kv/untyped_map.h"

namespace ccf::js
{
  namespace
  {
    using KVMap = kv::untyped::Map;

    using HandleGetter = KVMap::
      ReadOnlyHandle* (*)(js::core::Context& jsctx, JSValueConst this_val);

    static constexpr char const* access_permissions_explanation_url =
      "https://microsoft.github.io/CCF/main/audit/read_write_restrictions.html";

#define JS_KV_PERMISSION_ERROR_HELPER(C_FUNC_NAME, JS_METHOD_NAME) \
  static JSValue C_FUNC_NAME( \
    JSContext* ctx, JSValueConst this_val, int, JSValueConst*) \
  { \
    js::core::Context& jsctx = *(js::core::Context*)JS_GetContextOpaque(ctx); \
    const auto table_name = \
      jsctx.to_str(JS_GetPropertyStr(jsctx, this_val, "_map_name")) \
        .value_or(""); \
    if (table_name.empty()) \
    { \
      return JS_ThrowTypeError(ctx, "Internal: No map name stored on handle"); \
    } \
    const auto permission = check_kv_map_access(jsctx.access, table_name); \
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

    static KVMap::Handle* _get_map_handle(
      js::core::Context& jsctx, JSValueConst _this_val)
    {
      auto this_val = jsctx.duplicate_value(_this_val);
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

    static KVMap::ReadOnlyHandle* _get_map_handle_current(
      js::core::Context& jsctx, JSValueConst this_val)
    {
      // NB: This creates (and stores) a writeable handle internally, but
      // converts to the (subtype) ReadOnlyHandle* in return here. This means
      // that if we call has() and then put(), we'll correctly have a writeable
      // handle for the put() despite reading initially.
      return _get_map_handle(jsctx, this_val);
    }

    static KVMap::ReadOnlyHandle* _get_map_handle_historical(
      js::core::Context& jsctx, JSValueConst _this_val)
    {
      auto this_val = jsctx.duplicate_value(_this_val);
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

#define JS_CHECK_HANDLE(h) \
  do \
  { \
    if (h == nullptr) \
    { \
      return JS_ThrowInternalError( \
        ctx, "Internal: Unable to access MapHandle"); \
    } \
  } while (0)

    template <HandleGetter handle_getter_>
    static JSValue js_kv_map_has(
      JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
    {
      js::core::Context& jsctx = *(js::core::Context*)JS_GetContextOpaque(ctx);

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
      js::core::Context& jsctx = *(js::core::Context*)JS_GetContextOpaque(ctx);

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
        return ccf::js::core::constants::Undefined;
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
      js::core::Context& jsctx = *(js::core::Context*)JS_GetContextOpaque(ctx);

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
        return ccf::js::core::constants::Undefined;
      }

      return JS_NewInt64(ctx, val.value());
    }

    template <HandleGetter handle_getter_>
    static JSValue js_kv_map_size_getter(
      JSContext* ctx, JSValueConst this_val, int argc, JSValueConst*)
    {
      js::core::Context& jsctx = *(js::core::Context*)JS_GetContextOpaque(ctx);

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
      js::core::Context& jsctx = *(js::core::Context*)JS_GetContextOpaque(ctx);

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

      return ccf::js::core::constants::Undefined;
    }

    static JSValue js_kv_map_set(
      JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
    {
      js::core::Context& jsctx = *(js::core::Context*)JS_GetContextOpaque(ctx);

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
      js::core::Context& jsctx = *(js::core::Context*)JS_GetContextOpaque(ctx);

      if (argc != 0)
      {
        return JS_ThrowTypeError(
          ctx, "Passed %d arguments, but expected 0", argc);
      }

      auto handle = _get_map_handle(jsctx, this_val);
      JS_CHECK_HANDLE(handle);

      handle->clear();

      return ccf::js::core::constants::Undefined;
    }

    template <HandleGetter handle_getter_>
    static JSValue js_kv_map_foreach(
      JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
    {
      js::core::Context& jsctx = *(js::core::Context*)JS_GetContextOpaque(ctx);

      if (argc != 1)
        return JS_ThrowTypeError(
          ctx, "Passed %d arguments, but expected 1", argc);

      js::core::JSWrappedValue func(ctx, argv[0]);
      js::core::JSWrappedValue obj(ctx, this_val);

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
          std::vector<js::core::JSWrappedValue> args = {value, key, obj};

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
        return ccf::js::core::constants::Exception;
      }

      return ccf::js::core::constants::Undefined;
    }

    template <HandleGetter HG>
    static JSValue _create_kv_map_handle(
      js::core::Context& ctx,
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
      JS_CHECK_SET(view_val.set(
        "getVersionOfPreviousWrite", std::move(get_version_fn_val)));

      return view_val.take();
    }
  }

  static int js_kv_lookup(
    JSContext* ctx,
    JSPropertyDescriptor* desc,
    JSValueConst this_val,
    JSAtom property)
  {
    js::core::Context& jsctx = *(js::core::Context*)JS_GetContextOpaque(ctx);
    const auto map_name = jsctx.to_str(property).value_or("");
    LOG_TRACE_FMT("Looking for kv map '{}'", map_name);

    const auto access_permission = check_kv_map_access(jsctx.access, map_name);
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
    js::core::Context& jsctx = *(js::core::Context*)JS_GetContextOpaque(ctx);
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
}