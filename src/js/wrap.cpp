// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "js/wrap.h"

#include "ccf/tx_id.h"
#include "ds/logger.h"
#include "js/conv.cpp"
#include "js/crypto.cpp"
#include "kv/untyped_map.h"
#include "node/jwt.h"
#include "node/rpc/call_types.h"
#include "node/rpc/node_interface.h"
#include "tls/base64.h"

#include <memory>
#include <quickjs/quickjs-exports.h>
#include <quickjs/quickjs.h>

namespace js
{
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc99-extensions"

  using KVMap = kv::untyped::Map;

  JSClassID kv_class_id = 0;
  JSClassID kv_map_handle_class_id = 0;
  JSClassID body_class_id = 0;
  JSClassID node_class_id = 0;
  JSClassID network_class_id = 0;

  JSClassDef kv_class_def = {};
  JSClassExoticMethods kv_exotic_methods = {};
  JSClassDef kv_map_handle_class_def = {};
  JSClassDef body_class_def = {};
  JSClassDef node_class_def = {};
  JSClassDef network_class_def = {};

  static JSValue js_kv_map_has(
    JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
  {
    auto handle = static_cast<KVMap::Handle*>(
      JS_GetOpaque(this_val, kv_map_handle_class_id));

    if (argc != 1)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 1", argc);

    size_t key_size;
    uint8_t* key = JS_GetArrayBuffer(ctx, &key_size, argv[0]);

    if (!key)
      return JS_ThrowTypeError(ctx, "Argument must be an ArrayBuffer");

    auto has = handle->has({key, key + key_size});

    return JS_NewBool(ctx, has);
  }

  static JSValue js_kv_map_get(
    JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
  {
    auto handle = static_cast<KVMap::Handle*>(
      JS_GetOpaque(this_val, kv_map_handle_class_id));

    if (argc != 1)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 1", argc);

    size_t key_size;
    uint8_t* key = JS_GetArrayBuffer(ctx, &key_size, argv[0]);

    if (!key)
      return JS_ThrowTypeError(ctx, "Argument must be an ArrayBuffer");

    auto val = handle->get({key, key + key_size});

    if (!val.has_value())
      return JS_UNDEFINED;

    JSValue buf =
      JS_NewArrayBufferCopy(ctx, val.value().data(), val.value().size());

    if (JS_IsException(buf))
      js_dump_error(ctx);

    return buf;
  }

  static JSValue js_kv_map_delete(
    JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
  {
    auto handle = static_cast<KVMap::Handle*>(
      JS_GetOpaque(this_val, kv_map_handle_class_id));

    if (argc != 1)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 1", argc);

    size_t key_size;
    uint8_t* key = JS_GetArrayBuffer(ctx, &key_size, argv[0]);

    if (!key)
      return JS_ThrowTypeError(ctx, "Argument must be an ArrayBuffer");

    auto val = handle->remove({key, key + key_size});

    return JS_NewBool(ctx, val);
  }

  static JSValue js_kv_map_delete_read_only(
    JSContext* ctx, JSValueConst, int, JSValueConst*)
  {
    return JS_ThrowTypeError(ctx, "Cannot call delete on read-only map");
  }

  static JSValue js_kv_map_set(
    JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
  {
    auto handle = static_cast<KVMap::Handle*>(
      JS_GetOpaque(this_val, kv_map_handle_class_id));

    if (argc != 2)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 2", argc);

    size_t key_size;
    uint8_t* key = JS_GetArrayBuffer(ctx, &key_size, argv[0]);

    size_t val_size;
    uint8_t* val = JS_GetArrayBuffer(ctx, &val_size, argv[1]);

    if (!key || !val)
      return JS_ThrowTypeError(ctx, "Arguments must be ArrayBuffers");

    handle->put({key, key + key_size}, {val, val + val_size});

    return JS_DupValue(ctx, this_val);
  }

  static JSValue js_kv_map_set_read_only(
    JSContext* ctx, JSValueConst, int, JSValueConst*)
  {
    return JS_ThrowTypeError(ctx, "Cannot call set on read-only map");
  }

  static JSValue js_kv_map_foreach(
    JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
  {
    auto handle = static_cast<KVMap::Handle*>(
      JS_GetOpaque(this_val, kv_map_handle_class_id));

    if (argc != 1)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 1", argc);

    JSValue func = argv[0];

    if (!JS_IsFunction(ctx, func))
      return JS_ThrowTypeError(ctx, "Argument must be a function");

    bool failed = false;
    handle->foreach(
      [ctx, this_val, func, &failed](const auto& k, const auto& v) {
        JSValue args[3];

        // JS forEach expects (v, k, map) rather than (k, v)
        args[0] = JS_NewArrayBufferCopy(ctx, v.data(), v.size());
        args[1] = JS_NewArrayBufferCopy(ctx, k.data(), k.size());
        args[2] = JS_DupValue(ctx, this_val);

        auto val = JS_Call(ctx, func, JS_UNDEFINED, 3, args);

        JS_FreeValue(ctx, args[0]);
        JS_FreeValue(ctx, args[1]);
        JS_FreeValue(ctx, args[2]);

        if (JS_IsException(val))
        {
          js_dump_error(ctx);
          failed = true;
          return false;
        }

        JS_FreeValue(ctx, val);

        return true;
      });

    if (failed)
    {
      return JS_EXCEPTION;
    }

    return JS_UNDEFINED;
  }

  static int js_kv_lookup(
    JSContext* ctx,
    JSPropertyDescriptor* desc,
    JSValueConst this_val,
    JSAtom property)
  {
    const auto property_name_c = JS_AtomToCString(ctx, property);
    const std::string property_name(property_name_c);
    JS_FreeCString(ctx, property_name_c);
    LOG_TRACE_FMT("Looking for kv map '{}'", property_name);

    const auto [security_domain, access_category] =
      kv::parse_map_name(property_name);

    auto tx_ctx_ptr =
      static_cast<TxContext*>(JS_GetOpaque(this_val, kv_class_id));

    auto read_only = false;
    switch (access_category)
    {
      case kv::AccessCategory::INTERNAL:
      {
        if (security_domain == kv::SecurityDomain::PUBLIC)
        {
          read_only = true;
        }
        else
        {
          throw std::runtime_error(fmt::format(
            "JS application cannot access private internal CCF table '{}'",
            property_name));
        }
        break;
      }
      case kv::AccessCategory::GOVERNANCE:
      {
        read_only = tx_ctx_ptr->access != TxAccess::GOV_RW;
        break;
      }
      case kv::AccessCategory::APPLICATION:
      {
        read_only = tx_ctx_ptr->access != TxAccess::APP;
        break;
      }
      default:
      {
        throw std::logic_error(fmt::format(
          "Unhandled AccessCategory for table '{}'", property_name));
      }
    }

    auto handle = tx_ctx_ptr->tx->rw<KVMap>(property_name);

    // This follows the interface of Map:
    // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Map
    // Keys and values are ArrayBuffers. Keys are matched based on their
    // contents.
    auto view_val = JS_NewObjectClass(ctx, kv_map_handle_class_id);
    JS_SetOpaque(view_val, handle);

    JS_SetPropertyStr(
      ctx, view_val, "has", JS_NewCFunction(ctx, js_kv_map_has, "has", 1));

    JS_SetPropertyStr(
      ctx, view_val, "get", JS_NewCFunction(ctx, js_kv_map_get, "get", 1));

    auto setter = js_kv_map_set;
    auto deleter = js_kv_map_delete;

    if (read_only)
    {
      setter = js_kv_map_set_read_only;
      deleter = js_kv_map_delete_read_only;
    }

    JS_SetPropertyStr(
      ctx, view_val, "set", JS_NewCFunction(ctx, setter, "set", 2));
    JS_SetPropertyStr(
      ctx, view_val, "delete", JS_NewCFunction(ctx, deleter, "delete", 1));

    JS_SetPropertyStr(
      ctx,
      view_val,
      "forEach",
      JS_NewCFunction(ctx, js_kv_map_foreach, "forEach", 1));

    desc->flags = 0;
    desc->value = view_val;

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

    auto body = static_cast<const std::vector<uint8_t>*>(
      JS_GetOpaque(this_val, body_class_id));
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

    auto body = static_cast<const std::vector<uint8_t>*>(
      JS_GetOpaque(this_val, body_class_id));
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

    auto body = static_cast<const std::vector<uint8_t>*>(
      JS_GetOpaque(this_val, body_class_id));
    auto body_ = JS_NewArrayBufferCopy(ctx, body->data(), body->size());
    return body_;
  }

  JSValue js_node_trigger_ledger_rekey(
    JSContext* ctx,
    JSValueConst this_val,
    int argc,
    [[maybe_unused]] JSValueConst* argv)
  {
    if (argc != 0)
    {
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments but expected none", argc);
    }

    auto node = static_cast<ccf::AbstractNodeState*>(
      JS_GetOpaque(this_val, node_class_id));

    auto global_obj = JS_GetGlobalObject(ctx);
    auto ccf = JS_GetPropertyStr(ctx, global_obj, "ccf");
    auto kv = JS_GetPropertyStr(ctx, ccf, "kv");

    auto tx_ctx_ptr = static_cast<TxContext*>(JS_GetOpaque(kv, kv_class_id));

    if (tx_ctx_ptr->tx == nullptr)
    {
      return JS_ThrowInternalError(
        ctx, "No transaction available to rekey ledger");
    }

    JS_FreeValue(ctx, kv);
    JS_FreeValue(ctx, ccf);
    JS_FreeValue(ctx, global_obj);

    bool result = node->rekey_ledger(*tx_ctx_ptr->tx);

    if (!result)
    {
      return JS_ThrowInternalError(ctx, "Could not rekey ledger");
    }

    return JS_UNDEFINED;
  }

  JSValue js_node_transition_service_to_open(
    JSContext* ctx,
    JSValueConst this_val,
    int argc,
    [[maybe_unused]] JSValueConst* argv)
  {
    if (argc != 0)
    {
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments but expected none", argc);
    }

    auto node = static_cast<ccf::AbstractNodeState*>(
      JS_GetOpaque(this_val, node_class_id));

    if (node == nullptr)
    {
      return JS_ThrowInternalError(ctx, "Node state is not set");
    }

    auto global_obj = JS_GetGlobalObject(ctx);
    auto ccf = JS_GetPropertyStr(ctx, global_obj, "ccf");
    auto kv = JS_GetPropertyStr(ctx, ccf, "kv");

    auto tx_ctx_ptr = static_cast<TxContext*>(JS_GetOpaque(kv, kv_class_id));

    if (tx_ctx_ptr->tx == nullptr)
    {
      return JS_ThrowInternalError(
        ctx, "No transaction available to open service");
    }

    JS_FreeValue(ctx, kv);
    JS_FreeValue(ctx, ccf);
    JS_FreeValue(ctx, global_obj);

    try
    {
      node->transition_service_to_open(*tx_ctx_ptr->tx);
    }
    catch (const std::exception& e)
    {
      LOG_FAIL_FMT("Unable to open service: {}", e.what());
    }

    return JS_UNDEFINED;
  }

  JSValue js_network_latest_ledger_secret_seqno(
    JSContext* ctx,
    JSValueConst this_val,
    int argc,
    [[maybe_unused]] JSValueConst* argv)
  {
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

    auto global_obj = JS_GetGlobalObject(ctx);
    auto ccf = JS_GetPropertyStr(ctx, global_obj, "ccf");
    auto kv = JS_GetPropertyStr(ctx, ccf, "kv");

    auto tx_ctx_ptr = static_cast<TxContext*>(JS_GetOpaque(kv, kv_class_id));

    if (tx_ctx_ptr->tx == nullptr)
    {
      return JS_ThrowInternalError(
        ctx, "No transaction available to fetch latest ledger secret seqno");
    }

    JS_FreeValue(ctx, kv);
    JS_FreeValue(ctx, ccf);
    JS_FreeValue(ctx, global_obj);

    return JS_NewInt64(
      ctx, network->ledger_secrets->get_latest(*tx_ctx_ptr->tx).first);
  }

  JSValue js_gov_set_jwt_public_signing_keys(
    JSContext* ctx,
    [[maybe_unused]] JSValueConst this_val,
    int argc,
    JSValueConst* argv)
  {
    if (argc != 3)
    {
      return JS_ThrowTypeError(ctx, "Passed %d arguments but expected 3", argc);
    }

    // yikes
    auto global_obj = JS_GetGlobalObject(ctx);
    auto ccf = JS_GetPropertyStr(ctx, global_obj, "ccf");
    auto kv = JS_GetPropertyStr(ctx, ccf, "kv");

    auto tx_ctx_ptr = static_cast<TxContext*>(JS_GetOpaque(kv, kv_class_id));

    if (tx_ctx_ptr->tx == nullptr)
    {
      return JS_ThrowInternalError(ctx, "No transaction available");
    }

    JS_FreeValue(ctx, kv);
    JS_FreeValue(ctx, ccf);
    JS_FreeValue(ctx, global_obj);

    auto& tx = *tx_ctx_ptr->tx;

    auto issuer_cstr = JS_ToCString(ctx, argv[0]);
    if (issuer_cstr == nullptr)
    {
      return JS_ThrowTypeError(ctx, "issuer argument is not a string");
    }
    std::string issuer(issuer_cstr);
    JS_FreeCString(ctx, issuer_cstr);

    JSValue metadata_val = JS_JSONStringify(ctx, argv[1], JS_NULL, JS_NULL);
    if (JS_IsException(metadata_val))
    {
      return JS_ThrowTypeError(ctx, "metadata argument is not a JSON object");
    }
    auto metadata_cstr = JS_ToCString(ctx, metadata_val);
    std::string metadata_json(metadata_cstr);
    JS_FreeCString(ctx, metadata_cstr);
    JS_FreeValue(ctx, metadata_val);

    JSValue jwks_val = JS_JSONStringify(ctx, argv[2], JS_NULL, JS_NULL);
    if (JS_IsException(jwks_val))
    {
      return JS_ThrowTypeError(ctx, "jwks argument is not a JSON object");
    }
    auto jwks_cstr = JS_ToCString(ctx, jwks_val);
    std::string jwks_json(jwks_cstr);
    JS_FreeCString(ctx, jwks_cstr);
    JS_FreeValue(ctx, jwks_val);

    try
    {
      auto metadata =
        nlohmann::json::parse(metadata_json).get<ccf::JwtIssuerMetadata>();
      auto jwks = nlohmann::json::parse(jwks_json).get<ccf::JsonWebKeySet>();
      auto success =
        ccf::set_jwt_public_signing_keys(tx, "<js>", issuer, metadata, jwks);
      if (!success)
      {
        return JS_ThrowInternalError(
          ctx, "set_jwt_public_signing_keys() failed");
      }
    }
    catch (std::exception& exc)
    {
      return JS_ThrowInternalError(ctx, "Error: %s", exc.what());
    }
    return JS_UNDEFINED;
  }

  JSValue js_gov_remove_jwt_public_signing_keys(
    JSContext* ctx,
    [[maybe_unused]] JSValueConst this_val,
    int argc,
    JSValueConst* argv)
  {
    if (argc != 1)
    {
      return JS_ThrowTypeError(ctx, "Passed %d arguments but expected 1", argc);
    }

    // yikes
    auto global_obj = JS_GetGlobalObject(ctx);
    auto ccf = JS_GetPropertyStr(ctx, global_obj, "ccf");
    auto kv = JS_GetPropertyStr(ctx, ccf, "kv");

    auto tx_ctx_ptr = static_cast<TxContext*>(JS_GetOpaque(kv, kv_class_id));

    if (tx_ctx_ptr->tx == nullptr)
    {
      return JS_ThrowInternalError(ctx, "No transaction available");
    }

    JS_FreeValue(ctx, kv);
    JS_FreeValue(ctx, ccf);
    JS_FreeValue(ctx, global_obj);

    auto& tx = *tx_ctx_ptr->tx;

    auto issuer_cstr = JS_ToCString(ctx, argv[0]);
    if (issuer_cstr == nullptr)
    {
      return JS_ThrowTypeError(ctx, "issuer argument is not a string");
    }
    std::string issuer(issuer_cstr);
    JS_FreeCString(ctx, issuer_cstr);

    try
    {
      ccf::remove_jwt_public_signing_keys(tx, issuer);
    }
    catch (std::exception& exc)
    {
      return JS_ThrowInternalError(ctx, "Error: %s", exc.what());
    }
    return JS_UNDEFINED;
  }

  JSValue js_node_trigger_recovery_shares_refresh(
    JSContext* ctx,
    JSValueConst this_val,
    int argc,
    [[maybe_unused]] JSValueConst* argv)
  {
    if (argc != 0)
    {
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments but expected none", argc);
    }

    auto node = static_cast<ccf::AbstractNodeState*>(
      JS_GetOpaque(this_val, node_class_id));
    auto global_obj = JS_GetGlobalObject(ctx);
    auto ccf = JS_GetPropertyStr(ctx, global_obj, "ccf");
    auto kv = JS_GetPropertyStr(ctx, ccf, "kv");

    auto tx_ctx_ptr = static_cast<TxContext*>(JS_GetOpaque(kv, kv_class_id));

    if (tx_ctx_ptr->tx == nullptr)
    {
      return JS_ThrowInternalError(
        ctx, "No transaction available to open service");
    }

    JS_FreeValue(ctx, kv);
    JS_FreeValue(ctx, ccf);
    JS_FreeValue(ctx, global_obj);

    node->trigger_recovery_shares_refresh(*tx_ctx_ptr->tx);

    return JS_UNDEFINED;
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

    JS_NewClassID(&kv_map_handle_class_id);
    kv_map_handle_class_def.class_name = "KV Map Handle";

    JS_NewClassID(&body_class_id);
    body_class_def.class_name = "Body";

    JS_NewClassID(&node_class_id);
    node_class_def.class_name = "Node";

    JS_NewClassID(&network_class_id);
    network_class_def.class_name = "Network";
  }

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

    JS_Throw(ctx, exception_val);
  }

  std::pair<std::string, std::optional<std::string>> js_error_message(
    JSContext* ctx)
  {
    JSValue exception_val = JS_GetException(ctx);
    const char* str;
    bool is_error = JS_IsError(ctx, exception_val);
    if (!is_error && JS_IsObject(exception_val))
    {
      JSValue rval = JS_JSONStringify(ctx, exception_val, JS_NULL, JS_NULL);
      str = JS_ToCString(ctx, rval);
      JS_FreeValue(ctx, rval);
    }
    else
    {
      str = JS_ToCString(ctx, exception_val);
    }
    std::string message(str);
    JS_FreeCString(ctx, str);

    std::optional<std::string> trace = std::nullopt;
    if (is_error)
    {
      auto val = JS_GetPropertyStr(ctx, exception_val, "stack");
      if (!JS_IsUndefined(val))
      {
        auto stack = JS_ToCString(ctx, val);
        trace = stack;
        JS_FreeCString(ctx, stack);
      }
      JS_FreeValue(ctx, val);
    }
    JS_FreeValue(ctx, exception_val);
    return {message, trace};
  }

  JSValue Context::default_function(
    const std::string& code, const std::string& path)

  {
    return function(code, "default", path);
  }

  JSValue Context::function(
    const std::string& code, const std::string& func, const std::string& path)
  {
    JSValue module = JS_Eval(
      ctx,
      code.c_str(),
      code.size(),
      path.c_str(),
      JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_COMPILE_ONLY);

    if (JS_IsException(module))
    {
      js_dump_error(ctx);
      throw std::runtime_error(fmt::format("Failed to compile {}", path));
    }

    auto eval_val = JS_EvalFunction(ctx, module);
    if (JS_IsException(eval_val))
    {
      js_dump_error(ctx);
      JS_FreeValue(ctx, eval_val);
      throw std::runtime_error(fmt::format("Failed to execute {}", path));
    }
    JS_FreeValue(ctx, eval_val);

    // Get exported function from module
    assert(JS_VALUE_GET_TAG(module) == JS_TAG_MODULE);
    auto module_def = (JSModuleDef*)JS_VALUE_GET_PTR(module);
    auto export_count = JS_GetModuleExportEntriesCount(module_def);
    for (auto i = 0; i < export_count; i++)
    {
      auto export_name_atom = JS_GetModuleExportEntryName(ctx, module_def, i);
      auto export_name_cstr = JS_AtomToCString(ctx, export_name_atom);
      std::string export_name{export_name_cstr};
      JS_FreeCString(ctx, export_name_cstr);
      JS_FreeAtom(ctx, export_name_atom);
      if (export_name == func)
      {
        auto export_func = JS_GetModuleExportEntry(ctx, module_def, i);
        if (!JS_IsFunction(ctx, export_func))
        {
          JS_FreeValue(ctx, export_func);
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

  static JSValue create_console_obj(JSContext* ctx)
  {
    auto console = JS_NewObject(ctx);

    JS_SetPropertyStr(
      ctx, console, "log", JS_NewCFunction(ctx, js_print, "log", 1));

    return console;
  }

  void populate_global_console(JSContext* ctx)
  {
    auto global_obj = JS_GetGlobalObject(ctx);
    JS_SetPropertyStr(ctx, global_obj, "console", create_console_obj(ctx));
    JS_FreeValue(ctx, global_obj);
  }

  JSValue create_ccf_obj(
    TxContext* txctx,
    const std::optional<ccf::TxID>& transaction_id,
    ccf::historical::TxReceiptPtr receipt,
    ccf::AbstractNodeState* node_state,
    ccf::NetworkState* network_state,
    JSContext* ctx)
  {
    auto ccf = JS_NewObject(ctx);

    JS_SetPropertyStr(
      ctx, ccf, "strToBuf", JS_NewCFunction(ctx, js_str_to_buf, "strToBuf", 1));
    JS_SetPropertyStr(
      ctx, ccf, "bufToStr", JS_NewCFunction(ctx, js_buf_to_str, "bufToStr", 1));
    JS_SetPropertyStr(
      ctx,
      ccf,
      "jsonCompatibleToBuf",
      JS_NewCFunction(
        ctx, js_json_compatible_to_buf, "jsonCompatibleToBuf", 1));
    JS_SetPropertyStr(
      ctx,
      ccf,
      "bufToJsonCompatible",
      JS_NewCFunction(
        ctx, js_buf_to_json_compatible, "bufToJsonCompatible", 1));
    JS_SetPropertyStr(
      ctx,
      ccf,
      "generateAesKey",
      JS_NewCFunction(ctx, js_generate_aes_key, "generateAesKey", 1));
    JS_SetPropertyStr(
      ctx,
      ccf,
      "generateRsaKeyPair",
      JS_NewCFunction(ctx, js_generate_rsa_key_pair, "generateRsaKeyPair", 1));
    JS_SetPropertyStr(
      ctx, ccf, "wrapKey", JS_NewCFunction(ctx, js_wrap_key, "wrapKey", 3));
    JS_SetPropertyStr(
      ctx, ccf, "digest", JS_NewCFunction(ctx, js_digest, "digest", 2));
    JS_SetPropertyStr(
      ctx,
      ccf,
      "isValidX509Chain",
      JS_NewCFunction(ctx, js_is_valid_pem, "isValidX509Chain", 1));
    JS_SetPropertyStr(
      ctx, ccf, "pemToId", JS_NewCFunction(ctx, js_pem_to_id, "pemToId", 1));

    if (txctx != nullptr)
    {
      auto kv = JS_NewObjectClass(ctx, kv_class_id);
      JS_SetOpaque(kv, txctx);
      JS_SetPropertyStr(ctx, ccf, "kv", kv);

      JS_SetPropertyStr(
        ctx,
        ccf,
        "setJwtPublicSigningKeys",
        JS_NewCFunction(
          ctx,
          js_gov_set_jwt_public_signing_keys,
          "setJwtPublicSigningKeys",
          3));
      JS_SetPropertyStr(
        ctx,
        ccf,
        "removeJwtPublicSigningKeys",
        JS_NewCFunction(
          ctx,
          js_gov_remove_jwt_public_signing_keys,
          "removeJwtPublicSigningKeys",
          1));
    }

    // Historical queries
    if (receipt != nullptr)
    {
      CCF_ASSERT(
        transaction_id.has_value(),
        "Expected receipt and transaction_id to both be passed");

      auto state = JS_NewObject(ctx);

      JS_SetPropertyStr(
        ctx,
        state,
        "transactionId",
        JS_NewString(ctx, transaction_id->to_str().c_str()));

      ccf::Receipt receipt_out;
      receipt->describe(receipt_out);
      auto js_receipt = JS_NewObject(ctx);
      JS_SetPropertyStr(
        ctx,
        js_receipt,
        "signature",
        JS_NewString(ctx, receipt_out.signature.c_str()));
      JS_SetPropertyStr(
        ctx, js_receipt, "root", JS_NewString(ctx, receipt_out.root.c_str()));
      JS_SetPropertyStr(
        ctx, js_receipt, "leaf", JS_NewString(ctx, receipt_out.leaf.c_str()));
      JS_SetPropertyStr(
        ctx,
        js_receipt,
        "nodeId",
        JS_NewString(ctx, receipt_out.node_id.value().c_str()));
      auto proof = JS_NewArray(ctx);
      uint32_t i = 0;
      for (auto& element : receipt_out.proof)
      {
        auto js_element = JS_NewObject(ctx);
        auto is_left = element.left.has_value();
        JS_SetPropertyStr(
          ctx,
          js_element,
          is_left ? "left" : "right",
          JS_NewString(
            ctx, (is_left ? element.left : element.right).value().c_str()));
        JS_DefinePropertyValueUint32(
          ctx, proof, i++, js_element, JS_PROP_C_W_E);
      }
      JS_SetPropertyStr(ctx, js_receipt, "proof", proof);
      JS_SetPropertyStr(ctx, state, "receipt", js_receipt);
      JS_SetPropertyStr(ctx, ccf, "historicalState", state);
    }

    // Node state
    if (node_state != nullptr)
    {
      if (txctx == nullptr)
      {
        throw std::logic_error("Tx should be set to set node context");
      }

      auto node = JS_NewObjectClass(ctx, node_class_id);
      JS_SetOpaque(node, node_state);
      JS_SetPropertyStr(ctx, ccf, "node", node);
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
          ctx,
          js_node_transition_service_to_open,
          "transitionServiceToOpen",
          0));
      JS_SetPropertyStr(
        ctx,
        node,
        "triggerRecoverySharesRefresh",
        JS_NewCFunction(
          ctx,
          js_node_trigger_recovery_shares_refresh,
          "triggerRecoverySharesRefresh",
          0));
    }

    if (network_state != nullptr)
    {
      if (txctx == nullptr)
      {
        throw std::logic_error("Tx should be set to set network context");
      }

      auto network = JS_NewObjectClass(ctx, network_class_id);
      JS_SetOpaque(network, network_state);
      JS_SetPropertyStr(ctx, ccf, "network", network);
      JS_SetPropertyStr(
        ctx,
        network,
        "getLatestLedgerSecretSeqno",
        JS_NewCFunction(
          ctx,
          js_network_latest_ledger_secret_seqno,
          "getLatestLedgerSecretSeqno",
          0));
    }

    return ccf;
  }

  void populate_global_ccf(
    TxContext* txctx,
    const std::optional<ccf::TxID>& transaction_id,
    ccf::historical::TxReceiptPtr receipt,
    ccf::AbstractNodeState* node_state,
    ccf::NetworkState* network_state,
    JSContext* ctx)
  {
    auto global_obj = JS_GetGlobalObject(ctx);

    JS_SetPropertyStr(
      ctx,
      global_obj,
      "ccf",
      create_ccf_obj(
        txctx, transaction_id, receipt, node_state, network_state, ctx));

    JS_FreeValue(ctx, global_obj);
  }

  void Runtime::add_ccf_classdefs()
  {
    // Register class for KV
    {
      auto ret = JS_NewClass(rt, kv_class_id, &kv_class_def);
      if (ret != 0)
      {
        throw std::logic_error("Failed to register JS class definition for KV");
      }
    }

    // Register class for KV map views
    {
      auto ret =
        JS_NewClass(rt, kv_map_handle_class_id, &kv_map_handle_class_def);
      if (ret != 0)
      {
        throw std::logic_error(
          "Failed to register JS class definition for KVMap");
      }
    }

    // Register class for request body
    {
      auto ret = JS_NewClass(rt, body_class_id, &body_class_def);
      if (ret != 0)
      {
        throw std::logic_error(
          "Failed to register JS class definition for Body");
      }
    }

    // Register class for node
    {
      auto ret = JS_NewClass(rt, node_class_id, &node_class_def);
      if (ret != 0)
      {
        throw std::logic_error(
          "Failed to register JS class definition for node");
      }
    }

    // Register class for network
    {
      auto ret = JS_NewClass(rt, network_class_id, &network_class_def);
      if (ret != 0)
      {
        throw std::logic_error(
          "Failed to register JS class definition for network");
      }
    }
  }

#pragma clang diagnostic pop
}
