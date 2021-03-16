// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "js/wrap.h"

#include "ds/logger.h"
#include "js/crypto.cpp"
#include "kv/untyped_map.h"
#include "node/rpc/call_types.h"
#include "tls/base64.h"
#include "tx_id.h"

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

  JSClassDef kv_class_def = {};
  JSClassExoticMethods kv_exotic_methods = {};
  JSClassDef kv_map_handle_class_def = {};
  JSClassDef body_class_def = {};

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
    const auto property_name = JS_AtomToCString(ctx, property);
    LOG_TRACE_FMT("Looking for kv map '{}'", property_name);

    const auto [security_domain, access_category] =
      kv::parse_map_name(property_name);

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
        read_only = true;
        break;
      }
      case kv::AccessCategory::APPLICATION:
      {
        break;
      }
      default:
      {
        throw std::logic_error(fmt::format(
          "Unhandled AccessCategory for table '{}'", property_name));
      }
    }

    auto tx_ptr = static_cast<kv::Tx*>(JS_GetOpaque(this_val, kv_class_id));
    auto handle = tx_ptr->rw<KVMap>(property_name);

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

  static void js_free_arraybuffer_cstring(JSRuntime*, void* opaque, void* ptr)
  {
    JS_FreeCString((JSContext*)opaque, (char*)ptr);
  }

  void populate_global_console(JSContext* ctx)
  {
    auto global_obj = JS_GetGlobalObject(ctx);
    JS_SetPropertyStr(ctx, global_obj, "console", create_console_obj(ctx));
    JS_FreeValue(ctx, global_obj);
  }

  static JSValue js_str_to_buf(
    JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
  {
    if (argc != 1)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 1", argc);

    if (!JS_IsString(argv[0]))
      return JS_ThrowTypeError(ctx, "Argument must be a string");

    size_t str_size = 0;
    const char* str = JS_ToCStringLen(ctx, &str_size, argv[0]);

    if (!str)
    {
      js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    JSValue buf = JS_NewArrayBuffer(
      ctx, (uint8_t*)str, str_size, js_free_arraybuffer_cstring, ctx, false);

    if (JS_IsException(buf))
      js_dump_error(ctx);

    return buf;
  }

  static JSValue js_buf_to_str(
    JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
  {
    if (argc != 1)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 1", argc);

    size_t buf_size;
    uint8_t* buf = JS_GetArrayBuffer(ctx, &buf_size, argv[0]);

    if (!buf)
      return JS_ThrowTypeError(ctx, "Argument must be an ArrayBuffer");

    JSValue str = JS_NewStringLen(ctx, (char*)buf, buf_size);

    if (JS_IsException(str))
      js::js_dump_error(ctx);

    return str;
  }

  static JSValue js_json_compatible_to_buf(
    JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
  {
    if (argc != 1)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 1", argc);

    JSValue str = JS_JSONStringify(ctx, argv[0], JS_NULL, JS_NULL);

    if (JS_IsException(str))
    {
      js::js_dump_error(ctx);
      return str;
    }

    JSValue buf = js_str_to_buf(ctx, JS_NULL, 1, &str);
    JS_FreeValue(ctx, str);
    return buf;
  }

  static JSValue js_buf_to_json_compatible(
    JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
  {
    if (argc != 1)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 1", argc);

    size_t buf_size;
    uint8_t* buf = JS_GetArrayBuffer(ctx, &buf_size, argv[0]);

    if (!buf)
      return JS_ThrowTypeError(ctx, "Argument must be an ArrayBuffer");

    std::vector<uint8_t> buf_null_terminated(buf_size + 1);
    buf_null_terminated[buf_size] = 0;
    buf_null_terminated.assign(buf, buf + buf_size);

    JSValue obj =
      JS_ParseJSON(ctx, (char*)buf_null_terminated.data(), buf_size, "<json>");

    if (JS_IsException(obj))
      js::js_dump_error(ctx);

    return obj;
  }

  JSValue create_ccf_obj(
    kv::Tx& tx,
    const std::optional<kv::TxID>& transaction_id,
    ccf::historical::TxReceiptPtr receipt,
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

    auto kv = JS_NewObjectClass(ctx, kv_class_id);
    JS_SetOpaque(kv, &tx);
    JS_SetPropertyStr(ctx, ccf, "kv", kv);

    // Historical queries
    if (receipt)
    {
      auto state = JS_NewObject(ctx);

      ccf::TxID tx_id;
      tx_id.seqno = static_cast<ccf::SeqNo>(transaction_id.value().version);
      tx_id.view = static_cast<ccf::View>(transaction_id.value().term);
      JS_SetPropertyStr(
        ctx, state, "transactionId", JS_NewString(ctx, tx_id.to_str().c_str()));

      ccf::GetReceipt::Out receipt_out;
      receipt_out.from_receipt(receipt);
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

    return ccf;
  }

  void populate_global_ccf(
    kv::Tx& tx,
    const std::optional<kv::TxID>& transaction_id,
    ccf::historical::TxReceiptPtr receipt,
    JSContext* ctx)
  {
    auto global_obj = JS_GetGlobalObject(ctx);

    JS_SetPropertyStr(
      ctx, global_obj, "ccf", create_ccf_obj(tx, transaction_id, receipt, ctx));

    JS_FreeValue(ctx, global_obj);
  }

#pragma clang diagnostic pop

}