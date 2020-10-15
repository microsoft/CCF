// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "enclave/app_interface.h"
#include "kv/untyped_map.h"
#include "node/rpc/user_frontend.h"
#include "tls/entropy.h"

#include <memory>
#include <quickjs/quickjs-exports.h>
#include <quickjs/quickjs.h>
#include <vector>

namespace ccfapp
{
  using namespace std;
  using namespace kv;
  using namespace ccf;

  using KVMap = kv::Map<std::vector<uint8_t>, std::vector<uint8_t>>;

  JSClassID kv_class_id;
  JSClassID kv_map_view_class_id;
  JSClassID body_class_id;

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

  struct JSAutoFree
  {
    JSAutoFree(JSContext* ctx) : ctx(ctx) {}

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

    JSContext* ctx;
  };

  static JSValue js_generate_aes_key(
    JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
  {
    if (argc != 1)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 1", argc);

    int32_t key_size;
    if (JS_ToInt32(ctx, &key_size, argv[0]) < 0)
    {
      js_dump_error(ctx);
      return JS_EXCEPTION;
    }
    // Supported key sizes for AES.
    if (key_size != 128 && key_size != 192 && key_size != 256)
    {
      JS_ThrowRangeError(ctx, "invalid key size");
      js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    std::vector<uint8_t> key = tls::create_entropy()->random(key_size / 8);

    return JS_NewArrayBufferCopy(ctx, key.data(), key.size());
  }

  static JSValue js_wrap_key(
    JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
  {
    if (argc != 3)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 3", argc);

    // API loosely modeled after
    // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/wrapKey.

    JSAutoFree auto_free(ctx);

    size_t key_size;
    uint8_t* key = JS_GetArrayBuffer(ctx, &key_size, argv[0]);
    if (!key)
    {
      js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    size_t wrapping_key_size;
    uint8_t* wrapping_key = JS_GetArrayBuffer(ctx, &wrapping_key_size, argv[1]);
    if (!wrapping_key)
    {
      js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    JSValue wrap_algo = argv[2];
    auto wrap_algo_name_val =
      auto_free(JS_GetPropertyStr(ctx, wrap_algo, "name"));
    auto wrap_algo_name_cstr = auto_free(JS_ToCString(ctx, wrap_algo_name_val));

    if (!wrap_algo_name_cstr)
    {
      js_dump_error(ctx);
      return JS_EXCEPTION;
    }
    std::string wrap_algo_name(wrap_algo_name_cstr);

    std::vector<uint8_t> wrapped_key;

    auto entropy = tls::create_entropy();

    if (wrap_algo_name == "RSA-OAEP")
    {
      // key can in principle be arbitrary data (see note on maximum size
      // below). wrapping_key is a private RSA key.

      auto label_val = auto_free(JS_GetPropertyStr(ctx, wrap_algo, "label"));
      size_t label_buf_size;
      uint8_t* label_buf = JS_GetArrayBuffer(ctx, &label_buf_size, label_val);

      int err;

      mbedtls_pk_context pk_ctx;
      mbedtls_pk_init(&pk_ctx);
      err =
        mbedtls_pk_parse_public_key(&pk_ctx, wrapping_key, wrapping_key_size);
      if (err)
      {
        mbedtls_pk_free(&pk_ctx);
        JS_ThrowRangeError(
          ctx,
          "parsing of wrapping key failed: %s",
          tls::error_string(err).c_str());
        js_dump_error(ctx);
        return JS_EXCEPTION;
      }
      if (pk_ctx.pk_info != mbedtls_pk_info_from_type(MBEDTLS_PK_RSA))
      {
        mbedtls_pk_free(&pk_ctx);
        JS_ThrowTypeError(ctx, "wrapping key must be an RSA key");
        js_dump_error(ctx);
        return JS_EXCEPTION;
      }

      mbedtls_rsa_context* rsa_ctx = mbedtls_pk_rsa(pk_ctx);
      mbedtls_rsa_set_padding(rsa_ctx, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);

      wrapped_key.resize(rsa_ctx->len);

      // Note that the maximum input size to wrap is k - 2*hLen - 2
      // where hLen is the hash size (32 bytes = SHA256) and
      // k the wrapping key modulus size (e.g. 256 bytes = 2048 bits).
      // In this example, it would be 190 bytes (1520 bits) max.
      // This is enough for wrapping AES keys for example.
      err = mbedtls_rsa_rsaes_oaep_encrypt(
        rsa_ctx,
        entropy->get_rng(),
        entropy->get_data(),
        MBEDTLS_RSA_PUBLIC,
        label_buf,
        label_buf_size,
        key_size,
        key,
        wrapped_key.data());
      mbedtls_pk_free(&pk_ctx);
      if (err)
      {
        JS_ThrowRangeError(
          ctx, "key wrapping failed: %s", tls::error_string(err).c_str());
        js_dump_error(ctx);
        return JS_EXCEPTION;
      }
    }
    else
    {
      JS_ThrowRangeError(
        ctx, "unsupported key wrapping algorithm, supported: RSA-OAEP");
      js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    return JS_NewArrayBufferCopy(ctx, wrapped_key.data(), wrapped_key.size());
  }

  static void js_free_arraybuffer_cstring(JSRuntime*, void* opaque, void* ptr)
  {
    JS_FreeCString((JSContext*)opaque, (char*)ptr);
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
      js_dump_error(ctx);

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
      js_dump_error(ctx);
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
      js_dump_error(ctx);

    return obj;
  }

  static JSValue js_kv_map_has(
    JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
  {
    auto map_view =
      static_cast<KVMap::TxView*>(JS_GetOpaque(this_val, kv_map_view_class_id));

    if (argc != 1)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 1", argc);

    size_t key_size;
    uint8_t* key = JS_GetArrayBuffer(ctx, &key_size, argv[0]);

    if (!key)
      return JS_ThrowTypeError(ctx, "Argument must be an ArrayBuffer");

    auto val = map_view->get({key, key + key_size});

    return JS_NewBool(ctx, val.has_value());
  }

  static JSValue js_kv_map_get(
    JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
  {
    auto map_view =
      static_cast<KVMap::TxView*>(JS_GetOpaque(this_val, kv_map_view_class_id));

    if (argc != 1)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 1", argc);

    size_t key_size;
    uint8_t* key = JS_GetArrayBuffer(ctx, &key_size, argv[0]);

    if (!key)
      return JS_ThrowTypeError(ctx, "Argument must be an ArrayBuffer");

    auto val = map_view->get({key, key + key_size});

    if (!val.has_value())
      return JS_ThrowRangeError(ctx, "No such key");

    JSValue buf =
      JS_NewArrayBufferCopy(ctx, val.value().data(), val.value().size());

    if (JS_IsException(buf))
      js_dump_error(ctx);

    return buf;
  }

  static JSValue js_kv_map_delete(
    JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
  {
    auto map_view =
      static_cast<KVMap::TxView*>(JS_GetOpaque(this_val, kv_map_view_class_id));

    if (argc != 1)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 1", argc);

    size_t key_size;
    uint8_t* key = JS_GetArrayBuffer(ctx, &key_size, argv[0]);

    if (!key)
      return JS_ThrowTypeError(ctx, "Argument must be an ArrayBuffer");

    auto val = map_view->remove({key, key + key_size});

    if (!val)
      return JS_ThrowRangeError(ctx, "Failed to remove at key");

    return JS_UNDEFINED;
  }

  static JSValue js_kv_map_delete_read_only(
    JSContext* ctx, JSValueConst, int, JSValueConst*)
  {
    return JS_ThrowTypeError(ctx, "Cannot call delete on read-only map");
  }

  static JSValue js_kv_map_set(
    JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
  {
    auto map_view =
      static_cast<KVMap::TxView*>(JS_GetOpaque(this_val, kv_map_view_class_id));

    if (argc != 2)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 2", argc);

    size_t key_size;
    uint8_t* key = JS_GetArrayBuffer(ctx, &key_size, argv[0]);

    size_t val_size;
    uint8_t* val = JS_GetArrayBuffer(ctx, &val_size, argv[1]);

    if (!key || !val)
      return JS_ThrowTypeError(ctx, "Arguments must be ArrayBuffers");

    if (!map_view->put({key, key + key_size}, {val, val + val_size}))
      return JS_ThrowRangeError(ctx, "Could not insert at key");

    return JS_UNDEFINED;
  }

  static JSValue js_kv_map_set_read_only(
    JSContext* ctx, JSValueConst, int, JSValueConst*)
  {
    return JS_ThrowTypeError(ctx, "Cannot call set on read-only map");
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
    auto view = tx_ptr->get_view<KVMap>(property_name);

    // This follows the interface of Map:
    // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Map
    // Keys and values are ArrayBuffers. Keys are matched based on their
    // contents.
    auto view_val = JS_NewObjectClass(ctx, kv_map_view_class_id);
    JS_SetOpaque(view_val, view);

    JS_SetPropertyStr(
      ctx,
      view_val,
      "has",
      JS_NewCFunction(ctx, ccfapp::js_kv_map_has, "has", 1));

    JS_SetPropertyStr(
      ctx,
      view_val,
      "get",
      JS_NewCFunction(ctx, ccfapp::js_kv_map_get, "get", 1));

    auto setter = ccfapp::js_kv_map_set;
    auto deleter = ccfapp::js_kv_map_delete;

    if (read_only)
    {
      setter = ccfapp::js_kv_map_set_read_only;
      deleter = ccfapp::js_kv_map_delete_read_only;
    }

    JS_SetPropertyStr(
      ctx, view_val, "set", JS_NewCFunction(ctx, setter, "set", 2));
    JS_SetPropertyStr(
      ctx, view_val, "delete", JS_NewCFunction(ctx, deleter, "delete", 1));

    desc->flags = 0;
    desc->value = view_val;

    return true;
  }

  static JSValue js_body_text(
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

  static JSValue js_body_json(
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

  static JSValue js_body_array_buffer(
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

  struct JSModuleLoaderArg
  {
    ccf::NetworkTables* network;
    kv::Tx* tx;
  };

  static JSModuleDef* js_module_loader(
    JSContext* ctx, const char* module_name, void* opaque)
  {
    // QuickJS resolves relative paths but in some cases omits leading slashes.
    std::string module_name_kv(module_name);
    if (module_name_kv[0] != '/')
    {
      module_name_kv.insert(0, "/");
    }

    LOG_TRACE_FMT("Loading module '{}'", module_name_kv);

    auto arg = (JSModuleLoaderArg*)opaque;

    const auto modules = arg->tx->get_view(arg->network->modules);
    auto module = modules->get(module_name_kv);
    if (!module.has_value())
    {
      JS_ThrowReferenceError(ctx, "module '%s' not found in kv", module_name);
      return nullptr;
    }
    std::string js = module->js;

    const char* buf = js.c_str();
    size_t buf_len = js.size();
    JSValue func_val = JS_Eval(
      ctx,
      buf,
      buf_len,
      module_name,
      JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_COMPILE_ONLY);
    if (JS_IsException(func_val))
    {
      js_dump_error(ctx);
      return nullptr;
    }

    auto m = (JSModuleDef*)JS_VALUE_GET_PTR(func_val);
    // module already referenced, decrement ref count
    JS_FreeValue(ctx, func_val);
    return m;
  }

  class JSHandlers : public UserEndpointRegistry
  {
  private:
    NetworkTables& network;

    JSClassDef kv_class_def = {};
    JSClassExoticMethods kv_exotic_methods = {};

    JSClassDef kv_map_view_class_def = {};

    JSClassDef body_class_def = {};

    void execute_request(EndpointContext& args)
    {
      const auto method = args.rpc_ctx->get_method();
      const auto local_method = method.substr(method.find_first_not_of('/'));

      const auto scripts = args.tx.get_view(this->network.app_scripts);

      // Try to find script for method
      // - First try a script called "foo"
      // - If that fails, try a script called "POST foo"
      auto handler_script = scripts->get(local_method);
      if (!handler_script)
      {
        const auto verb_prefixed = fmt::format(
          "{} {}", args.rpc_ctx->get_request_verb().c_str(), local_method);
        handler_script = scripts->get(verb_prefixed);
        if (!handler_script)
        {
          args.rpc_ctx->set_response_status(HTTP_STATUS_NOT_FOUND);
          args.rpc_ctx->set_response_body(fmt::format(
            "No handler script found for method '{}'", verb_prefixed));
          return;
        }
      }

      JSRuntime* rt = JS_NewRuntime();
      if (rt == nullptr)
      {
        throw std::runtime_error("Failed to initialise QuickJS runtime");
      }

      JS_SetMaxStackSize(rt, 1024 * 1024);

      JSModuleLoaderArg js_module_loader_arg{&this->network, &args.tx};
      JS_SetModuleLoaderFunc(
        rt, nullptr, js_module_loader, &js_module_loader_arg);

      JSContext* ctx = JS_NewContext(rt);
      if (ctx == nullptr)
      {
        JS_FreeRuntime(rt);
        throw std::runtime_error("Failed to initialise QuickJS context");
      }

      // Register class for KV
      {
        auto ret = JS_NewClass(rt, kv_class_id, &kv_class_def);
        if (ret != 0)
        {
          throw std::logic_error(
            "Failed to register JS class definition for KV");
        }
      }

      // Register class for KV map views
      {
        auto ret =
          JS_NewClass(rt, kv_map_view_class_id, &kv_map_view_class_def);
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
        JSValue body_proto = JS_NewObject(ctx);
        size_t func_count =
          sizeof(js_body_proto_funcs) / sizeof(js_body_proto_funcs[0]);
        JS_SetPropertyFunctionList(
          ctx, body_proto, js_body_proto_funcs, func_count);
        JS_SetClassProto(ctx, body_class_id, body_proto);
      }

      auto global_obj = JS_GetGlobalObject(ctx);

      auto console = JS_NewObject(ctx);
      JS_SetPropertyStr(ctx, global_obj, "console", console);

      JS_SetPropertyStr(
        ctx, console, "log", JS_NewCFunction(ctx, ccfapp::js_print, "log", 1));

      auto ccf = JS_NewObject(ctx);
      JS_SetPropertyStr(ctx, global_obj, "ccf", ccf);

      JS_SetPropertyStr(
        ctx,
        ccf,
        "strToBuf",
        JS_NewCFunction(ctx, ccfapp::js_str_to_buf, "strToBuf", 1));
      JS_SetPropertyStr(
        ctx,
        ccf,
        "bufToStr",
        JS_NewCFunction(ctx, ccfapp::js_buf_to_str, "bufToStr", 1));
      JS_SetPropertyStr(
        ctx,
        ccf,
        "jsonCompatibleToBuf",
        JS_NewCFunction(
          ctx, ccfapp::js_json_compatible_to_buf, "jsonCompatibleToBuf", 1));
      JS_SetPropertyStr(
        ctx,
        ccf,
        "bufToJsonCompatible",
        JS_NewCFunction(
          ctx, ccfapp::js_buf_to_json_compatible, "bufToJsonCompatible", 1));
      JS_SetPropertyStr(
        ctx,
        ccf,
        "generateAesKey",
        JS_NewCFunction(ctx, ccfapp::js_generate_aes_key, "generateAesKey", 1));
      JS_SetPropertyStr(
        ctx,
        ccf,
        "wrapKey",
        JS_NewCFunction(ctx, ccfapp::js_wrap_key, "wrapKey", 3));

      auto kv = JS_NewObjectClass(ctx, kv_class_id);
      JS_SetPropertyStr(ctx, ccf, "kv", kv);
      JS_SetOpaque(kv, &args.tx);

      auto request = JS_NewObject(ctx);

      auto headers = JS_NewObject(ctx);
      for (auto& [header_name, header_value] :
           args.rpc_ctx->get_request_headers())
      {
        JS_SetPropertyStr(
          ctx,
          headers,
          header_name.c_str(),
          JS_NewStringLen(ctx, header_value.c_str(), header_value.size()));
      }
      JS_SetPropertyStr(ctx, request, "headers", headers);

      const auto& request_query = args.rpc_ctx->get_request_query();
      auto query_str =
        JS_NewStringLen(ctx, request_query.c_str(), request_query.size());
      JS_SetPropertyStr(ctx, request, "query", query_str);

      auto params = JS_NewObject(ctx);
      for (auto& [param_name, param_value] :
           args.rpc_ctx->get_request_path_params())
      {
        JS_SetPropertyStr(
          ctx,
          params,
          param_name.c_str(),
          JS_NewStringLen(ctx, param_value.c_str(), param_value.size()));
      }
      JS_SetPropertyStr(ctx, request, "params", params);

      const auto& request_body = args.rpc_ctx->get_request_body();
      auto body_ = JS_NewObjectClass(ctx, body_class_id);
      JS_SetOpaque(body_, (void*)&request_body);
      JS_SetPropertyStr(ctx, request, "body", body_);

      JS_FreeValue(ctx, global_obj);

      if (!handler_script.value().text.has_value())
      {
        throw std::runtime_error("Could not find script text");
      }

      // Compile module
      std::string code = handler_script.value().text.value();
      const std::string path = "/__endpoint__.js";
      JSValue module = JS_Eval(
        ctx,
        code.c_str(),
        code.size(),
        path.c_str(),
        JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_COMPILE_ONLY);

      if (JS_IsException(module))
      {
        js_dump_error(ctx);
        args.rpc_ctx->set_response_status(HTTP_STATUS_INTERNAL_SERVER_ERROR);
        args.rpc_ctx->set_response_body("Exception thrown while compiling");
        return;
      }

      // Evaluate module
      auto eval_val = JS_EvalFunction(ctx, module);
      if (JS_IsException(eval_val))
      {
        js_dump_error(ctx);
        args.rpc_ctx->set_response_status(HTTP_STATUS_INTERNAL_SERVER_ERROR);
        args.rpc_ctx->set_response_body("Exception thrown while executing");
        return;
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
        throw std::runtime_error(
          "Endpoint module exports something that is not a function");
      }

      // Call exported function
      int argc = 1;
      JSValueConst* argv = (JSValueConst*)&request;
      auto val = JS_Call(ctx, export_func, JS_UNDEFINED, argc, argv);
      JS_FreeValue(ctx, request);
      JS_FreeValue(ctx, export_func);

      if (JS_IsException(val))
      {
        js_dump_error(ctx);
        args.rpc_ctx->set_response_status(HTTP_STATUS_INTERNAL_SERVER_ERROR);
        args.rpc_ctx->set_response_body("Exception thrown while executing");
        return;
      }

      // Handle return value: {body, headers, statusCode}
      if (!JS_IsObject(val))
      {
        args.rpc_ctx->set_response_status(HTTP_STATUS_INTERNAL_SERVER_ERROR);
        args.rpc_ctx->set_response_body(
          "Invalid endpoint function return value");
        return;
      }

      // Response body (also sets a default response content-type header)
      auto response_body_js = JS_GetPropertyStr(ctx, val, "body");
      std::vector<uint8_t> response_body;
      size_t buf_size;
      size_t buf_offset;
      JSValue typed_array_buffer = JS_GetTypedArrayBuffer(
        ctx, response_body_js, &buf_offset, &buf_size, nullptr);
      uint8_t* array_buffer;
      if (!JS_IsException(typed_array_buffer))
      {
        size_t buf_size_total;
        array_buffer =
          JS_GetArrayBuffer(ctx, &buf_size_total, typed_array_buffer);
        array_buffer += buf_offset;
        JS_FreeValue(ctx, typed_array_buffer);
      }
      else
      {
        array_buffer = JS_GetArrayBuffer(ctx, &buf_size, response_body_js);
      }
      if (array_buffer)
      {
        args.rpc_ctx->set_response_header(
          http::headers::CONTENT_TYPE,
          http::headervalues::contenttype::OCTET_STREAM);
        response_body =
          std::vector<uint8_t>(array_buffer, array_buffer + buf_size);
      }
      else
      {
        const char* cstr = nullptr;
        if (JS_IsString(response_body_js))
        {
          args.rpc_ctx->set_response_header(
            http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
          cstr = JS_ToCString(ctx, response_body_js);
        }
        else
        {
          args.rpc_ctx->set_response_header(
            http::headers::CONTENT_TYPE, http::headervalues::contenttype::JSON);
          JSValue rval =
            JS_JSONStringify(ctx, response_body_js, JS_NULL, JS_NULL);
          cstr = JS_ToCString(ctx, rval);
          JS_FreeValue(ctx, rval);
        }
        std::string str(cstr);
        JS_FreeCString(ctx, cstr);

        response_body = std::vector<uint8_t>(str.begin(), str.end());
      }
      JS_FreeValue(ctx, response_body_js);
      args.rpc_ctx->set_response_body(std::move(response_body));

      // Response headers
      auto response_headers_js = JS_GetPropertyStr(ctx, val, "headers");
      if (JS_IsObject(response_headers_js))
      {
        uint32_t prop_count = 0;
        JSPropertyEnum* props = nullptr;
        JS_GetOwnPropertyNames(
          ctx,
          &props,
          &prop_count,
          response_headers_js,
          JS_GPN_STRING_MASK | JS_GPN_ENUM_ONLY);
        for (size_t i = 0; i < prop_count; i++)
        {
          auto prop_name = props[i].atom;
          auto prop_name_cstr = JS_AtomToCString(ctx, prop_name);
          auto prop_val = JS_GetProperty(ctx, response_headers_js, prop_name);
          auto prop_val_cstr = JS_ToCString(ctx, prop_val);
          if (!prop_val_cstr)
          {
            args.rpc_ctx->set_response_status(
              HTTP_STATUS_INTERNAL_SERVER_ERROR);
            args.rpc_ctx->set_response_body("Invalid header value type");
            return;
          }
          args.rpc_ctx->set_response_header(prop_name_cstr, prop_val_cstr);
          JS_FreeCString(ctx, prop_name_cstr);
          JS_FreeCString(ctx, prop_val_cstr);
          JS_FreeValue(ctx, prop_val);
        }
        js_free(ctx, props);
      }
      JS_FreeValue(ctx, response_headers_js);

      // Response status code
      int response_status_code = HTTP_STATUS_OK;
      auto status_code_js = JS_GetPropertyStr(ctx, val, "statusCode");
      if (JS_VALUE_GET_TAG(status_code_js) == JS_TAG_INT)
      {
        response_status_code = JS_VALUE_GET_INT(status_code_js);
      }
      JS_FreeValue(ctx, status_code_js);
      args.rpc_ctx->set_response_status(response_status_code);

      JS_FreeValue(ctx, val);

      JS_FreeContext(ctx);
      JS_FreeRuntime(rt);

      return;
    }

    struct JSDynamicEndpoint : public EndpointDefinition
    {};

  public:
    JSHandlers(NetworkTables& network) :
      UserEndpointRegistry(network),
      network(network)
    {
      JS_NewClassID(&kv_class_id);
      kv_exotic_methods.get_own_property = js_kv_lookup;
      kv_class_def.class_name = "KV Tables";
      kv_class_def.exotic = &kv_exotic_methods;

      JS_NewClassID(&kv_map_view_class_id);
      kv_map_view_class_def.class_name = "KV View";

      JS_NewClassID(&body_class_id);
      body_class_def.class_name = "Body";

      auto default_handler = [this](EndpointContext& args) {
        execute_request(args);
      };

      set_default(default_handler);
    }

    EndpointDefinitionPtr find_endpoint(
      kv::Tx& tx, enclave::RpcContext& rpc_ctx) override
    {
      auto method = fmt::format("/{}", rpc_ctx.get_method());
      auto verb = rpc_ctx.get_request_verb();

      auto endpoints_view =
        tx.get_view<ccf::endpoints::EndpointsMap>(ccf::Tables::ENDPOINTS);

      const auto key = ccf::endpoints::EndpointKey{method, verb};

      const auto it = endpoints_view->get(key);
      if (it.has_value())
      {
        auto endpoint_def = std::make_shared<JSDynamicEndpoint>();
        endpoint_def->dispatch = key;
        endpoint_def->properties = it.value();

        return endpoint_def;
      }

      return EndpointRegistry::find_endpoint(tx, rpc_ctx);
    }

    void execute_endpoint(
      EndpointDefinitionPtr e, EndpointContext& args) override
    {
      auto endpoint = dynamic_cast<JSDynamicEndpoint*>(e.get());
      if (endpoint != nullptr)
      {
        execute_request(args);
        return;
      }

      EndpointRegistry::execute_endpoint(e, args);
    }

    static std::pair<http_method, std::string> split_script_key(
      const std::string& key)
    {
      size_t s = key.find(' ');
      if (s != std::string::npos)
      {
        return std::make_pair(
          http::http_method_from_str(key.substr(0, s).c_str()),
          key.substr(s + 1, key.size() - (s + 1)));
      }
      else
      {
        return std::make_pair(HTTP_POST, key);
      }
    }

    // Since we do our own dispatch within the default handler, report the
    // supported methods here
    void build_api(nlohmann::json& document, kv::Tx& tx) override
    {
      UserEndpointRegistry::build_api(document, tx);

      auto scripts = tx.get_view(this->network.app_scripts);
      scripts->foreach([&document](const auto& key, const auto&) {
        const auto [verb, method] = split_script_key(key);

        ds::openapi::path_operation(ds::openapi::path(document, method), verb);
        return true;
      });
    }
  };

#pragma clang diagnostic pop

  class JS : public ccf::UserRpcFrontend
  {
  private:
    JSHandlers js_handlers;

  public:
    JS(NetworkTables& network) :
      ccf::UserRpcFrontend(*network.tables, js_handlers),
      js_handlers(network)
    {}
  };

  std::shared_ptr<ccf::UserRpcFrontend> get_rpc_handler(
    NetworkTables& network, ccfapp::AbstractNodeContext&)
  {
    return make_shared<JS>(network);
  }
} // namespace ccfapp
