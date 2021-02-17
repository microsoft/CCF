// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "enclave/app_interface.h"
#include "kv/untyped_map.h"
#include "named_auth_policies.h"
#include "node/rpc/metrics_tracker.h"
#include "node/rpc/user_frontend.h"
#include "tls/entropy.h"
#include "tls/rsa_key_pair.h"

#include <memory>
#include <quickjs/quickjs-exports.h>
#include <quickjs/quickjs.h>
#include <vector>

namespace ccfapp
{
  using namespace std;
  using namespace kv;
  using namespace ccf;

  using KVMap = kv::untyped::Map;

  JSClassID kv_class_id;
  JSClassID kv_map_handle_class_id;
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

  struct JSAutoFreeRuntime
  {
    JSRuntime* rt;

    JSAutoFreeRuntime(JSRuntime* rt) : rt(rt) {}
    ~JSAutoFreeRuntime()
    {
      JS_FreeRuntime(rt);
    }
  };

  struct JSAutoFreeCtx
  {
    JSContext* ctx;

    JSAutoFreeCtx(JSContext* ctx) : ctx(ctx) {}
    ~JSAutoFreeCtx()
    {
      JS_FreeContext(ctx);
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

    void* auto_free_ptr = JS_GetContextOpaque(ctx);
    JSAutoFreeCtx& auto_free = *(JSAutoFreeCtx*)auto_free_ptr;

    JSValue wrap_algo = argv[2];
    auto wrap_algo_name_val =
      auto_free(JS_GetPropertyStr(ctx, wrap_algo, "name"));
    auto wrap_algo_name_cstr = auto_free(JS_ToCString(ctx, wrap_algo_name_val));

    if (!wrap_algo_name_cstr)
    {
      js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    if (std::string(wrap_algo_name_cstr) != "RSA-OAEP")
    {
      JS_ThrowRangeError(
        ctx, "unsupported key wrapping algorithm, supported: RSA-OAEP");
      js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    // key can in principle be arbitrary data (see note on maximum size
    // in rsa_key_pair.h). wrapping_key is a public RSA key.

    auto label_val = auto_free(JS_GetPropertyStr(ctx, wrap_algo, "label"));
    size_t label_buf_size;
    uint8_t* label_buf = JS_GetArrayBuffer(ctx, &label_buf_size, label_val);

    auto wrapped_key = tls::make_rsa_public_key(wrapping_key, wrapping_key_size)
                         ->wrap(key, key_size, label_buf, label_buf_size);

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

    JS_SetPropertyStr(
      ctx,
      view_val,
      "forEach",
      JS_NewCFunction(ctx, ccfapp::js_kv_map_foreach, "forEach", 1));

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

    const auto modules = arg->tx->ro(arg->network->modules);
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

    JSClassDef kv_map_handle_class_def = {};

    JSClassDef body_class_def = {};

    metrics::Tracker metrics_tracker;

    static JSValue create_ccf_obj(EndpointContext& args, JSContext* ctx)
    {
      auto ccf = JS_NewObject(ctx);

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
      JS_SetOpaque(kv, &args.tx);
      JS_SetPropertyStr(ctx, ccf, "kv", kv);

      return ccf;
    }

    static JSValue create_console_obj(JSContext* ctx)
    {
      auto console = JS_NewObject(ctx);

      JS_SetPropertyStr(
        ctx, console, "log", JS_NewCFunction(ctx, ccfapp::js_print, "log", 1));

      return console;
    }

    static void populate_global_obj(EndpointContext& args, JSContext* ctx)
    {
      auto global_obj = JS_GetGlobalObject(ctx);

      JS_SetPropertyStr(ctx, global_obj, "console", create_console_obj(ctx));
      JS_SetPropertyStr(ctx, global_obj, "ccf", create_ccf_obj(args, ctx));

      JS_FreeValue(ctx, global_obj);
    }

    static JSValue create_json_obj(const nlohmann::json& j, JSContext* ctx)
    {
      const auto buf = j.dump();
      return JS_ParseJSON(ctx, buf.data(), buf.size(), "<json>");
    }

    static JSValue create_caller_obj(EndpointContext& args, JSContext* ctx)
    {
      if (args.caller == nullptr)
      {
        return JS_NULL;
      }

      auto caller = JS_NewObject(ctx);

      if (auto jwt_ident = args.try_get_caller<ccf::JwtAuthnIdentity>())
      {
        JS_SetPropertyStr(
          ctx,
          caller,
          "policy",
          JS_NewString(ctx, get_policy_name_from_ident(jwt_ident)));

        auto jwt = JS_NewObject(ctx);
        JS_SetPropertyStr(
          ctx,
          jwt,
          "key_issuer",
          JS_NewStringLen(
            ctx, jwt_ident->key_issuer.data(), jwt_ident->key_issuer.size()));
        JS_SetPropertyStr(
          ctx, jwt, "header", create_json_obj(jwt_ident->header, ctx));
        JS_SetPropertyStr(
          ctx, jwt, "payload", create_json_obj(jwt_ident->payload, ctx));
        JS_SetPropertyStr(ctx, caller, "jwt", jwt);

        return caller;
      }
      else if (
        auto empty_ident = args.try_get_caller<ccf::EmptyAuthnIdentity>())
      {
        JS_SetPropertyStr(
          ctx,
          caller,
          "policy",
          JS_NewString(ctx, get_policy_name_from_ident(empty_ident)));
        return caller;
      }

      char const* policy_name = nullptr;
      size_t id = ccf::INVALID_ID;
      nlohmann::json data;
      std::string cert_s;

      if (
        auto user_cert_ident =
          args.try_get_caller<ccf::UserCertAuthnIdentity>())
      {
        policy_name = get_policy_name_from_ident(user_cert_ident);
        id = user_cert_ident->user_id;
        data = user_cert_ident->user_data;
        cert_s = user_cert_ident->user_cert.str();
      }
      else if (
        auto member_cert_ident =
          args.try_get_caller<ccf::MemberCertAuthnIdentity>())
      {
        policy_name = get_policy_name_from_ident(member_cert_ident);
        id = member_cert_ident->member_id;
        data = member_cert_ident->member_data;
        cert_s = member_cert_ident->member_cert.str();
      }
      else if (
        auto user_sig_ident =
          args.try_get_caller<ccf::UserSignatureAuthnIdentity>())
      {
        policy_name = get_policy_name_from_ident(user_sig_ident);
        id = user_sig_ident->user_id;
        data = user_sig_ident->user_data;
        cert_s = user_sig_ident->user_cert.str();
      }
      else if (
        auto member_sig_ident =
          args.try_get_caller<ccf::MemberSignatureAuthnIdentity>())
      {
        policy_name = get_policy_name_from_ident(member_sig_ident);
        id = member_sig_ident->member_id;
        data = member_sig_ident->member_data;
        cert_s = member_sig_ident->member_cert.str();
      }

      if (policy_name == nullptr)
      {
        throw std::logic_error("Unable to convert caller info to JS object");
      }

      JS_SetPropertyStr(ctx, caller, "policy", JS_NewString(ctx, policy_name));
      JS_SetPropertyStr(ctx, caller, "id", JS_NewUint32(ctx, id));
      JS_SetPropertyStr(ctx, caller, "data", create_json_obj(data, ctx));
      JS_SetPropertyStr(
        ctx,
        caller,
        "cert",
        JS_NewStringLen(ctx, cert_s.data(), cert_s.size()));

      return caller;
    }

    static JSValue create_request_obj(EndpointContext& args, JSContext* ctx)
    {
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

      JS_SetPropertyStr(ctx, request, "caller", create_caller_obj(args, ctx));

      return request;
    }

    void execute_request(
      const std::string& method,
      const ccf::RESTVerb& verb,
      EndpointContext& args)
    {
      const auto local_method = method.substr(method.find_first_not_of('/'));

      const auto scripts = args.tx.ro(this->network.app_scripts);

      // Try to find script for method
      // - First try a script called "foo"
      // - If that fails, try a script called "POST foo"
      auto handler_script = scripts->get(local_method);
      if (!handler_script)
      {
        const auto verb_prefixed =
          fmt::format("{} {}", verb.c_str(), local_method);
        handler_script = scripts->get(verb_prefixed);
        if (!handler_script)
        {
          args.rpc_ctx->set_error(
            HTTP_STATUS_NOT_FOUND,
            ccf::errors::ResourceNotFound,
            fmt::format(
              "No handler script found for method '{}'.", verb_prefixed));
          return;
        }
      }

      JSRuntime* rt = JS_NewRuntime();
      if (rt == nullptr)
      {
        throw std::runtime_error("Failed to initialise QuickJS runtime");
      }
      JSAutoFreeRuntime auto_free_rt(rt);

      JS_SetMaxStackSize(rt, 1024 * 1024);
      JS_SetMemoryLimit(rt, 100 * 1024 * 1024);

      JSModuleLoaderArg js_module_loader_arg{&this->network, &args.tx};
      JS_SetModuleLoaderFunc(
        rt, nullptr, js_module_loader, &js_module_loader_arg);

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

      JSContext* ctx = JS_NewContext(rt);
      if (ctx == nullptr)
      {
        throw std::runtime_error("Failed to initialise QuickJS context");
      }
      JSAutoFreeCtx auto_free(ctx);
      JS_SetContextOpaque(ctx, &auto_free);

      // Set prototype for request body class
      JSValue body_proto = JS_NewObject(ctx);
      size_t func_count =
        sizeof(js_body_proto_funcs) / sizeof(js_body_proto_funcs[0]);
      JS_SetPropertyFunctionList(
        ctx, body_proto, js_body_proto_funcs, func_count);
      JS_SetClassProto(ctx, body_class_id, body_proto);

      // Populate globalThis with console and ccf globals
      populate_global_obj(args, ctx);

      // Compile module
      if (!handler_script.value().text.has_value())
      {
        throw std::runtime_error("Could not find script text");
      }
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

        args.rpc_ctx->set_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          "Exception thrown while compiling.");
        return;
      }

      // Evaluate module
      auto eval_val = JS_EvalFunction(ctx, module);
      if (JS_IsException(eval_val))
      {
        js_dump_error(ctx);
        args.rpc_ctx->set_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          "Exception thrown while executing.");
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
        JS_FreeValue(ctx, export_func);
        throw std::runtime_error(
          "Endpoint module exports something that is not a function");
      }

      // Call exported function
      auto request = create_request_obj(args, ctx);
      int argc = 1;
      JSValueConst* argv = (JSValueConst*)&request;
      auto val = auto_free(JS_Call(ctx, export_func, JS_UNDEFINED, argc, argv));
      JS_FreeValue(ctx, request);
      JS_FreeValue(ctx, export_func);

      if (JS_IsException(val))
      {
        js_dump_error(ctx);
        args.rpc_ctx->set_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          "Exception thrown while executing.");
        return;
      }

      // Handle return value: {body, headers, statusCode}
      if (!JS_IsObject(val))
      {
        args.rpc_ctx->set_error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          "Invalid endpoint function return value (not an object).");
        return;
      }

      // Response body (also sets a default response content-type header)
      {
        auto response_body_js = auto_free(JS_GetPropertyStr(ctx, val, "body"));
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
              http::headers::CONTENT_TYPE,
              http::headervalues::contenttype::TEXT);
            cstr = JS_ToCString(ctx, response_body_js);
          }
          else
          {
            args.rpc_ctx->set_response_header(
              http::headers::CONTENT_TYPE,
              http::headervalues::contenttype::JSON);
            JSValue rval =
              JS_JSONStringify(ctx, response_body_js, JS_NULL, JS_NULL);
            if (JS_IsException(rval))
            {
              js_dump_error(ctx);
              args.rpc_ctx->set_error(
                HTTP_STATUS_INTERNAL_SERVER_ERROR,
                ccf::errors::InternalError,
                "Invalid endpoint function return value (error during JSON "
                "conversion of body).");
              return;
            }
            cstr = JS_ToCString(ctx, rval);
            JS_FreeValue(ctx, rval);
          }
          if (!cstr)
          {
            js_dump_error(ctx);
            args.rpc_ctx->set_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              "Invalid endpoint function return value (error during string "
              "conversion of body).");
            return;
          }
          std::string str(cstr);
          JS_FreeCString(ctx, cstr);

          response_body = std::vector<uint8_t>(str.begin(), str.end());
        }
        args.rpc_ctx->set_response_body(std::move(response_body));
      }

      // Response headers
      {
        auto response_headers_js =
          auto_free(JS_GetPropertyStr(ctx, val, "headers"));
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
            auto prop_name_cstr = auto_free(JS_AtomToCString(ctx, prop_name));
            auto prop_val =
              auto_free(JS_GetProperty(ctx, response_headers_js, prop_name));
            auto prop_val_cstr = JS_ToCString(ctx, prop_val);
            if (!prop_val_cstr)
            {
              args.rpc_ctx->set_error(
                HTTP_STATUS_INTERNAL_SERVER_ERROR,
                ccf::errors::InternalError,
                "Invalid endpoint function return value (header value type).");
              return;
            }
            args.rpc_ctx->set_response_header(prop_name_cstr, prop_val_cstr);
            JS_FreeCString(ctx, prop_val_cstr);
          }
          js_free(ctx, props);
        }
      }

      // Response status code
      {
        int response_status_code = HTTP_STATUS_OK;
        auto status_code_js =
          auto_free(JS_GetPropertyStr(ctx, val, "statusCode"));
        if (!JS_IsUndefined(status_code_js) && !JS_IsNull(status_code_js))
        {
          if (JS_VALUE_GET_TAG(status_code_js.val) != JS_TAG_INT)
          {
            args.rpc_ctx->set_error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              "Invalid endpoint function return value (status code type).");
            return;
          }
          response_status_code = JS_VALUE_GET_INT(status_code_js.val);
        }
        args.rpc_ctx->set_response_status(response_status_code);
      }

      return;
    }

    struct JSDynamicEndpoint : public EndpointDefinition
    {};

  public:
    JSHandlers(NetworkTables& network, ccf::AbstractNodeState& node_state) :
      UserEndpointRegistry(node_state),
      network(network)
    {
      JS_NewClassID(&kv_class_id);
      kv_exotic_methods.get_own_property = js_kv_lookup;
      kv_class_def.class_name = "KV Tables";
      kv_class_def.exotic = &kv_exotic_methods;

      JS_NewClassID(&kv_map_handle_class_id);
      kv_map_handle_class_def.class_name = "KV Map Handle";

      JS_NewClassID(&body_class_id);
      body_class_def.class_name = "Body";

      auto default_handler = [this](EndpointContext& args) {
        execute_request(
          args.rpc_ctx->get_method(), args.rpc_ctx->get_request_verb(), args);
      };

      set_default(default_handler, no_auth_required);

      metrics_tracker.install_endpoint(*this);
    }

    void instantiate_authn_policies(JSDynamicEndpoint& endpoint)
    {
      for (const auto& policy_name : endpoint.properties.authn_policies)
      {
        auto policy = get_policy_by_name(policy_name);
        if (policy == nullptr)
        {
          throw std::logic_error(
            fmt::format("Unknown auth policy: {}", policy_name));
        }
        endpoint.authn_policies.push_back(std::move(policy));
      }
    }

    EndpointDefinitionPtr find_endpoint(
      kv::Tx& tx, enclave::RpcContext& rpc_ctx) override
    {
      const auto method = fmt::format("/{}", rpc_ctx.get_method());
      const auto verb = rpc_ctx.get_request_verb();

      auto endpoints =
        tx.ro<ccf::endpoints::EndpointsMap>(ccf::Tables::ENDPOINTS);

      const auto key = ccf::endpoints::EndpointKey{method, verb};

      // Look for a direct match of the given path
      const auto it = endpoints->get(key);
      if (it.has_value())
      {
        auto endpoint_def = std::make_shared<JSDynamicEndpoint>();
        endpoint_def->dispatch = key;
        endpoint_def->properties = it.value();
        instantiate_authn_policies(*endpoint_def);
        return endpoint_def;
      }

      // If that doesn't exist, look through _all_ the endpoints to find
      // templated matches. If there is one, that's a match. More is an error,
      // none means delegate to the base class.
      {
        std::vector<EndpointDefinitionPtr> matches;

        endpoints->foreach([this, &matches, &key, &rpc_ctx](
                             const auto& other_key, const auto& properties) {
          if (key.verb == other_key.verb)
          {
            const auto opt_spec =
              EndpointRegistry::parse_path_template(other_key.uri_path);
            if (opt_spec.has_value())
            {
              const auto& template_spec = opt_spec.value();
              // This endpoint has templates in its path, and the correct verb
              // - now check if template matches the current request's path
              std::smatch match;
              if (std::regex_match(
                    key.uri_path, match, template_spec.template_regex))
              {
                if (matches.empty())
                {
                  // Populate the request_path_params while we have the match,
                  // though this will be discarded on error if we later find
                  // multiple matches
                  auto& path_params = rpc_ctx.get_request_path_params();
                  for (size_t i = 0;
                       i < template_spec.template_component_names.size();
                       ++i)
                  {
                    const auto& template_name =
                      template_spec.template_component_names[i];
                    const auto& template_value = match[i + 1].str();
                    path_params[template_name] = template_value;
                  }
                }

                auto endpoint = std::make_shared<JSDynamicEndpoint>();
                endpoint->dispatch = other_key;
                endpoint->properties = properties;
                instantiate_authn_policies(*endpoint);
                matches.push_back(endpoint);
              }
            }
          }
          return true;
        });

        if (matches.size() > 1)
        {
          report_ambiguous_templated_path(key.uri_path, matches);
        }
        else if (matches.size() == 1)
        {
          return matches[0];
        }
      }

      return EndpointRegistry::find_endpoint(tx, rpc_ctx);
    }

    void execute_endpoint(
      EndpointDefinitionPtr e, EndpointContext& args) override
    {
      auto endpoint = dynamic_cast<const JSDynamicEndpoint*>(e.get());
      if (endpoint != nullptr)
      {
        execute_request(
          endpoint->dispatch.uri_path, endpoint->dispatch.verb, args);
        return;
      }

      EndpointRegistry::execute_endpoint(e, args);
    }

    // Since we do our own dispatch within the default handler, report the
    // supported methods here
    void build_api(nlohmann::json& document, kv::ReadOnlyTx& tx) override
    {
      UserEndpointRegistry::build_api(document, tx);

      auto endpoints =
        tx.ro<ccf::endpoints::EndpointsMap>(ccf::Tables::ENDPOINTS);

      endpoints->foreach([&document](const auto& key, const auto& properties) {
        const auto http_verb = key.verb.get_http_method();
        if (!http_verb.has_value())
        {
          return true;
        }

        if (!properties.openapi_hidden)
        {
          auto& path_op = ds::openapi::path_operation(
            ds::openapi::path(document, key.uri_path), http_verb.value());
          if (!properties.openapi.empty())
          {
            path_op.insert(
              properties.openapi.cbegin(), properties.openapi.cend());
          }
        }

        return true;
      });
    }

    void tick(
      std::chrono::milliseconds elapsed,
      kv::Consensus::Statistics stats) override
    {
      metrics_tracker.tick(elapsed, stats);

      ccf::UserEndpointRegistry::tick(elapsed, stats);
    }
  };

#pragma clang diagnostic pop

  class JS : public ccf::UserRpcFrontend
  {
  private:
    JSHandlers js_handlers;

  public:
    JS(NetworkTables& network, ccfapp::AbstractNodeContext& node_context) :
      ccf::UserRpcFrontend(*network.tables, js_handlers),
      js_handlers(network, node_context.get_node_state())
    {}
  };

  std::shared_ptr<ccf::UserRpcFrontend> get_rpc_handler(
    NetworkTables& network, ccfapp::AbstractNodeContext& node_context)
  {
    return make_shared<JS>(network, node_context);
  }
} // namespace ccfapp
