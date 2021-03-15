// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "crypto/entropy.h"
#include "crypto/key_wrap.h"
#include "crypto/rsa_key_pair.h"
#include "enclave/app_interface.h"
#include "js/wrap.h"
#include "kv/untyped_map.h"
#include "named_auth_policies.h"
#include "node/rpc/metrics_tracker.h"
#include "node/rpc/user_frontend.h"

#include <memory>
#include <quickjs/quickjs-exports.h>
#include <quickjs/quickjs.h>
#include <stdexcept>
#include <vector>

namespace ccfapp
{
  using namespace std;
  using namespace kv;
  using namespace ccf;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc99-extensions"

  static JSValue js_generate_aes_key(
    JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
  {
    if (argc != 1)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 1", argc);

    int32_t key_size;
    if (JS_ToInt32(ctx, &key_size, argv[0]) < 0)
    {
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }
    // Supported key sizes for AES.
    if (key_size != 128 && key_size != 192 && key_size != 256)
    {
      JS_ThrowRangeError(ctx, "invalid key size");
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    std::vector<uint8_t> key = crypto::create_entropy()->random(key_size / 8);

    return JS_NewArrayBufferCopy(ctx, key.data(), key.size());
  }

  static JSValue js_generate_rsa_key_pair(
    JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
  {
    if (argc != 1 && argc != 2)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 1 or 2", argc);

    uint32_t key_size = 0, key_exponent = 0;
    if (JS_ToUint32(ctx, &key_size, argv[0]) < 0)
    {
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    if (argc == 2 && JS_ToUint32(ctx, &key_exponent, argv[1]) < 0)
    {
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    std::shared_ptr<RSAKeyPair> k;
    if (argc == 1)
    {
      k = crypto::make_rsa_key_pair(key_size);
    }
    else
    {
      k = crypto::make_rsa_key_pair(key_size, key_exponent);
    }

    Pem prv = k->private_key_pem();
    Pem pub = k->public_key_pem();

    auto r = JS_NewObject(ctx);
    JS_SetPropertyStr(
      ctx, r, "privateKey", JS_NewString(ctx, (char*)prv.data()));
    JS_SetPropertyStr(
      ctx, r, "publicKey", JS_NewString(ctx, (char*)pub.data()));
    return r;
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
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    size_t wrapping_key_size;
    uint8_t* wrapping_key = JS_GetArrayBuffer(ctx, &wrapping_key_size, argv[1]);
    if (!wrapping_key)
    {
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    void* auto_free_ptr = JS_GetContextOpaque(ctx);
    js::Context& auto_free = *(js::Context*)auto_free_ptr;

    auto parameters = argv[2];
    JSValue wrap_algo_name_val =
      auto_free(JS_GetPropertyStr(ctx, parameters, "name"));

    auto wrap_algo_name_cstr = auto_free(JS_ToCString(ctx, wrap_algo_name_val));

    if (!wrap_algo_name_cstr)
    {
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    try
    {
      auto algo_name = std::string(wrap_algo_name_cstr);
      if (algo_name == "RSA-OAEP")
      {
        // key can in principle be arbitrary data (see note on maximum size
        // in rsa_key_pair.h). wrapping_key is a public RSA key.

        auto label_val = auto_free(JS_GetPropertyStr(ctx, parameters, "label"));
        size_t label_buf_size = 0;
        uint8_t* label_buf = JS_GetArrayBuffer(ctx, &label_buf_size, label_val);

        auto wrapped_key = crypto::ckm_rsa_pkcs_oaep_wrap(
          Pem(wrapping_key, wrapping_key_size),
          {key, key + key_size},
          {label_buf, label_buf + label_buf_size});

        return JS_NewArrayBufferCopy(
          ctx, wrapped_key.data(), wrapped_key.size());
      }
      else if (algo_name == "AES-KWP")
      {
        std::vector<uint8_t> wrapped_key = crypto::ckm_aes_key_wrap_pad(
          {wrapping_key, wrapping_key + wrapping_key_size},
          {key, key + key_size});

        return JS_NewArrayBufferCopy(
          ctx, wrapped_key.data(), wrapped_key.size());
      }
      else if (algo_name == "RSA-OAEP-AES-KWP")
      {
        auto aes_key_size_value =
          auto_free(JS_GetPropertyStr(ctx, parameters, "aesKeySize"));
        int32_t aes_key_size = 0;
        if (JS_ToInt32(ctx, &aes_key_size, aes_key_size_value) < 0)
        {
          js::js_dump_error(ctx);
          return JS_EXCEPTION;
        }

        auto label_val = auto_free(JS_GetPropertyStr(ctx, parameters, "label"));
        size_t label_buf_size = 0;
        uint8_t* label_buf = JS_GetArrayBuffer(ctx, &label_buf_size, label_val);

        auto wrapped_key = crypto::ckm_rsa_aes_key_wrap(
          aes_key_size,
          Pem(wrapping_key, wrapping_key_size),
          {key, key + key_size},
          {label_buf, label_buf + label_buf_size});

        return JS_NewArrayBufferCopy(
          ctx, wrapped_key.data(), wrapped_key.size());
      }
      else
      {
        JS_ThrowRangeError(
          ctx,
          "unsupported key wrapping algorithm, supported: RSA-OAEP, AES-KWP, "
          "RSA-OAEP-AES-KWP");
        js::js_dump_error(ctx);
        return JS_EXCEPTION;
      }
    }
    catch (std::exception& ex)
    {
      JS_ThrowRangeError(ctx, "%s", ex.what());
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }
    catch (...)
    {
      JS_ThrowRangeError(ctx, "caught unknown exception");
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }
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
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    JSValue buf = JS_NewArrayBuffer(
      ctx, (uint8_t*)str, str_size, js_free_arraybuffer_cstring, ctx, false);

    if (JS_IsException(buf))
      js::js_dump_error(ctx);

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

  // Modules

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
      js::js_dump_error(ctx);
      return nullptr;
    }

    auto m = (JSModuleDef*)JS_VALUE_GET_PTR(func_val);
    // module already referenced, decrement ref count
    JS_FreeValue(ctx, func_val);
    return m;
  }

  // END modules

  class JSHandlers : public UserEndpointRegistry
  {
  private:
    NetworkTables& network;
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
        "generateRsaKeyPair",
        JS_NewCFunction(
          ctx, ccfapp::js_generate_rsa_key_pair, "generateRsaKeyPair", 1));
      JS_SetPropertyStr(
        ctx,
        ccf,
        "wrapKey",
        JS_NewCFunction(ctx, ccfapp::js_wrap_key, "wrapKey", 3));

      auto kv = JS_NewObjectClass(ctx, js::kv_class_id);
      JS_SetOpaque(kv, &args.tx);
      JS_SetPropertyStr(ctx, ccf, "kv", kv);

      return ccf;
    }

    static JSValue create_console_obj(JSContext* ctx)
    {
      auto console = JS_NewObject(ctx);

      JS_SetPropertyStr(
        ctx, console, "log", JS_NewCFunction(ctx, js::js_print, "log", 1));

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
      CallerId id;
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
      JS_SetPropertyStr(
        ctx, caller, "id", JS_NewStringLen(ctx, id.data(), id.size()));
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
      auto body_ = JS_NewObjectClass(ctx, js::body_class_id);
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

      js::Runtime rt;

      JSModuleLoaderArg js_module_loader_arg{&this->network, &args.tx};
      JS_SetModuleLoaderFunc(
        rt, nullptr, js_module_loader, &js_module_loader_arg);

      // Register class for KV
      {
        auto ret = JS_NewClass(rt, js::kv_class_id, &js::kv_class_def);
        if (ret != 0)
        {
          throw std::logic_error(
            "Failed to register JS class definition for KV");
        }
      }

      // Register class for KV map views
      {
        auto ret = JS_NewClass(
          rt, js::kv_map_handle_class_id, &js::kv_map_handle_class_def);
        if (ret != 0)
        {
          throw std::logic_error(
            "Failed to register JS class definition for KVMap");
        }
      }

      // Register class for request body
      {
        auto ret = JS_NewClass(rt, js::body_class_id, &js::body_class_def);
        if (ret != 0)
        {
          throw std::logic_error(
            "Failed to register JS class definition for Body");
        }
      }

      js::Context ctx(rt);

      js::register_request_body_class(ctx);

      // Populate globalThis with console and ccf globals
      populate_global_obj(args, ctx);

      // Compile module
      if (!handler_script.value().text.has_value())
      {
        throw std::runtime_error("Could not find script text");
      }
      std::string code = handler_script.value().text.value();
      const std::string path = "/__endpoint__.js";

      auto export_func = ctx.function(code, path);

      // Call exported function
      auto request = create_request_obj(args, ctx);
      int argc = 1;
      JSValueConst* argv = (JSValueConst*)&request;
      auto val = ctx(JS_Call(ctx, export_func, JS_UNDEFINED, argc, argv));
      JS_FreeValue(ctx, request);
      JS_FreeValue(ctx, export_func);

      if (JS_IsException(val))
      {
        js::js_dump_error(ctx);
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
        auto response_body_js = ctx(JS_GetPropertyStr(ctx, val, "body"));
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
              js::js_dump_error(ctx);
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
            js::js_dump_error(ctx);
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
        auto response_headers_js = ctx(JS_GetPropertyStr(ctx, val, "headers"));
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
            auto prop_name_cstr = ctx(JS_AtomToCString(ctx, prop_name));
            auto prop_val =
              ctx(JS_GetProperty(ctx, response_headers_js, prop_name));
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
        auto status_code_js = ctx(JS_GetPropertyStr(ctx, val, "statusCode"));
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
    JSHandlers(NetworkTables& network, AbstractNodeContext& context) :
      UserEndpointRegistry(context),
      network(network)
    {
      js::register_class_ids();
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
            ds::openapi::path(document, key.uri_path),
            http_verb.value(),
            false);
          LOG_INFO_FMT(
            "Building OpenAPI for {} {}", key.verb.c_str(), key.uri_path);
          const auto dumped = document.dump(2);
          LOG_INFO_FMT(
            "Starting from: {}", std::string(dumped.begin(), dumped.end()));
          if (!properties.openapi.empty())
          {
            for (const auto& [k, v] : properties.openapi.items())
            {
              LOG_INFO_FMT("Inserting field {}", k);
            }
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
    JS(NetworkTables& network, ccfapp::AbstractNodeContext& context) :
      ccf::UserRpcFrontend(*network.tables, js_handlers),
      js_handlers(network, context)
    {}
  };

  std::shared_ptr<ccf::UserRpcFrontend> get_rpc_handler(
    NetworkTables& network, ccfapp::AbstractNodeContext& context)
  {
    return make_shared<JS>(network, context);
  }
} // namespace ccfapp
