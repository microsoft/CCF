// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "ccf/version.h"
#include "js/checks.h"
#include "js/context.h"
#include "js/modules.h"
#include "node/rpc/jwt_management.h"

namespace ccf::js::globals
{
  namespace
  {
    static JSValue js_str_to_buf(
      JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
    {
      js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

      if (argc != 1)
      {
        return JS_ThrowTypeError(
          ctx, "Passed %d arguments, but expected 1", argc);
      }

      if (!JS_IsString(argv[0]))
      {
        return JS_ThrowTypeError(ctx, "Argument must be a string");
      }

      auto str = jsctx.to_str(argv[0]);
      if (!str)
      {
        return ccf::js::constants::Exception;
      }

      auto buf =
        jsctx.new_array_buffer_copy((uint8_t*)str->c_str(), str->size());
      JS_CHECK_EXC(buf);

      return buf.take();
    }

    static JSValue js_buf_to_str(
      JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
    {
      js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

      if (argc != 1)
      {
        return JS_ThrowTypeError(
          ctx, "Passed %d arguments, but expected 1", argc);
      }

      size_t buf_size;
      uint8_t* buf = JS_GetArrayBuffer(ctx, &buf_size, argv[0]);

      if (!buf)
      {
        return JS_ThrowTypeError(ctx, "Argument must be an ArrayBuffer");
      }

      auto str = jsctx.new_string_len((char*)buf, buf_size);
      JS_CHECK_EXC(str);

      return str.take();
    }

    static JSValue js_json_compatible_to_buf(
      JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
    {
      js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

      if (argc != 1)
      {
        return JS_ThrowTypeError(
          ctx, "Passed %d arguments, but expected 1", argc);
      }

      auto str = jsctx.json_stringify(JSWrappedValue(ctx, argv[0]));
      JS_CHECK_EXC(str);

      return js_str_to_buf(ctx, ccf::js::constants::Null, 1, &str.val);
    }

    static JSValue js_buf_to_json_compatible(
      JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
    {
      js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

      if (argc != 1)
      {
        return JS_ThrowTypeError(
          ctx, "Passed %d arguments, but expected 1", argc);
      }

      size_t buf_size;
      uint8_t* buf = JS_GetArrayBuffer(ctx, &buf_size, argv[0]);

      if (!buf)
      {
        return JS_ThrowTypeError(ctx, "Argument must be an ArrayBuffer");
      }

      std::vector<uint8_t> buf_null_terminated(buf_size + 1);
      buf_null_terminated[buf_size] = 0;
      buf_null_terminated.assign(buf, buf + buf_size);

      auto obj =
        jsctx.parse_json((char*)buf_null_terminated.data(), buf_size, "<json>");
      JS_CHECK_EXC(obj);

      return obj.take();
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

    static JSValue js_pem_to_id(
      JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
    {
      if (argc != 1)
        return JS_ThrowTypeError(
          ctx, "Passed %d arguments, but expected 1", argc);

      js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

      auto pem_str = jsctx.to_str(argv[0]);
      if (!pem_str)
      {
        return ccf::js::constants::Exception;
      }

      try
      {
        auto pem = crypto::Pem(*pem_str);
        auto der = crypto::make_verifier(pem)->cert_der();
        auto id = crypto::Sha256Hash(der).hex_str();

        return JS_NewString(ctx, id.c_str());
      }
      catch (const std::exception& exc)
      {
        return JS_ThrowInternalError(
          ctx, "Failed to parse PEM: %s", exc.what());
      }
    }

    static JSValue js_refresh_app_bytecode_cache(
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
      auto quickjs_bytecode = tx.wo<ccf::ModulesQuickJsBytecode>(
        ccf::Tables::MODULES_QUICKJS_BYTECODE);

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

    static JSValue js_gov_set_jwt_public_signing_keys(
      JSContext* ctx,
      [[maybe_unused]] JSValueConst this_val,
      int argc,
      JSValueConst* argv)
    {
      js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

      if (argc != 3)
      {
        return JS_ThrowTypeError(
          ctx, "Passed %d arguments but expected 3", argc);
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
        return JS_ThrowTypeError(
          ctx, "Passed %d arguments but expected 1", argc);
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

  void extend_ccf_object_with_gov_actions(js::Context& ctx)
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
}