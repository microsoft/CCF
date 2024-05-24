// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

// NB: Despite the naming scheme used elsewhere, this populates functions
// directly on the ccf object.

#include "ccf/js/extensions/ccf/gov_effects.h"

#include "ccf/js/core/context.h"
#include "ccf/js/modules.h"
#include "ccf/version.h"
#include "node/rpc/jwt_management.h"

#include <quickjs/quickjs.h>

namespace ccf::js::extensions
{
  namespace
  {
    JSValue js_refresh_app_bytecode_cache(
      JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
    {
      js::core::Context& jsctx = *(js::core::Context*)JS_GetContextOpaque(ctx);

      if (argc != 0)
      {
        return JS_ThrowTypeError(
          ctx, "Passed %d arguments but expected none", argc);
      }

      auto extension = jsctx.get_extension<GovEffectsExtension>();
      if (extension == nullptr)
      {
        return JS_ThrowInternalError(ctx, "Failed to get extension object");
      }

      auto tx_ptr = extension->tx;
      if (tx_ptr == nullptr)
      {
        return JS_ThrowInternalError(ctx, "No transaction available");
      }

      auto& tx = *tx_ptr;

      js::core::Context ctx2(js::TxAccess::APP_RW);
      ctx2.runtime().set_runtime_options(
        tx_ptr, js::core::RuntimeLimitsPolicy::NO_LOWER_THAN_DEFAULTS);
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

      return ccf::js::core::constants::Undefined;
    }

    JSValue js_gov_set_jwt_public_signing_keys(
      JSContext* ctx,
      [[maybe_unused]] JSValueConst this_val,
      int argc,
      JSValueConst* argv)
    {
      js::core::Context& jsctx = *(js::core::Context*)JS_GetContextOpaque(ctx);

      if (argc != 3)
      {
        return JS_ThrowTypeError(
          ctx, "Passed %d arguments but expected 3", argc);
      }

      auto extension = jsctx.get_extension<GovEffectsExtension>();
      if (extension == nullptr)
      {
        return JS_ThrowInternalError(ctx, "Failed to get extension object");
      }

      auto tx_ptr = extension->tx;
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

      auto metadata_val = jsctx.json_stringify(jsctx.wrap(argv[1]));
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

      auto jwks_val = jsctx.json_stringify(jsctx.wrap(argv[2]));
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
      return ccf::js::core::constants::Undefined;
    }

    JSValue js_gov_remove_jwt_public_signing_keys(
      JSContext* ctx,
      [[maybe_unused]] JSValueConst this_val,
      int argc,
      JSValueConst* argv)
    {
      js::core::Context& jsctx = *(js::core::Context*)JS_GetContextOpaque(ctx);

      if (argc != 1)
      {
        return JS_ThrowTypeError(
          ctx, "Passed %d arguments but expected 1", argc);
      }

      auto extension = jsctx.get_extension<GovEffectsExtension>();
      if (extension == nullptr)
      {
        return JS_ThrowInternalError(ctx, "Failed to get extension object");
      }

      auto tx_ptr = extension->tx;
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
      return ccf::js::core::constants::Undefined;
    }
  }

  void GovEffectsExtension::install(js::core::Context& ctx)
  {
    auto ccf = ctx.get_or_create_global_property("ccf", ctx.new_obj());

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
