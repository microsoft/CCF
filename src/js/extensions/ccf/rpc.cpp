// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/js/extensions/ccf/rpc.h"

#include "ccf/js/core/context.h"
#include "ccf/rpc_context.h"

#include <quickjs/quickjs.h>

namespace ccf::js::extensions
{
  namespace
  {
    JSValue js_rpc_set_apply_writes(
      JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
    {
      (void)this_val;
      js::core::Context& jsctx =
        *reinterpret_cast<js::core::Context*>(JS_GetContextOpaque(ctx));

      if (argc != 1)
      {
        return JS_ThrowTypeError(
          ctx, "Passed %d arguments but expected 1", argc);
      }

      auto* extension = jsctx.get_extension<RpcExtension>();
      if (extension == nullptr)
      {
        return JS_ThrowInternalError(ctx, "Failed to get extension object");
      }

      auto* rpc_ctx = extension->rpc_ctx;
      if (rpc_ctx == nullptr)
      {
        return JS_ThrowInternalError(ctx, "RPC context is not set");
      }

      int val = JS_ToBool(ctx, argv[0]);
      if (val == -1)
      {
        return ccf::js::core::constants::Exception;
      }

      rpc_ctx->set_apply_writes(val != 0);
      return ccf::js::core::constants::Undefined;
    }

    JSValue js_rpc_set_claims_digest(
      JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
    {
      (void)this_val;
      js::core::Context& jsctx =
        *reinterpret_cast<js::core::Context*>(JS_GetContextOpaque(ctx));

      if (argc != 1)
      {
        return JS_ThrowTypeError(
          ctx, "Passed %d arguments but expected 1", argc);
      }

      auto* extension = jsctx.get_extension<RpcExtension>();
      if (extension == nullptr)
      {
        return JS_ThrowInternalError(ctx, "Failed to get extension object");
      }

      auto* rpc_ctx = extension->rpc_ctx;
      if (rpc_ctx == nullptr)
      {
        return JS_ThrowInternalError(ctx, "RPC context is not set");
      }

      size_t digest_size = 0;
      uint8_t* digest = JS_GetArrayBuffer(ctx, &digest_size, argv[0]);

      if (digest == nullptr)
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

      return ccf::js::core::constants::Undefined;
    }
  }

  void RpcExtension::install(js::core::Context& ctx)
  {
    auto rpc = JS_NewObject(ctx);

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

    auto ccf = ctx.get_or_create_global_property("ccf", ctx.new_obj());
    // NOLINTBEGIN(performance-move-const-arg)
    ccf.set("rpc", std::move(rpc));
    // NOLINTEND(performance-move-const-arg)
  }
}
