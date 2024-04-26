// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/rpc_context.h"
#include "js/context.h"
#include "js/global_class_ids.h"

#include <quickjs/quickjs.h>

namespace ccf::js
{
  namespace
  {
    JSValue js_rpc_set_apply_writes(
      JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
    {
      js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

      if (argc != 1)
      {
        return JS_ThrowTypeError(
          ctx, "Passed %d arguments but expected 1", argc);
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
        return JS_ThrowTypeError(
          ctx, "Passed %d arguments but expected 1", argc);
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
  }

  JSValue create_global_rpc_object(ccf::RpcContext* rpc_ctx, JSContext* ctx)
  {
    auto rpc = JS_NewObjectClass(ctx, rpc_class_id);
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

    return rpc;
  }
}
