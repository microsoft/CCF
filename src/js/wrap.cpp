// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ccf/ds/logger.h"
#include "ccf/rpc_context.h"
#include "ccf/service/tables/jwt.h"
#include "ccf/tx_id.h"
#include "crypto/certs.h"
#include "enclave/enclave_time.h"
#include "js/context.h"
#include "js/global_class_ids.h"
#include "js/no_plugins.cpp"
#include "node/rpc/call_types.h"
#include "node/rpc/gov_effects_interface.h"
#include "node/rpc/gov_logging.h"
#include "node/rpc/jwt_management.h"
#include "node/rpc/node_interface.h"

#include <algorithm>
#include <memory>
#include <quickjs/quickjs-exports.h>
#include <quickjs/quickjs.h>
#include <span>

namespace ccf::js
{
// "mixture of designated and non-designated initializers in the same
// initializer list is a C99 extension"
// Used heavily by QuickJS, including in macros (such as JS_CFUNC_DEF) repeated
// here
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc99-extensions"



  JSValue js_body_text(
    JSContext* ctx,
    JSValueConst this_val,
    int argc,
    [[maybe_unused]] JSValueConst* argv)
  {
    if (argc != 0)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected none", argc);

    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);
    auto body = jsctx.globals.current_request_body;
    if (body == nullptr)
    {
      return JS_ThrowInternalError(ctx, "No request body set");
    }

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

    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);
    auto body = jsctx.globals.current_request_body;
    if (body == nullptr)
    {
      return JS_ThrowTypeError(ctx, "No request body set");
    }

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

    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);
    auto body = jsctx.globals.current_request_body;
    if (body == nullptr)
    {
      return JS_ThrowTypeError(ctx, "No request body set");
    }

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

#pragma clang diagnostic pop
}

extern "C"
{
  int qjs_gettimeofday(struct JSContext* ctx, struct timeval* tv, void* tz)
  {
    if (tv != NULL)
    {
      // Opaque may be null, when this is called during Context construction
      const ccf::js::Context* jsctx =
        (ccf::js::Context*)JS_GetContextOpaque(ctx);
      if (jsctx != nullptr && jsctx->implement_untrusted_time)
      {
        const auto microseconds_since_epoch = ccf::get_enclave_time();
        tv->tv_sec = std::chrono::duration_cast<std::chrono::seconds>(
                       microseconds_since_epoch)
                       .count();
        tv->tv_usec = microseconds_since_epoch.count() % std::micro::den;
      }
      else
      {
        memset(tv, 0, sizeof(struct timeval));
      }
    }
    return 0;
  }
}
