// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "js/wrap.h"

namespace ccf::js
{
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc99-extensions"

  static JSValue ccf_receipt_to_js(JSContext* ctx, TxReceiptPtr receipt)
  {
    ccf::Receipt receipt_out;
    receipt->describe(receipt_out);
    auto js_receipt = JS_NewObject(ctx);
    JS_SetPropertyStr(
      ctx,
      js_receipt,
      "signature",
      JS_NewString(ctx, receipt_out.signature.c_str()));
    if (receipt_out.cert.has_value())
      JS_SetPropertyStr(
        ctx,
        js_receipt,
        "cert",
        JS_NewString(ctx, receipt_out.cert.value().c_str()));
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
      JS_DefinePropertyValueUint32(ctx, proof, i++, js_element, JS_PROP_C_W_E);
    }
    JS_SetPropertyStr(ctx, js_receipt, "proof", proof);
    return js_receipt;
  }

  static void js_historical_state_finalizer(JSRuntime* rt, JSValue val)
  {
    auto* state_ctx =
      (HistoricalStateContext*)JS_GetOpaque(val, historical_state_class_id);
    delete state_ctx;
  }

  static JSValue js_historical_get_state_range(
    JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
  {
    if (argc != 4)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 4", argc);

    auto historical_state = static_cast<ccf::historical::AbstractStateCache*>(
      JS_GetOpaque(this_val, historical_class_id));
    if (historical_state == nullptr)
      return JS_ThrowInternalError(ctx, "Failed to get state cache");

    int64_t handle;
    int64_t start_seqno;
    int64_t end_seqno;
    int64_t seconds_until_expiry;
    if (JS_ToInt64(ctx, &handle, argv[0]) < 0)
      return JS_EXCEPTION;
    if (JS_ToInt64(ctx, &start_seqno, argv[1]) < 0)
      return JS_EXCEPTION;
    if (JS_ToInt64(ctx, &end_seqno, argv[2]) < 0)
      return JS_EXCEPTION;
    if (JS_ToInt64(ctx, &seconds_until_expiry, argv[3]) < 0)
      return JS_EXCEPTION;
    if (
      handle < 0 || start_seqno < 0 || end_seqno < 0 ||
      seconds_until_expiry < 0)
      return JS_ThrowRangeError(
        ctx, "Invalid handle or seqno or expiry: cannot be negative");

    ccf::View view;
    ccf::SeqNo seqno;
    std::vector<ccf::historical::StatePtr> states;
    try
    {
      states = historical_state->get_state_range(
        handle,
        start_seqno,
        end_seqno,
        std::chrono::seconds(seconds_until_expiry));
    }
    catch (std::exception& exc)
    {
      return JS_ThrowInternalError(ctx, "Error: %s", exc.what());
    }

    if (states.empty())
    {
      return JS_NULL;
    }

    auto states_array = JS_NewArray(ctx);
    size_t i = 0;
    for (auto& state : states)
    {
      auto js_state = JS_NewObjectClass(ctx, historical_state_class_id);

      // Note: The state_ctx object is deleted by js_historical_state_finalizer
      // which is registered as the finalizer for historical_state_class_id.
      auto state_ctx = new HistoricalStateContext{
        state, state->store->create_tx(), TxContext{nullptr, TxAccess::APP}};
      state_ctx->tx_ctx.tx = &state_ctx->tx;
      JS_SetOpaque(js_state, state_ctx);

      JS_SetPropertyStr(
        ctx,
        js_state,
        "transactionId",
        JS_NewString(ctx, state->transaction_id.to_str().c_str()));
      auto js_receipt = ccf_receipt_to_js(ctx, state->receipt);
      JS_SetPropertyStr(ctx, js_state, "receipt", js_receipt);

      auto kv = JS_NewObjectClass(ctx, kv_class_id);
      JS_SetOpaque(kv, &state_ctx->tx_ctx);
      JS_SetPropertyStr(ctx, js_state, "kv", kv);

      JS_SetPropertyUint32(ctx, states_array, i++, js_state);
    }

    return states_array;
  }

  static JSValue js_historical_drop_cached_states(
    JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
  {
    if (argc != 1)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 1", argc);

    auto historical_state = static_cast<ccf::historical::AbstractStateCache*>(
      JS_GetOpaque(this_val, historical_class_id));
    if (historical_state == nullptr)
      return JS_ThrowInternalError(ctx, "Failed to get state cache");

    int64_t handle;
    if (JS_ToInt64(ctx, &handle, argv[0]) < 0)
      return JS_EXCEPTION;
    if (handle < 0)
      return JS_ThrowRangeError(ctx, "Invalid handle: cannot be negative");

    auto found = historical_state->drop_request(handle);
    return JS_NewBool(ctx, found);
  }

#pragma clang diagnostic pop
}