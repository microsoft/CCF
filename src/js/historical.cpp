// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "js/wrap.h"

namespace ccf::js
{
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc99-extensions"

  static JSValue ccf_receipt_to_js(JSContext* ctx, TxReceiptImplPtr receipt)
  {
    ccf::ReceiptPtr receipt_out_p = ccf::describe_receipt_v2(*receipt);
    auto& receipt_out = *receipt_out_p;
    auto js_receipt = JS_NewObject(ctx);

    const auto sig_b64 = crypto::b64_from_raw(receipt_out.signature);
    JS_SetPropertyStr(
      ctx, js_receipt, "signature", JS_NewString(ctx, sig_b64.c_str()));

    JS_SetPropertyStr(
      ctx,
      js_receipt,
      "cert",
      JS_NewString(ctx, receipt_out.cert.str().c_str()));

    JS_SetPropertyStr(
      ctx,
      js_receipt,
      "node_id",
      JS_NewString(ctx, receipt_out.node_id.value().c_str()));

    JS_SetPropertyStr(
      ctx,
      js_receipt,
      "is_signature_transaction",
      JS_NewBool(ctx, receipt_out.is_signature_transaction()));

    if (!receipt_out_p->is_signature_transaction())
    {
      auto p_receipt =
        std::dynamic_pointer_cast<ccf::ProofReceipt>(receipt_out_p);
      auto leaf_components = JS_NewObject(ctx);
      const auto wsd_hex =
        ds::to_hex(p_receipt->leaf_components.write_set_digest.h);
      JS_SetPropertyStr(
        ctx,
        leaf_components,
        "write_set_digest",
        JS_NewString(ctx, wsd_hex.c_str()));

      JS_SetPropertyStr(
        ctx,
        leaf_components,
        "commit_evidence",
        JS_NewString(ctx, p_receipt->leaf_components.commit_evidence.c_str()));

      if (!p_receipt->leaf_components.claims_digest.empty())
      {
        const auto cd_hex =
          ds::to_hex(p_receipt->leaf_components.claims_digest.value().h);
        JS_SetPropertyStr(
          ctx,
          leaf_components,
          "claims_digest",
          JS_NewString(ctx, cd_hex.c_str()));
      }

      JS_SetPropertyStr(ctx, js_receipt, "leaf_components", leaf_components);

      auto proof = JS_NewArray(ctx);
      uint32_t i = 0;
      for (auto& element : p_receipt->proof)
      {
        auto js_element = JS_NewObject(ctx);
        auto is_left = element.direction == ccf::ProofReceipt::ProofStep::Left;
        const auto hash_hex = ds::to_hex(element.hash.h);
        JS_SetPropertyStr(
          ctx,
          js_element,
          is_left ? "left" : "right",
          JS_NewString(ctx, hash_hex.c_str()));
        JS_DefinePropertyValueUint32(
          ctx, proof, i++, js_element, JS_PROP_C_W_E);
      }
      JS_SetPropertyStr(ctx, js_receipt, "proof", proof);
    }
    else
    {
      auto sig_receipt =
        std::dynamic_pointer_cast<ccf::SignatureReceipt>(receipt_out_p);
      const auto signed_root = sig_receipt->signed_root;
      const auto root_hex = ds::to_hex(signed_root.h);
      JS_SetPropertyStr(
        ctx, js_receipt, "root_hex", JS_NewString(ctx, root_hex.c_str()));
    }

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
        state, state->store->create_read_only_tx(), ReadOnlyTxContext{nullptr}};
      state_ctx->tx_ctx.tx = &state_ctx->tx;
      JS_SetOpaque(js_state, state_ctx);

      JS_SetPropertyStr(
        ctx,
        js_state,
        "transactionId",
        JS_NewString(ctx, state->transaction_id.to_str().c_str()));
      auto js_receipt = ccf_receipt_to_js(ctx, state->receipt);
      JS_SetPropertyStr(ctx, js_state, "receipt", js_receipt);

      auto kv = JS_NewObjectClass(ctx, kv_read_only_class_id);
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

    auto found = historical_state->drop_cached_states(handle);
    return JS_NewBool(ctx, found);
  }

#pragma clang diagnostic pop
}