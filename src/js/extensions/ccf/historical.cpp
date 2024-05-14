// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "js/extensions/ccf/historical.h"

#include "ccf/ds/hex.h"
#include "ccf/historical_queries_interface.h"
#include "js/checks.h"
#include "js/core/context.h"
#include "js/global_class_ids.h"

namespace ccf::js::extensions
{
  namespace
  {
    static JSValue js_historical_get_state_range(
      JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
    {
      if (argc != 4)
      {
        return JS_ThrowTypeError(
          ctx, "Passed %d arguments, but expected 4", argc);
      }

      js::core::Context& jsctx = *(js::core::Context*)JS_GetContextOpaque(ctx);
      auto extension = jsctx.get_extension<CcfHistoricalExtension>();

      if (extension == nullptr)
      {
        return JS_ThrowInternalError(ctx, "Failed to get extension object");
      }

      auto historical_state = extension->historical_state;
      if (historical_state == nullptr)
      {
        return JS_ThrowInternalError(ctx, "Failed to get state cache");
      }

      int64_t handle;
      int64_t start_seqno;
      int64_t end_seqno;
      int64_t seconds_until_expiry;
      if (JS_ToInt64(ctx, &handle, argv[0]) < 0)
      {
        return ccf::js::core::constants::Exception;
      }
      if (JS_ToInt64(ctx, &start_seqno, argv[1]) < 0)
      {
        return ccf::js::core::constants::Exception;
      }
      if (JS_ToInt64(ctx, &end_seqno, argv[2]) < 0)
      {
        return ccf::js::core::constants::Exception;
      }
      if (JS_ToInt64(ctx, &seconds_until_expiry, argv[3]) < 0)
      {
        return ccf::js::core::constants::Exception;
      }
      if (
        handle < 0 || start_seqno < 0 || end_seqno < 0 ||
        seconds_until_expiry < 0)
      {
        return JS_ThrowRangeError(
          ctx, "Invalid handle or seqno or expiry: cannot be negative");
      }

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
        return JS_ThrowInternalError(
          ctx, "Failed to get state range: %s", exc.what());
      }

      if (states.empty())
      {
        return ccf::js::core::constants::Null;
      }

      auto states_array = jsctx.new_array();
      JS_CHECK_EXC(states_array);
      size_t i = 0;
      for (auto& state : states)
      {
        auto js_state =
          jsctx.wrap(extension->create_historical_state_object(jsctx, state));
        JS_CHECK_SET(states_array.set_at_index(i++, std::move(js_state)));
      }

      return states_array.take();
    }

    static JSValue js_historical_drop_cached_states(
      JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
    {
      if (argc != 1)
      {
        return JS_ThrowTypeError(
          ctx, "Passed %d arguments, but expected 1", argc);
      }

      js::core::Context& jsctx = *(js::core::Context*)JS_GetContextOpaque(ctx);
      auto extension = jsctx.get_extension<CcfHistoricalExtension>();

      if (extension == nullptr)
      {
        return JS_ThrowInternalError(ctx, "Failed to get extension object");
      }

      auto historical_state = extension->historical_state;
      if (historical_state == nullptr)
      {
        return JS_ThrowInternalError(ctx, "Failed to get state cache");
      }

      int64_t handle;
      if (JS_ToInt64(ctx, &handle, argv[0]) < 0)
      {
        return ccf::js::core::constants::Exception;
      }
      if (handle < 0)
      {
        return JS_ThrowRangeError(ctx, "Invalid handle: cannot be negative");
      }

      try
      {
        auto found = historical_state->drop_cached_states(handle);
        return JS_NewBool(ctx, found);
      }
      catch (const std::exception& exc)
      {
        return JS_ThrowInternalError(
          ctx, "Failed to drop cached states: %s", exc.what());
      }
    }

    static JSValue ccf_receipt_to_js(
      js::core::Context& jsctx, TxReceiptImplPtr receipt)
    {
      ccf::ReceiptPtr receipt_out_p = ccf::describe_receipt_v2(*receipt);
      auto& receipt_out = *receipt_out_p;
      auto js_receipt = jsctx.new_obj();
      JS_CHECK_EXC(js_receipt);

      std::string sig_b64;
      try
      {
        sig_b64 = crypto::b64_from_raw(receipt_out.signature);
      }
      catch (const std::exception& e)
      {
        return jsctx
          .new_internal_error(
            "Failed to convert signature to base64: %s", e.what())
          .take();
      }
      auto sig_string = jsctx.new_string(sig_b64);
      JS_CHECK_EXC(sig_string);
      JS_CHECK_SET(js_receipt.set("signature", std::move(sig_string)));

      auto js_cert = jsctx.new_string(receipt_out.cert.str());
      JS_CHECK_EXC(js_cert);
      JS_CHECK_SET(js_receipt.set("cert", std::move(js_cert)));

      auto js_node_id = jsctx.new_string(receipt_out.node_id.value());
      JS_CHECK_EXC(js_node_id);
      JS_CHECK_SET(js_receipt.set("node_id", std::move(js_node_id)));
      bool is_signature_transaction = receipt_out.is_signature_transaction();
      JS_CHECK_SET(js_receipt.set_bool(
        "is_signature_transaction", is_signature_transaction));

      if (!is_signature_transaction)
      {
        auto p_receipt =
          std::dynamic_pointer_cast<ccf::ProofReceipt>(receipt_out_p);
        auto leaf_components = jsctx.new_obj();
        JS_CHECK_EXC(leaf_components);

        const auto wsd_hex =
          ds::to_hex(p_receipt->leaf_components.write_set_digest.h);

        auto js_wsd = jsctx.new_string(wsd_hex);
        JS_CHECK_EXC(js_wsd);
        JS_CHECK_SET(
          leaf_components.set("write_set_digest", std::move(js_wsd)));

        auto js_commit_evidence =
          jsctx.new_string(p_receipt->leaf_components.commit_evidence);
        JS_CHECK_EXC(js_commit_evidence);
        JS_CHECK_SET(leaf_components.set(
          "commit_evidence", std::move(js_commit_evidence)));

        if (!p_receipt->leaf_components.claims_digest.empty())
        {
          const auto cd_hex =
            ds::to_hex(p_receipt->leaf_components.claims_digest.value().h);

          auto js_cd = jsctx.new_string(cd_hex);
          JS_CHECK_EXC(js_cd);
          JS_CHECK_SET(leaf_components.set("claims_digest", std::move(js_cd)));
        }
        JS_CHECK_SET(
          js_receipt.set("leaf_components", std::move(leaf_components)));

        auto proof = jsctx.new_array();
        JS_CHECK_EXC(proof);

        uint32_t i = 0;
        for (auto& element : p_receipt->proof)
        {
          auto js_element = jsctx.new_obj();
          JS_CHECK_EXC(js_element);

          auto is_left =
            element.direction == ccf::ProofReceipt::ProofStep::Left;
          const auto hash_hex = ds::to_hex(element.hash.h);

          auto js_hash = jsctx.new_string(hash_hex);
          JS_CHECK_EXC(js_hash);
          JS_CHECK_SET(
            js_element.set(is_left ? "left" : "right", std::move(js_hash)));
          JS_CHECK_SET(proof.set_at_index(i++, std::move(js_element)));
        }
        JS_CHECK_SET(js_receipt.set("proof", std::move(proof)));
      }
      else
      {
        auto sig_receipt =
          std::dynamic_pointer_cast<ccf::SignatureReceipt>(receipt_out_p);
        const auto signed_root = sig_receipt->signed_root;
        const auto root_hex = ds::to_hex(signed_root.h);
        auto js_root_hex = jsctx.new_string(root_hex);
        JS_CHECK_EXC(js_root_hex);
        JS_CHECK_SET(js_receipt.set("root_hex", std::move(js_root_hex)));
      }

      return js_receipt.take();
    }

  }

  void CcfHistoricalExtension::install(js::core::Context& ctx)
  {
    auto historical = JS_NewObjectClass(ctx, historical_class_id);

    JS_SetPropertyStr(
      ctx,
      historical,
      "getStateRange",
      JS_NewCFunction(ctx, js_historical_get_state_range, "getStateRange", 4));
    JS_SetPropertyStr(
      ctx,
      historical,
      "dropCachedStates",
      JS_NewCFunction(
        ctx, js_historical_drop_cached_states, "dropCachedStates", 1));

    auto ccf = ctx.get_or_create_global_property("ccf", ctx.new_obj());
    ccf.set("historical", std::move(historical));
  }

  JSValue CcfHistoricalExtension::create_historical_state_object(
    js::core::Context& ctx, ccf::historical::StatePtr state)
  {
    auto js_state = ctx.new_obj_class(historical_state_class_id);
    JS_CHECK_EXC(js_state);

    const auto transaction_id = state->transaction_id;
    auto transaction_id_s = ctx.new_string(transaction_id.to_str());
    JS_CHECK_EXC(transaction_id_s);
    JS_CHECK_SET(js_state.set("transactionId", std::move(transaction_id_s)));

    // NB: ccf_receipt_to_js returns a JSValue (unwrapped), due to its use of
    // macros. So we must rewrap it here, immediately after returning
    auto js_receipt = ctx.wrap(ccf_receipt_to_js(ctx, state->receipt));
    JS_CHECK_EXC(js_receipt);
    JS_CHECK_SET(js_state.set("receipt", std::move(js_receipt)));

    auto kv = ctx.new_obj_class(kv_historical_class_id);
    JS_CHECK_EXC(kv);
    JS_SetOpaque(kv.val, reinterpret_cast<void*>(transaction_id.seqno));
    JS_CHECK_SET(js_state.set("kv", std::move(kv)));

    try
    {
      // Create a tx which will be used to access this state
      auto tx = state->store->create_read_only_tx_ptr();

      // Extend lifetime of state and tx, by storing on this extension
      historical_handles[transaction_id.seqno] = {state, std::move(tx)};
    }
    catch (const std::exception& e)
    {
      return ctx
        .new_internal_error(
          "Failed to create read-only historical tx: %s", e.what())
        .take();
    }

    return js_state.take();
  }
}
