// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/js/extensions/ccf/historical.h"

#include "ccf/ds/hex.h"
#include "ccf/historical_queries_interface.h"
#include "ccf/js/core/context.h"
#include "js/checks.h"
#include "js/extensions/ccf/kv_helpers.h"
#include "kv/untyped_map.h"

namespace ccf::js::extensions
{
  struct HistoricalExtension::Impl
  {
    ccf::historical::AbstractStateCache* historical_state;

    struct HistoricalHandle
    {
      ccf::historical::StatePtr state;
      std::unique_ptr<ccf::kv::ReadOnlyTx> tx;
      std::unordered_map<std::string, ccf::kv::untyped::Map::ReadOnlyHandle*>
        kv_handles;
    };
    std::unordered_map<ccf::SeqNo, HistoricalHandle> historical_handles;

    Impl(ccf::historical::AbstractStateCache* hs) : historical_state(hs) {};
  };

  namespace
  {
    JSValue js_historical_get_state_range(
      JSContext* ctx,
      [[maybe_unused]] JSValueConst this_val,
      int argc,
      JSValueConst* argv)
    {
      if (argc != 4)
      {
        return JS_ThrowTypeError(
          ctx, "Passed %d arguments, but expected 4", argc);
      }

      js::core::Context& jsctx =
        *reinterpret_cast<js::core::Context*>(JS_GetContextOpaque(ctx));
      auto* extension = jsctx.get_extension<HistoricalExtension>();

      if (extension == nullptr)
      {
        return JS_ThrowInternalError(ctx, "Failed to get extension object");
      }

      auto* historical_state = extension->impl->historical_state;
      if (historical_state == nullptr)
      {
        return JS_ThrowInternalError(ctx, "Failed to get state cache");
      }

      int64_t handle = 0;
      int64_t start_seqno = 0;
      int64_t end_seqno = 0;
      int64_t seconds_until_expiry = 0;
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
        auto js_state = extension->create_historical_state_object(jsctx, state);
        JS_CHECK_SET(states_array.set_at_index(i++, std::move(js_state)));
      }

      return states_array.take();
    }

    JSValue js_historical_drop_cached_states(
      JSContext* ctx,
      [[maybe_unused]] JSValueConst this_val,
      int argc,
      JSValueConst* argv)
    {
      if (argc != 1)
      {
        return JS_ThrowTypeError(
          ctx, "Passed %d arguments, but expected 1", argc);
      }

      js::core::Context& jsctx =
        *reinterpret_cast<js::core::Context*>(JS_GetContextOpaque(ctx));
      auto* extension = jsctx.get_extension<HistoricalExtension>();

      if (extension == nullptr)
      {
        return JS_ThrowInternalError(ctx, "Failed to get extension object");
      }

      auto* historical_state = extension->impl->historical_state;
      if (historical_state == nullptr)
      {
        return JS_ThrowInternalError(ctx, "Failed to get state cache");
      }

      int64_t handle = 0;
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
        return JS_NewBool(ctx, static_cast<int>(found));
      }
      catch (const std::exception& exc)
      {
        return JS_ThrowInternalError(
          ctx, "Failed to drop cached states: %s", exc.what());
      }
    }

    JSValue ccf_receipt_to_js(
      js::core::Context& jsctx, TxReceiptImplPtr receipt)
    {
      ccf::ReceiptPtr receipt_out_p = ccf::describe_receipt_v2(*receipt);
      auto& receipt_out = *receipt_out_p;
      auto js_receipt = jsctx.new_obj();
      JS_CHECK_EXC(js_receipt);

      std::string sig_b64;
      try
      {
        sig_b64 = ccf::crypto::b64_from_raw(receipt_out.signature);
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

    kvhelpers::KVMap::ReadOnlyHandle* get_map_handle_historical(
      js::core::Context& jsctx, JSValueConst _this_val)
    {
      auto this_val = jsctx.duplicate_value(_this_val);
      auto map_name_val = this_val["_map_name"];
      auto map_name = jsctx.to_str(map_name_val);

      if (!map_name.has_value())
      {
        LOG_FAIL_FMT("No map name stored on handle");
        return nullptr;
      }

      const auto seqno = reinterpret_cast<ccf::SeqNo>(
        JS_GetOpaque(_this_val, kv_map_handle_class_id));

      // Handle to historical KV
      auto* extension = jsctx.get_extension<HistoricalExtension>();
      if (extension == nullptr)
      {
        LOG_FAIL_FMT("No historical extension available");
        return nullptr;
      }

      auto it = extension->impl->historical_handles.find(seqno);
      if (it == extension->impl->historical_handles.end())
      {
        LOG_FAIL_FMT(
          "Unable to retrieve any historical handles for state at {}", seqno);
        return nullptr;
      }

      auto& handles = it->second.kv_handles;
      auto hit = handles.find(map_name.value());
      if (hit == handles.end())
      {
        hit = handles.emplace_hint(hit, map_name.value(), nullptr);
      }

      if (hit->second == nullptr)
      {
        ccf::kv::ReadOnlyTx* tx = it->second.tx.get();
        if (tx == nullptr)
        {
          LOG_FAIL_FMT("Can't rehydrate MapHandle - no transaction");
          return nullptr;
        }

        hit->second = tx->ro<kvhelpers::KVMap>(map_name.value());
      }

      return hit->second;
    }

    int js_historical_kv_lookup(
      JSContext* ctx,
      JSPropertyDescriptor* desc,
      JSValueConst this_val,
      JSAtom property)
    {
      js::core::Context& jsctx =
        *reinterpret_cast<js::core::Context*>(JS_GetContextOpaque(ctx));
      const auto map_name = jsctx.to_str(property).value_or("");
      auto seqno = reinterpret_cast<ccf::SeqNo>(
        JS_GetOpaque(this_val, kv_historical_class_id));
      LOG_TRACE_FMT(
        "Looking for historical kv map '{}' at seqno {}", map_name, seqno);

      auto access_permission =
        ccf::js::check_kv_map_access(jsctx.access, map_name);
      std::string explanation =
        ccf::js::explain_kv_map_access(access_permission, jsctx.access);

      // If it's illegal, it stays illegal in historical lookup
      if (access_permission != KVAccessPermissions::ILLEGAL)
      {
        // But otherwise, ignore evaluated access permissions - all tables are
        // read-only in historical KV
        access_permission = KVAccessPermissions::READ_ONLY;
        explanation = "All tables are read-only during historical transaction.";
      }

      auto handle_val =
        kvhelpers::create_kv_map_handle<get_map_handle_historical, nullptr>(
          jsctx, map_name, access_permission, explanation);
      if (JS_IsException(handle_val) != 0)
      {
        return -1;
      }

      // Copy seqno from kv to handle
      JS_SetOpaque(handle_val, reinterpret_cast<void*>(seqno));

      desc->flags = 0;
      desc->value = handle_val;

      return 1;
    }
  }

  HistoricalExtension::HistoricalExtension(
    ccf::historical::AbstractStateCache* hs)
  {
    impl = std::make_unique<HistoricalExtension::Impl>(hs);
  }

  HistoricalExtension::~HistoricalExtension() = default;

  void HistoricalExtension::install(js::core::Context& ctx)
  {
    auto historical = ctx.new_obj();

    JS_CHECK_OR_THROW(historical.set(
      "getStateRange",
      ctx.new_c_function(js_historical_get_state_range, "getStateRange", 4)));
    JS_CHECK_OR_THROW(historical.set(
      "dropCachedStates",
      ctx.new_c_function(
        js_historical_drop_cached_states, "dropCachedStates", 1)));

    auto ccf = ctx.get_or_create_global_property("ccf", ctx.new_obj());
    JS_CHECK_OR_THROW(ccf.set("historical", std::move(historical)));
  }

  js::core::JSWrappedValue HistoricalExtension::create_historical_state_object(
    js::core::Context& ctx, ccf::historical::StatePtr state) const
  {
#define WRAPPED_CHECK_EXC(val) \
  do \
  { \
    if ((val).is_exception()) \
    { \
      return val; \
    } \
  } while (0)

#define WRAPPED_CHECK_SET(val) \
  do \
  { \
    if ((val) != 1) \
    { \
      return ctx.wrap(ccf::js::core::constants::Exception); \
    } \
  } while (0)

    auto js_state = ctx.new_obj_class(historical_state_class_id);
    WRAPPED_CHECK_EXC(js_state);

    const auto transaction_id = state->transaction_id;
    auto transaction_id_s = ctx.new_string(transaction_id.to_str());
    WRAPPED_CHECK_EXC(transaction_id_s);
    WRAPPED_CHECK_SET(
      js_state.set("transactionId", std::move(transaction_id_s)));

    // NB: ccf_receipt_to_js returns a JSValue (unwrapped), due to its use of
    // macros. So we must rewrap it here, immediately after returning
    auto js_receipt = ctx.wrap(ccf_receipt_to_js(ctx, state->receipt));
    WRAPPED_CHECK_EXC(js_receipt);
    WRAPPED_CHECK_SET(js_state.set("receipt", std::move(js_receipt)));

    auto kv = ctx.new_obj_class(kv_historical_class_id);
    WRAPPED_CHECK_EXC(kv);
    JS_SetOpaque(kv.val, reinterpret_cast<void*>(transaction_id.seqno));
    WRAPPED_CHECK_SET(js_state.set("kv", std::move(kv)));

    try
    {
      // Create a tx which will be used to access this state
      auto tx = state->store->create_read_only_tx_ptr();

      // Extend lifetime of state and tx, by storing on this extension
      impl->historical_handles[transaction_id.seqno] = {
        state, std::move(tx), {}};
    }
    catch (const std::exception& e)
    {
      return ctx.new_internal_error(
        "Failed to create read-only historical tx: %s", e.what());
    }

    return js_state;

#undef WRAPPED_CHECK_EXC
#undef WRAPPED_CHECK_SET
  }
}

namespace ccf::js
{
  JSClassExoticMethods kv_historical_exotic_methods = {
    .get_own_property = extensions::js_historical_kv_lookup,
    .get_own_property_names = {},
    .delete_property = {},
    .define_own_property = {},
    .has_property = {},
    .get_property = {},
    .set_property = {}};
  JSClassDef kv_historical_class_def = {
    .class_name = "Read-only Historical KV Tables",
    .finalizer = {},
    .gc_mark = {},
    .call = {},
    .exotic = &kv_historical_exotic_methods};
}
