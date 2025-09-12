// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/js/extensions/ccf/consensus.h"

#include "ccf/base_endpoint_registry.h"
#include "ccf/js/core/context.h"
#include "js/checks.h"

#include <quickjs/quickjs.h>

namespace ccf::js::extensions
{
  namespace
  {
    JSValue js_consensus_get_last_committed_txid(
      JSContext* ctx,
      [[maybe_unused]] JSValueConst this_val,
      int argc,
      [[maybe_unused]] JSValueConst* argv)
    {
      if (argc != 0)
      {
        return JS_ThrowTypeError(
          ctx, "Passed %d arguments, but expected 0", argc);
      }

      js::core::Context& jsctx =
        *reinterpret_cast<js::core::Context*>(JS_GetContextOpaque(ctx));

      auto* extension = jsctx.get_extension<ConsensusExtension>();
      if (extension == nullptr)
      {
        return JS_ThrowInternalError(ctx, "Failed to get extension object");
      }

      auto* endpoint_registry = extension->endpoint_registry;
      if (endpoint_registry == nullptr)
      {
        return JS_ThrowInternalError(
          ctx, "Failed to get endpoint registry object");
      }

      ccf::View view = 0;
      ccf::SeqNo seqno = 0;
      auto result = endpoint_registry->get_last_committed_txid_v1(view, seqno);
      if (result != ccf::ApiResult::OK)
      {
        return JS_ThrowInternalError(
          ctx,
          "Failed to get last committed txid: %s",
          ccf::api_result_to_str(result));
      }

      auto obj = jsctx.new_obj();
      JS_CHECK_EXC(obj);
      JS_CHECK_SET(obj.set_int64("view", view));
      JS_CHECK_SET(obj.set_int64("seqno", seqno));
      return obj.take();
    }

    JSValue js_consensus_get_status_for_txid(
      JSContext* ctx,
      [[maybe_unused]] JSValueConst this_val,
      int argc,
      JSValueConst* argv)
    {
      if (argc != 2)
      {
        return JS_ThrowTypeError(
          ctx, "Passed %d arguments, but expected 2", argc);
      }

      int64_t view = 0;
      int64_t seqno = 0;
      if (JS_ToInt64(ctx, &view, argv[0]) < 0)
      {
        return ccf::js::core::constants::Exception;
      }
      if (JS_ToInt64(ctx, &seqno, argv[1]) < 0)
      {
        return ccf::js::core::constants::Exception;
      }
      if (view < 0 || seqno < 0)
      {
        return JS_ThrowRangeError(
          ctx, "Invalid view or seqno: cannot be negative");
      }

      js::core::Context& jsctx =
        *reinterpret_cast<js::core::Context*>(JS_GetContextOpaque(ctx));

      auto* extension = jsctx.get_extension<ConsensusExtension>();
      if (extension == nullptr)
      {
        return JS_ThrowInternalError(ctx, "Failed to get extension object");
      }

      auto* endpoint_registry = extension->endpoint_registry;
      if (endpoint_registry == nullptr)
      {
        return JS_ThrowInternalError(
          ctx, "Failed to get endpoint registry object");
      }

      ccf::TxStatus status = ccf::TxStatus::Unknown;
      auto result =
        endpoint_registry->get_status_for_txid_v1(view, seqno, status);
      if (result != ccf::ApiResult::OK)
      {
        return JS_ThrowInternalError(
          ctx,
          "Failed to get status for txid: %s",
          ccf::api_result_to_str(result));
      }
      const auto* status_str = ccf::tx_status_to_str(status);
      return JS_NewString(ctx, status_str);
    }

    JSValue js_consensus_get_view_for_seqno(
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

      int64_t seqno = 0;
      if (JS_ToInt64(ctx, &seqno, argv[0]) < 0)
      {
        return ccf::js::core::constants::Exception;
      }
      if (seqno < 0)
      {
        return JS_ThrowRangeError(ctx, "Invalid seqno: cannot be negative");
      }

      js::core::Context& jsctx =
        *reinterpret_cast<js::core::Context*>(JS_GetContextOpaque(ctx));

      auto* extension = jsctx.get_extension<ConsensusExtension>();
      if (extension == nullptr)
      {
        return JS_ThrowInternalError(ctx, "Failed to get extension object");
      }

      auto* endpoint_registry = extension->endpoint_registry;
      if (endpoint_registry == nullptr)
      {
        return JS_ThrowInternalError(
          ctx, "Failed to get endpoint registry object");
      }
      ccf::View view = 0;
      auto result = endpoint_registry->get_view_for_seqno_v1(seqno, view);
      if (result == ccf::ApiResult::NotFound)
      {
        return ccf::js::core::constants::Null;
      }
      if (result != ccf::ApiResult::OK)
      {
        return JS_ThrowInternalError(
          ctx,
          "Failed to get view for seqno: %s",
          ccf::api_result_to_str(result));
      }

      return JS_NewFloat64(ctx, view);
    }
  }

  void ConsensusExtension::install(js::core::Context& ctx)
  {
    auto consensus = ctx.new_obj();

    consensus.set(
      "getLastCommittedTxId",
      ctx.new_c_function(
        js_consensus_get_last_committed_txid, "getLastCommittedTxId", 0));
    consensus.set(
      "getStatusForTxId",
      ctx.new_c_function(
        js_consensus_get_status_for_txid, "getStatusForTxId", 2));
    consensus.set(
      "getViewForSeqno",
      ctx.new_c_function(
        js_consensus_get_view_for_seqno, "getViewForSeqno", 1));

    auto ccf = ctx.get_or_create_global_property("ccf", ctx.new_obj());
    ccf.set("consensus", std::move(consensus));
  }
}
