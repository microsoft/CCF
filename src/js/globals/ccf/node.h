// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "js/context.h"
#include "js/global_class_ids.h"
#include "node/rpc/gov_effects_interface.h"
#include "node/rpc/gov_logging.h"

#include <quickjs/quickjs.h>

namespace ccf::js
{
  namespace
  {
    JSValue js_node_trigger_ledger_rekey(
      JSContext* ctx,
      JSValueConst this_val,
      int argc,
      [[maybe_unused]] JSValueConst* argv)
    {
      js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);
      if (argc != 0)
      {
        return JS_ThrowTypeError(
          ctx, "Passed %d arguments but expected none", argc);
      }

      auto gov_effects = static_cast<ccf::AbstractGovernanceEffects*>(
        JS_GetOpaque(this_val, node_class_id));

      auto tx_ptr = jsctx.globals.tx;

      if (tx_ptr == nullptr)
      {
        return JS_ThrowInternalError(
          ctx, "No transaction available to rekey ledger");
      }

      try
      {
        bool result = gov_effects->rekey_ledger(*tx_ptr);
        if (!result)
        {
          return JS_ThrowInternalError(ctx, "Could not rekey ledger");
        }
      }
      catch (const std::exception& e)
      {
        GOV_FAIL_FMT("Failed to rekey ledger: {}", e.what());
        return JS_ThrowInternalError(
          ctx, "Failed to rekey ledger: %s", e.what());
      }

      return ccf::js::constants::Undefined;
    }

    JSValue js_node_transition_service_to_open(
      JSContext* ctx,
      JSValueConst this_val,
      int argc,
      [[maybe_unused]] JSValueConst* argv)
    {
      js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

      if (argc != 2)
      {
        return JS_ThrowTypeError(
          ctx, "Passed %d arguments but expected two", argc);
      }

      auto gov_effects = static_cast<ccf::AbstractGovernanceEffects*>(
        JS_GetOpaque(this_val, node_class_id));

      if (gov_effects == nullptr)
      {
        return JS_ThrowInternalError(ctx, "Node state is not set");
      }

      auto tx_ptr = jsctx.globals.tx;

      if (tx_ptr == nullptr)
      {
        return JS_ThrowInternalError(
          ctx, "No transaction available to open service");
      }

      try
      {
        AbstractGovernanceEffects::ServiceIdentities identities;

        size_t prev_bytes_sz = 0;
        uint8_t* prev_bytes = nullptr;
        if (!JS_IsUndefined(argv[0]))
        {
          prev_bytes = JS_GetArrayBuffer(ctx, &prev_bytes_sz, argv[0]);
          if (!prev_bytes)
          {
            return JS_ThrowTypeError(
              ctx, "Previous service identity argument is not an array buffer");
          }
          identities.previous = crypto::Pem(prev_bytes, prev_bytes_sz);
          GOV_DEBUG_FMT(
            "previous service identity: {}", identities.previous->str());
        }

        if (JS_IsUndefined(argv[1]))
        {
          return JS_ThrowInternalError(
            ctx, "Proposal requires a service identity");
        }

        size_t next_bytes_sz = 0;
        uint8_t* next_bytes = JS_GetArrayBuffer(ctx, &next_bytes_sz, argv[1]);

        if (!next_bytes)
        {
          return JS_ThrowTypeError(
            ctx, "Next service identity argument is not an array buffer");
        }

        identities.next = crypto::Pem(next_bytes, next_bytes_sz);
        GOV_DEBUG_FMT("next service identity: {}", identities.next.str());

        gov_effects->transition_service_to_open(*tx_ptr, identities);
      }
      catch (const std::exception& e)
      {
        GOV_FAIL_FMT("Unable to open service: {}", e.what());
        return JS_ThrowInternalError(
          ctx, "Unable to open service: %s", e.what());
      }

      return ccf::js::constants::Undefined;
    }

    JSValue js_node_trigger_recovery_shares_refresh(
      JSContext* ctx,
      JSValueConst this_val,
      int argc,
      [[maybe_unused]] JSValueConst* argv)
    {
      js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

      if (argc != 0)
      {
        return JS_ThrowTypeError(
          ctx, "Passed %d arguments but expected none", argc);
      }

      auto gov_effects = static_cast<ccf::AbstractGovernanceEffects*>(
        JS_GetOpaque(this_val, node_class_id));
      auto tx_ptr = jsctx.globals.tx;

      if (tx_ptr == nullptr)
      {
        return JS_ThrowInternalError(
          ctx, "No transaction available to open service");
      }

      try
      {
        gov_effects->trigger_recovery_shares_refresh(*tx_ptr);
      }
      catch (const std::exception& e)
      {
        GOV_FAIL_FMT("Unable to trigger recovery shares refresh: {}", e.what());
        return JS_ThrowInternalError(
          ctx, "Unable to trigger recovery shares refresh: %s", e.what());
      }

      return ccf::js::constants::Undefined;
    }

    JSValue js_trigger_ledger_chunk(
      JSContext* ctx,
      JSValueConst this_val,
      [[maybe_unused]] int argc,
      [[maybe_unused]] JSValueConst* argv)
    {
      js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

      auto gov_effects = static_cast<ccf::AbstractGovernanceEffects*>(
        JS_GetOpaque(this_val, node_class_id));
      auto tx_ptr = jsctx.globals.tx;

      if (tx_ptr == nullptr)
      {
        return JS_ThrowInternalError(ctx, "No transaction available");
      }

      try
      {
        gov_effects->trigger_ledger_chunk(*tx_ptr);
      }
      catch (const std::exception& e)
      {
        GOV_FAIL_FMT("Unable to force ledger chunk: {}", e.what());
        return JS_ThrowInternalError(
          ctx, "Unable to force ledger chunk: %s", e.what());
      }

      return ccf::js::constants::Undefined;
    }

    JSValue js_trigger_snapshot(
      JSContext* ctx,
      JSValueConst this_val,
      [[maybe_unused]] int argc,
      [[maybe_unused]] JSValueConst* argv)
    {
      js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

      auto gov_effects = static_cast<ccf::AbstractGovernanceEffects*>(
        JS_GetOpaque(this_val, node_class_id));
      auto tx_ptr = jsctx.globals.tx;

      if (tx_ptr == nullptr)
      {
        return JS_ThrowInternalError(ctx, "No transaction available");
      }

      try
      {
        gov_effects->trigger_snapshot(*tx_ptr);
      }
      catch (const std::exception& e)
      {
        GOV_FAIL_FMT("Unable to request snapshot: {}", e.what());
        return JS_ThrowInternalError(
          ctx, "Unable to request snapshot: %s", e.what());
      }

      return ccf::js::constants::Undefined;
    }

    JSValue js_trigger_acme_refresh(
      JSContext* ctx,
      JSValueConst this_val,
      [[maybe_unused]] int argc,
      [[maybe_unused]] JSValueConst* argv)
    {
      js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

      auto gov_effects = static_cast<ccf::AbstractGovernanceEffects*>(
        JS_GetOpaque(this_val, node_class_id));
      auto tx_ptr = jsctx.globals.tx;

      if (tx_ptr == nullptr)
      {
        return JS_ThrowInternalError(ctx, "No transaction available");
      }

      try
      {
        std::optional<std::vector<std::string>> opt_interfaces = std::nullopt;

        if (argc > 0)
        {
          std::vector<std::string> interfaces;
          JSValue r = jsctx.get_string_array(argv[0], interfaces);

          if (!JS_IsUndefined(r))
          {
            return r;
          }

          opt_interfaces = interfaces;
        }

        gov_effects->trigger_acme_refresh(*tx_ptr, opt_interfaces);
      }
      catch (const std::exception& e)
      {
        GOV_FAIL_FMT("Unable to request snapshot: {}", e.what());
        return JS_ThrowInternalError(
          ctx, "Unable to request snapshot: %s", e.what());
      }

      return ccf::js::constants::Undefined;
    }
  }

  JSValue create_global_node_object(
    ccf::AbstractGovernanceEffects* gov_effects, JSContext* ctx)
  {
    auto node = JS_NewObjectClass(ctx, node_class_id);
    JS_SetOpaque(node, gov_effects);
    JS_SetPropertyStr(
      ctx,
      node,
      "triggerLedgerRekey",
      JS_NewCFunction(
        ctx, js_node_trigger_ledger_rekey, "triggerLedgerRekey", 0));
    JS_SetPropertyStr(
      ctx,
      node,
      "transitionServiceToOpen",
      JS_NewCFunction(
        ctx, js_node_transition_service_to_open, "transitionServiceToOpen", 2));
    JS_SetPropertyStr(
      ctx,
      node,
      "triggerRecoverySharesRefresh",
      JS_NewCFunction(
        ctx,
        js_node_trigger_recovery_shares_refresh,
        "triggerRecoverySharesRefresh",
        0));
    JS_SetPropertyStr(
      ctx,
      node,
      "triggerLedgerChunk",
      JS_NewCFunction(ctx, js_trigger_ledger_chunk, "triggerLedgerChunk", 0));
    JS_SetPropertyStr(
      ctx,
      node,
      "triggerSnapshot",
      JS_NewCFunction(ctx, js_trigger_snapshot, "triggerSnapshot", 0));
    JS_SetPropertyStr(
      ctx,
      node,
      "triggerACMERefresh",
      JS_NewCFunction(ctx, js_trigger_acme_refresh, "triggerACMERefresh", 0));

    return node;
  }
}
