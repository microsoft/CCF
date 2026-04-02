// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "js/extensions/ccf/node.h"

#include "ccf/js/core/context.h"
#include "js/checks.h"
#include "node/rpc/gov_logging.h"
#include "service/tables/shards.h"

#include <quickjs/quickjs.h>

namespace ccf::js::extensions
{
  namespace
  {
    JSValue js_node_trigger_ledger_rekey(
      JSContext* ctx,
      [[maybe_unused]] JSValueConst this_val,
      int argc,
      [[maybe_unused]] JSValueConst* argv)
    {
      js::core::Context& jsctx =
        *reinterpret_cast<js::core::Context*>(JS_GetContextOpaque(ctx));
      if (argc != 0)
      {
        return JS_ThrowTypeError(
          ctx, "Passed %d arguments but expected none", argc);
      }

      auto* extension = jsctx.get_extension<NodeExtension>();
      if (extension == nullptr)
      {
        return JS_ThrowInternalError(ctx, "Failed to get extension object");
      }

      auto* gov_effects = extension->gov_effects;
      if (gov_effects == nullptr)
      {
        return JS_ThrowInternalError(
          ctx, "Failed to get governance effects object");
      }

      auto* tx_ptr = extension->tx;
      if (tx_ptr == nullptr)
      {
        return JS_ThrowInternalError(ctx, "Failed to get tx object");
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

      return ccf::js::core::constants::Undefined;
    }

    JSValue js_node_transition_service_to_open(
      JSContext* ctx,
      [[maybe_unused]] JSValueConst this_val,
      int argc,
      [[maybe_unused]] JSValueConst* argv)
    {
      js::core::Context& jsctx =
        *reinterpret_cast<js::core::Context*>(JS_GetContextOpaque(ctx));

      if (argc != 2)
      {
        return JS_ThrowTypeError(
          ctx, "Passed %d arguments but expected two", argc);
      }

      auto* extension = jsctx.get_extension<NodeExtension>();
      if (extension == nullptr)
      {
        return JS_ThrowInternalError(ctx, "Failed to get extension object");
      }

      auto* gov_effects = extension->gov_effects;
      if (gov_effects == nullptr)
      {
        return JS_ThrowInternalError(
          ctx, "Failed to get governance effects object");
      }

      auto* tx_ptr = extension->tx;
      if (tx_ptr == nullptr)
      {
        return JS_ThrowInternalError(ctx, "Failed to get tx object");
      }

      try
      {
        AbstractGovernanceEffects::ServiceIdentities identities;

        size_t prev_bytes_sz = 0;
        uint8_t* prev_bytes = nullptr;
        if (JS_IsUndefined(argv[0]) == 0)
        {
          prev_bytes = JS_GetArrayBuffer(ctx, &prev_bytes_sz, argv[0]);
          if (prev_bytes == nullptr)
          {
            return JS_ThrowTypeError(
              ctx, "Previous service identity argument is not an array buffer");
          }
          identities.previous = ccf::crypto::Pem(prev_bytes, prev_bytes_sz);
          GOV_DEBUG_FMT(
            "previous service identity: {}", identities.previous->str());
        }

        if (JS_IsUndefined(argv[1]) != 0)
        {
          return JS_ThrowInternalError(
            ctx, "Proposal requires a service identity");
        }

        size_t next_bytes_sz = 0;
        uint8_t* next_bytes = JS_GetArrayBuffer(ctx, &next_bytes_sz, argv[1]);

        if (next_bytes == nullptr)
        {
          return JS_ThrowTypeError(
            ctx, "Next service identity argument is not an array buffer");
        }

        identities.next = ccf::crypto::Pem(next_bytes, next_bytes_sz);
        GOV_DEBUG_FMT("next service identity: {}", identities.next.str());

        gov_effects->transition_service_to_open(*tx_ptr, identities);
      }
      catch (const std::exception& e)
      {
        GOV_FAIL_FMT("Unable to open service: {}", e.what());
        return JS_ThrowInternalError(
          ctx, "Unable to open service: %s", e.what());
      }

      return ccf::js::core::constants::Undefined;
    }

    JSValue js_node_trigger_recovery_shares_refresh(
      JSContext* ctx,
      [[maybe_unused]] JSValueConst this_val,
      int argc,
      [[maybe_unused]] JSValueConst* argv)
    {
      js::core::Context& jsctx =
        *reinterpret_cast<js::core::Context*>(JS_GetContextOpaque(ctx));

      if (argc != 0)
      {
        return JS_ThrowTypeError(
          ctx, "Passed %d arguments but expected none", argc);
      }

      auto* extension = jsctx.get_extension<NodeExtension>();
      if (extension == nullptr)
      {
        return JS_ThrowInternalError(ctx, "Failed to get extension object");
      }

      auto* gov_effects = extension->gov_effects;
      if (gov_effects == nullptr)
      {
        return JS_ThrowInternalError(
          ctx, "Failed to get governance effects object");
      }

      auto* tx_ptr = extension->tx;
      if (tx_ptr == nullptr)
      {
        return JS_ThrowInternalError(ctx, "Failed to get tx object");
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

      return ccf::js::core::constants::Undefined;
    }

    JSValue js_trigger_ledger_chunk(
      JSContext* ctx,
      [[maybe_unused]] JSValueConst this_val,
      [[maybe_unused]] int argc,
      [[maybe_unused]] JSValueConst* argv)
    {
      js::core::Context& jsctx =
        *reinterpret_cast<js::core::Context*>(JS_GetContextOpaque(ctx));

      auto* extension = jsctx.get_extension<NodeExtension>();
      if (extension == nullptr)
      {
        return JS_ThrowInternalError(ctx, "Failed to get extension object");
      }

      auto* gov_effects = extension->gov_effects;
      if (gov_effects == nullptr)
      {
        return JS_ThrowInternalError(
          ctx, "Failed to get governance effects object");
      }

      auto* tx_ptr = extension->tx;
      if (tx_ptr == nullptr)
      {
        return JS_ThrowInternalError(ctx, "Failed to get tx object");
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

      return ccf::js::core::constants::Undefined;
    }

    JSValue js_trigger_snapshot(
      JSContext* ctx,
      [[maybe_unused]] JSValueConst this_val,
      [[maybe_unused]] int argc,
      [[maybe_unused]] JSValueConst* argv)
    {
      js::core::Context& jsctx =
        *reinterpret_cast<js::core::Context*>(JS_GetContextOpaque(ctx));

      auto* extension = jsctx.get_extension<NodeExtension>();
      if (extension == nullptr)
      {
        return JS_ThrowInternalError(ctx, "Failed to get extension object");
      }

      auto* gov_effects = extension->gov_effects;
      if (gov_effects == nullptr)
      {
        return JS_ThrowInternalError(
          ctx, "Failed to get governance effects object");
      }

      auto* tx_ptr = extension->tx;
      if (tx_ptr == nullptr)
      {
        return JS_ThrowInternalError(ctx, "Failed to get tx object");
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

      return ccf::js::core::constants::Undefined;
    }

    JSValue js_shuffle_sealed_shares(
      JSContext* ctx,
      [[maybe_unused]] JSValueConst this_val,
      [[maybe_unused]] int argc,
      [[maybe_unused]] JSValueConst* argv)
    {
      js::core::Context& jsctx =
        *reinterpret_cast<js::core::Context*>(JS_GetContextOpaque(ctx));

      auto* extension = jsctx.get_extension<NodeExtension>();
      if (extension == nullptr)
      {
        return JS_ThrowInternalError(ctx, "Failed to get extension object");
      }

      auto* gov_effects = extension->gov_effects;
      if (gov_effects == nullptr)
      {
        return JS_ThrowInternalError(
          ctx, "Failed to get governance effects object");
      }

      auto* tx_ptr = extension->tx;
      if (tx_ptr == nullptr)
      {
        return JS_ThrowInternalError(ctx, "Failed to get tx object");
      }

      try
      {
        gov_effects->shuffle_sealed_shares(*tx_ptr);
      }
      catch (const std::exception& e)
      {
        GOV_FAIL_FMT("Unable to shuffle sealed shares: {}", e.what());
        return JS_ThrowInternalError(
          ctx, "Unable to shuffle sealed shares: %s", e.what());
      }

      return ccf::js::core::constants::Undefined;
    }

    JSValue js_node_seal_shard(
      JSContext* ctx,
      [[maybe_unused]] JSValueConst this_val,
      int argc,
      [[maybe_unused]] JSValueConst* argv)
    {
      js::core::Context& jsctx =
        *reinterpret_cast<js::core::Context*>(JS_GetContextOpaque(ctx));
      if (argc != 0)
      {
        return JS_ThrowTypeError(
          ctx, "Passed %d arguments but expected none", argc);
      }

      auto* extension = jsctx.get_extension<NodeExtension>();
      if (extension == nullptr)
      {
        return JS_ThrowInternalError(ctx, "Failed to get extension object");
      }

      auto* gov_effects = extension->gov_effects;
      if (gov_effects == nullptr)
      {
        return JS_ThrowInternalError(
          ctx, "Failed to get governance effects object");
      }

      auto* tx_ptr = extension->tx;
      if (tx_ptr == nullptr)
      {
        return JS_ThrowInternalError(ctx, "Failed to get tx object");
      }

      try
      {
        bool result = gov_effects->seal_shard(*tx_ptr);
        if (!result)
        {
          return JS_ThrowInternalError(ctx, "Could not seal shard");
        }
      }
      catch (const std::exception& e)
      {
        GOV_FAIL_FMT("Unable to seal shard: {}", e.what());
        return JS_ThrowInternalError(
          ctx, "Unable to seal shard: %s", e.what());
      }

      return ccf::js::core::constants::Undefined;
    }

    JSValue js_node_set_shard_policy(
      JSContext* ctx,
      [[maybe_unused]] JSValueConst this_val,
      int argc,
      [[maybe_unused]] JSValueConst* argv)
    {
      js::core::Context& jsctx =
        *reinterpret_cast<js::core::Context*>(JS_GetContextOpaque(ctx));
      if (argc != 1)
      {
        return JS_ThrowTypeError(
          ctx, "Passed %d arguments but expected one", argc);
      }

      auto* extension = jsctx.get_extension<NodeExtension>();
      if (extension == nullptr)
      {
        return JS_ThrowInternalError(ctx, "Failed to get extension object");
      }

      auto* gov_effects = extension->gov_effects;
      if (gov_effects == nullptr)
      {
        return JS_ThrowInternalError(
          ctx, "Failed to get governance effects object");
      }

      auto* tx_ptr = extension->tx;
      if (tx_ptr == nullptr)
      {
        return JS_ThrowInternalError(ctx, "Failed to get tx object");
      }

      try
      {
        size_t buf_sz = 0;
        uint8_t* buf = JS_GetArrayBuffer(ctx, &buf_sz, argv[0]);
        if (buf == nullptr)
        {
          return JS_ThrowTypeError(
            ctx, "Shard policy argument is not an array buffer");
        }

        auto policy_json =
          nlohmann::json::parse(buf, buf + buf_sz);
        auto policy = policy_json.get<ccf::ShardPolicyInfo>();
        gov_effects->set_shard_policy(*tx_ptr, policy);
      }
      catch (const std::exception& e)
      {
        GOV_FAIL_FMT("Unable to set shard policy: {}", e.what());
        return JS_ThrowInternalError(
          ctx, "Unable to set shard policy: %s", e.what());
      }

      return ccf::js::core::constants::Undefined;
    }
  }

  void NodeExtension::install(js::core::Context& ctx)
  {
    auto node = ctx.new_obj();

    JS_CHECK_OR_THROW(node.set(
      "triggerLedgerRekey",
      ctx.new_c_function(
        js_node_trigger_ledger_rekey, "triggerLedgerRekey", 0)));
    JS_CHECK_OR_THROW(node.set(
      "transitionServiceToOpen",
      ctx.new_c_function(
        js_node_transition_service_to_open, "transitionServiceToOpen", 2)));
    JS_CHECK_OR_THROW(node.set(
      "triggerRecoverySharesRefresh",
      ctx.new_c_function(
        js_node_trigger_recovery_shares_refresh,
        "triggerRecoverySharesRefresh",
        0)));
    JS_CHECK_OR_THROW(node.set(
      "triggerLedgerChunk",
      ctx.new_c_function(js_trigger_ledger_chunk, "triggerLedgerChunk", 0)));
    JS_CHECK_OR_THROW(node.set(
      "triggerSnapshot",
      ctx.new_c_function(js_trigger_snapshot, "triggerSnapshot", 0)));
    JS_CHECK_OR_THROW(node.set(
      "shuffleSealedShares",
      ctx.new_c_function(js_shuffle_sealed_shares, "shuffleSealedShares", 0)));
    JS_CHECK_OR_THROW(node.set(
      "sealShard",
      ctx.new_c_function(js_node_seal_shard, "sealShard", 0)));
    JS_CHECK_OR_THROW(node.set(
      "setShardPolicy",
      ctx.new_c_function(js_node_set_shard_policy, "setShardPolicy", 1)));

    auto ccf = ctx.get_or_create_global_property("ccf", ctx.new_obj());
    JS_CHECK_OR_THROW(ccf.set("node", std::move(node)));
  }
}