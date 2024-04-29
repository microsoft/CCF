// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/historical_queries_interface.h"

namespace ccf::js
{
  namespace
  {
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
      {
        return ccf::js::constants::Exception;
      }
      if (JS_ToInt64(ctx, &start_seqno, argv[1]) < 0)
      {
        return ccf::js::constants::Exception;
      }
      if (JS_ToInt64(ctx, &end_seqno, argv[2]) < 0)
      {
        return ccf::js::constants::Exception;
      }
      if (JS_ToInt64(ctx, &seconds_until_expiry, argv[3]) < 0)
      {
        return ccf::js::constants::Exception;
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
        return ccf::js::constants::Null;
      }

      js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

      auto states_array = jsctx.new_array();
      JS_CHECK_EXC(states_array);
      size_t i = 0;
      for (auto& state : states)
      {
        auto js_state = jsctx.wrap(jsctx.create_historical_state_object(state));
        JS_CHECK_SET(states_array.set_at_index(i++, std::move(js_state)));
      }

      return states_array.take();
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
      {
        return ccf::js::constants::Exception;
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

  }

  JSValue create_global_historical_object(
    ccf::historical::AbstractStateCache* historical_state, JSContext* ctx)
  {
    auto historical = JS_NewObjectClass(ctx, historical_class_id);

    JS_SetOpaque(historical, historical_state);
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

    return historical;
  }
}
