// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/entropy.h"
#include "js/ffi_plugins.h"
#include "js/globals/console.h"

namespace ccf::js
{
  namespace core
  {
    class Context;
  }

  namespace globals
  {
    namespace details
    {
      static JSValue js_random_impl(
        JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
      {
        crypto::EntropyPtr entropy = crypto::get_entropy();

        // Generate a random 64 bit unsigned int, and transform that to a double
        // between 0 and 1. Note this is non-uniform, and not cryptographically
        // sound.
        union
        {
          double d;
          uint64_t u;
        } u;
        try
        {
          u.u = entropy->random64();
        }
        catch (const std::exception& e)
        {
          return JS_ThrowInternalError(
            ctx, "Failed to generate random number: %s", e.what());
        }
        // From QuickJS - set exponent to 1, and shift random bytes to
        // fractional part, producing 1.0 <= u.d < 2
        u.u = ((uint64_t)1023 << 52) | (u.u >> 12);

        return JS_NewFloat64(ctx, u.d - 1.0);
      }

      static inline void override_builtin_funcs(js::core::Context& ctx)
      {
        // Overriding built-in Math.random
        auto math_val = ctx.get_global_property("Math");
        math_val.set("random", ctx.new_c_function(js_random_impl, "random", 0));
      }
    }

    void init_globals(js::core::Context& ctx)
    {
      // Always available, no other dependencies
      populate_global_console(ctx);

      details::override_builtin_funcs(ctx);

      for (auto& plugin : ffi_plugins)
      {
        LOG_DEBUG_FMT("Extending JS context with plugin {}", plugin.name);
        plugin.extend(ctx);
      }
    }
  }
}