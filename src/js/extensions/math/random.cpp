// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "js/extensions/math/random.h"

#include "ccf/crypto/entropy.h"
#include "js/core/context.h"

#include <quickjs/quickjs.h>

namespace ccf::js::extensions
{
  namespace
  {
    JSValue js_random_impl(
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
  }

  void MathRandomExtension::install(js::core::Context& ctx)
  {
    // Overriding built-in Math.random
    auto math_val = ctx.get_global_property("Math");
    math_val.set("random", ctx.new_c_function(js_random_impl, "random", 0));
  }
}
