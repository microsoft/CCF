// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/js/extensions/math/random.h"

#include "ccf/crypto/entropy.h"
#include "ccf/js/core/context.h"

#include <quickjs/quickjs.h>

namespace ccf::js::extensions
{
  namespace
  {
    constexpr uint64_t exponent_mask = 1023;
    constexpr uint64_t exponent_shift = 52;
    constexpr uint64_t mantissa_shift = 12;

    JSValue js_random_impl(
      JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
    {
      (void)this_val;
      (void)argc;
      (void)argv;
      ccf::crypto::EntropyPtr entropy = ccf::crypto::get_entropy();

      // Generate a random 64 bit unsigned int, and transform that to a double
      // between 0 and 1. Note this is non-uniform, and not cryptographically
      // sound.
      union
      {
        double double_value = 0;
        uint64_t uint_value;
      } value;
      try
      {
        value.uint_value = entropy->random64();
      }
      catch (const std::exception& e)
      {
        return JS_ThrowInternalError(
          ctx, "Failed to generate random number: %s", e.what());
      }
      // From QuickJS - set exponent to 1, and shift random bytes to
      // fractional part, producing 1.0 <= u.d < 2
      value.uint_value = (exponent_mask << exponent_shift) |
        (value.uint_value >> mantissa_shift);

      return JS_NewFloat64(ctx, value.double_value - 1.0);
    }
  }

  void MathRandomExtension::install(js::core::Context& ctx)
  {
    // Overriding built-in Math.random
    auto math_val = ctx.get_global_property("Math");
    math_val.set("random", ctx.new_c_function(js_random_impl, "random", 0));
  }
}
