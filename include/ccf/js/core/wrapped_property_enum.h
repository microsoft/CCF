// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/js/core/context.h"
#include "ccf/js/core/wrapped_value.h"

#include <quickjs/quickjs.h>

namespace ccf::js::core
{
  class JSWrappedPropertyEnum
  {
  public:
    JSWrappedPropertyEnum(JSContext* ctx_, const JSWrappedValue& value) :
      ctx(ctx_)
    {
      if (!value.is_obj())
      {
        throw std::logic_error(
          fmt::format("object value required for property enum"));
      }

      if (
        JS_GetOwnPropertyNames(
          ctx,
          &prop_enum,
          &prop_count,
          value.val,
          JS_GPN_STRING_MASK | JS_GPN_ENUM_ONLY) == -1)
      {
        throw std::logic_error(
          fmt::format("Could not extract property names of enum"));
      }
    }

    ~JSWrappedPropertyEnum()
    {
      for (uint32_t i = 0; i < prop_count; i++)
      {
        JS_FreeAtom(ctx, prop_enum[i].atom);
      }
      js_free(ctx, prop_enum);
    };

    JSAtom& operator[](size_t i) const
    {
      return prop_enum[i].atom;
    }

    [[nodiscard]] size_t size() const
    {
      return prop_count;
    }

    JSPropertyEnum* prop_enum = nullptr;
    uint32_t prop_count = 0;
    JSContext* ctx = nullptr;
  };
}
