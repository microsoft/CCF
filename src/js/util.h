// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <vector>
#include <string>
#include <stdexcept>
#include <quickjs/quickjs.h>

namespace js
{
  std::vector<std::string> read_string_array(JSContext* ctx, JSValueConst arr)
  {
    if (!JS_IsArray(ctx, arr))
    {
      throw std::invalid_argument("argument must be an array");
    }

    auto len_atom = JS_NewAtom(ctx, "length");
    auto len_val = JS_GetProperty(ctx, arr, len_atom);
    JS_FreeAtom(ctx, len_atom);
    uint32_t len = 0;
    JS_ToUint32(ctx, &len, len_val);
    JS_FreeValue(ctx, len_val);

    std::vector<std::string> v;
    for (uint32_t i = 0; i < len; i++)
    {
      auto val = JS_GetPropertyUint32(ctx, arr, i);
      if (!JS_IsString(val))
      {
        JS_FreeValue(ctx, val);
        throw std::invalid_argument(
          "array must only contain strings");
      }
      auto val_cstr = JS_ToCString(ctx, val);
      v.push_back(val_cstr);
      JS_FreeCString(ctx, val_cstr);
      JS_FreeValue(ctx, val);
    }
    return v;
  }
}