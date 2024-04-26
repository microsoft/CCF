// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

namespace ccf::js
{
  namespace
  {
    JSValue your_func_here(
      JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv)
    {
        ...
    }

  }

  JSValue create_global_FOO_object(
    ..., JSContext* ctx)
  {
    auto FOO = JS_NewObjectClass(ctx, host_class_id);
    JS_SetOpaque(host, ,,,);

    ...
    return FOO;
  }
}
