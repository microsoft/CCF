// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <quickjs/quickjs.h>

namespace ccf::js::core::constants
{
// "compound literals are a C99-specific feature"
// Used heavily by QuickJS, including in macros (such as
// ccf::js::core::constants::Null). Rather than disabling throughout the code,
// we replace those with const instances here
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc99-extensions"
  static constexpr JSValue Null = JS_NULL;
  static constexpr JSValue Undefined = JS_UNDEFINED;
  static constexpr JSValue False = JS_FALSE;
  static constexpr JSValue True = JS_TRUE;
  static constexpr JSValue Exception = JS_EXCEPTION;
#pragma clang diagnostic pop
}
