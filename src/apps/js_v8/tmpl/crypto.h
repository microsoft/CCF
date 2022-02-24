// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <v8.h>

namespace ccf::v8_tmpl
{
  class Crypto
  {
  public:
    static constexpr const char* NAME = "CCFCrypto";
    static v8::Local<v8::ObjectTemplate> create_template(v8::Isolate* isolate);

    static v8::Local<v8::Object> wrap(v8::Local<v8::Context> context);
  };

} // namespace ccf::v8_tmpl
