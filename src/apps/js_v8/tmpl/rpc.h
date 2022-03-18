// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/rpc_context.h"

#include <v8.h>

namespace ccf::v8_tmpl
{
  class Rpc
  {
  public:
    static constexpr const char* NAME = "CCFRpc";
    static v8::Local<v8::ObjectTemplate> create_template(v8::Isolate* isolate);

    static v8::Local<v8::Object> wrap(
      v8::Local<v8::Context> context, ccf::RpcContext* rpc_ctx);
  };

} // namespace ccf::v8_tmpl
