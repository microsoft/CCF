// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/base_endpoint_registry.h"

#include <v8.h>

namespace ccf::v8_tmpl
{
  class Consensus
  {
  public:
    static constexpr const char* NAME = "CCFConsensus";
    static v8::Local<v8::ObjectTemplate> create_template(v8::Isolate* isolate);

    static v8::Local<v8::Object> wrap(
      v8::Local<v8::Context> context,
      ccf::BaseEndpointRegistry* endpoint_registry);
  };

} // namespace ccf::v8_tmpl
