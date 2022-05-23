// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/base_endpoint_registry.h"
#include "ccf/endpoint_context.h"

#include <v8.h>

using ccf::BaseEndpointRegistry;
using ccf::endpoints::EndpointContext;
using ccf::endpoints::EndpointDefinition;

namespace ccf::v8_tmpl
{
  class Request
  {
  public:
    static constexpr const char* NAME = "CCFRequest";
    static v8::Local<v8::ObjectTemplate> create_template(v8::Isolate* isolate);

    static v8::Local<v8::Object> wrap(
      v8::Local<v8::Context> context,
      const EndpointDefinition* endpoint_def,
      EndpointContext* endpoint_ctx,
      BaseEndpointRegistry* endpoint_registry);
  };

} // namespace ccf::v8_tmpl
