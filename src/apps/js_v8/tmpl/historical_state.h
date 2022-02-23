// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/historical_queries_interface.h"

#include <map>
#include <string>
#include <v8.h>

namespace ccf::v8_tmpl
{
  class HistoricalState
  {
  public:
    static constexpr const char* NAME = "CCFHistoricalState";
    static v8::Local<v8::ObjectTemplate> create_template(v8::Isolate* isolate);

    static v8::Local<v8::Object> wrap(
      v8::Local<v8::Context> context,
      const ccf::historical::StatePtr& historical_state);
  };

} // namespace ccf::v8_tmpl
