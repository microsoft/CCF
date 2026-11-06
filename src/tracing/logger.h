// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "tracing/trace.h"

namespace ccf::tracing
{
  inline void emit_log(const ccf::logger::LogLine& line)
  {
    if (!FluentdSink::is_running())
    {
      return;
    }
    emit_record("ccf.log", [&](auto& buffer) {
      nlohmann::json::to_msgpack(ccf::logger::format_to_json(line), buffer);
    });
  }
}
