// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "tracing/trace.h"

namespace ccf::tracing
{
  class FluentdLogger : public ccf::logger::AbstractLogger
  {
  public:
    void write(const ccf::logger::LogLine& line) override
    {
      // Transport diagnostics run on an unbound consumer: never feed them back.
      if (
        line.log_level < ccf::LoggerLevel::INFO ||
        !FluentdSink::is_producer_active())
      {
        return;
      }
      emit_record("ccf.log", [&](auto& buffer) {
        nlohmann::json::to_msgpack(ccf::logger::format_to_json(line), buffer);
      });
    }
  };
}
