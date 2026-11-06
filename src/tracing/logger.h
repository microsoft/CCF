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
      if (!FluentdSink::is_running() || !FluentdSink::accepts("ccf.log"))
      {
        return;
      }
      try
      {
        FluentdSink::enqueue_log(
          "ccf.log", encode_record("ccf.log", [&](auto& buffer) {
            nlohmann::json::to_msgpack(
              ccf::logger::format_to_json(line), buffer);
          }));
      }
      catch (const std::bad_alloc&)
      {
        FluentdSink::record_drop("ccf.log");
      }
    }
  };
}
