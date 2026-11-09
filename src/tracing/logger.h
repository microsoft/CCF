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
    if (!FluentdSink::accepts("ccf.log"))
    {
      return;
    }
    ::timespec host_ts{};
    if (::timespec_get(&host_ts, TIME_UTC) == 0)
    {
      throw std::runtime_error("timespec_get failed");
    }
    std::tm host_tm{};
    ::gmtime_r(&host_ts.tv_sec, &host_tm);
    try
    {
      emit(
        "ccf.log",
        "h_ts",
        ccf::logger::get_timestamp(host_tm, host_ts),
        "thread_id",
        fmt::format("{}", line.thread_id),
        "level",
        ccf::logger::to_string(line.log_level),
        "tag",
        line.tag,
        "file",
        line.file_name,
        "number",
        fmt::format("{}", line.line_number),
        "msg",
        line.msg);
    }
    catch (const std::bad_alloc&)
    {
      FluentdSink::record_drop("ccf.log");
    }
  }
}
