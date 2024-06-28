// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/logger.h"

namespace ccf
{
  class RingbufferLogger : public ccf::logger::AbstractLogger
  {
  protected:
    ringbuffer::WriterPtr writer;

    // Current time, as us duration since epoch (from system_clock). Used to
    // produce offsets to host time when logging from inside the enclave
    std::atomic<std::chrono::microseconds> us = {};

  public:
    RingbufferLogger(const ringbuffer::WriterPtr& writer_) : writer(writer_) {}

    void write(
      const ccf::logger::LogLine& line,
      const std::optional<double>& enclave_offset = std::nullopt) override
    {
      writer->write(
        AdminMessage::log_msg,
        us.load().count(),
        line.file_name,
        line.line_number,
        line.log_level,
        line.tag,
        line.thread_id,
        line.msg);
    }

    void set_time(std::chrono::microseconds us_)
    {
      us.exchange(us_);
    }
  };
}