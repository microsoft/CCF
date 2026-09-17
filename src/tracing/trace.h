// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "msgpack/fields.h"
#include "msgpack/fluentd_event_time.h"
#include "tracing/fluentd_sink.h"

#include <atomic>
#include <chrono>
#include <string>
#include <unistd.h>
#include <vector>

namespace ccf::tracing
{
  inline std::vector<uint8_t>& event_buffer()
  {
    thread_local auto buffer = [] {
      std::vector<uint8_t> buffer;
      buffer.reserve(2048);
      return buffer;
    }();
    return buffer;
  }

  inline uint64_t next_sequence()
  {
    static std::atomic<uint64_t> sequence = 0;
    return sequence.fetch_add(1, std::memory_order_relaxed);
  }

  inline const std::string& process_identity()
  {
    static const auto id = fmt::format(
      "{}-{}",
      getpid(),
      std::chrono::system_clock::now().time_since_epoch().count());
    return id;
  }

  template <typename WriteRecord>
  inline void emit(
    std::string_view tag, uint32_t field_count, WriteRecord&& write_record)
  {
    if (!FluentdSink::is_configured())
    {
      return;
    }
    const auto sequence = next_sequence();
    auto& buffer = event_buffer();
    buffer.clear();
    msgpack::write_array_header(buffer, 3);
    msgpack::write_str(buffer, tag);
    msgpack::write_fluentd_event_time(
      buffer,
      msgpack::FluentdEventTime::make(std::chrono::system_clock::now()));
    msgpack::write_map_header(buffer, 3);
    msgpack::write_key(buffer, "process_id");
    msgpack::write_str(buffer, process_identity());
    msgpack::write_key(buffer, "h_ts");
    msgpack::write_uint(buffer, sequence);
    msgpack::write_key(buffer, "msg");
    msgpack::write_map_header(buffer, field_count);
    write_record(buffer);
    FluentdSink::enqueue(buffer);
  }

  template <typename... Fields>
  inline void emit_fields(std::string_view tag, const Fields&... fields)
  {
    emit(tag, sizeof...(Fields), [&](auto& out) {
      ((msgpack::write_key(out, fields.name),
        msgpack::write_msgpack(out, fields.value)),
       ...);
    });
  }
}
