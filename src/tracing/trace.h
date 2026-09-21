// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "msgpack/fluentd_event_time.h"
#include "msgpack/serialization.h"
#include "tracing/fluentd_sink.h"

#include <atomic>
#include <chrono>
#include <string>
#include <tuple>
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

  // Alternating string keys and borrowed values form the envelope's msg map.
  template <typename... Args>
    requires msgpack::map_arguments<Args...>
  inline void emit(std::string_view tag, const Args&... args)
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
    msgpack::write_str(buffer, "process_id");
    msgpack::write_str(buffer, process_identity());
    msgpack::write_str(buffer, "h_ts");
    msgpack::write_uint(buffer, sequence);
    msgpack::write_str(buffer, "msg");
    msgpack::write_map_header(buffer, sizeof...(Args) / 2);
    using msgpack::write_msgpack;
    const auto refs = std::tie(args...);
    [&]<size_t... I>(std::index_sequence<I...>) {
      ((msgpack::write_str(buffer, std::get<2 * I>(refs)),
        write_msgpack(buffer, std::get<2 * I + 1>(refs))),
       ...);
    }(std::make_index_sequence<sizeof...(Args) / 2>{});
    FluentdSink::enqueue(buffer);
  }
}

#define CCF_TRACE_PARAMETER_FOR_JSON_NEXT(TYPE, MEMBER) const auto &MEMBER,
#define CCF_TRACE_PARAMETER_FOR_JSON_FINAL(TYPE, MEMBER) const auto& MEMBER
#define CCF_TRACE_ARGUMENT_FOR_JSON_NEXT(TYPE, MEMBER) , #MEMBER, MEMBER
#define CCF_TRACE_ARGUMENT_FOR_JSON_FINAL(TYPE, MEMBER) \
  CCF_TRACE_ARGUMENT_FOR_JSON_NEXT(TYPE, MEMBER)

// DECLARE_TRACE_EVENT(event, tag, field) declares event(const auto& field).
// Declare in the caller's namespace. The wrapper adds the function field.
#define DECLARE_TRACE_EVENT(NAME, TAG, ...) \
  inline void NAME(__VA_OPT__(_FOR_JSON_COUNT_NN(__VA_ARGS__)(POP1)( \
    CCF_TRACE_PARAMETER, _, __VA_ARGS__))) \
  { \
    ccf::tracing::emit( \
      TAG, \
      "function", \
      #NAME __VA_OPT__(_FOR_JSON_COUNT_NN(__VA_ARGS__)(POP1)( \
        CCF_TRACE_ARGUMENT, _, __VA_ARGS__))); \
  } \
  REQUIRES_SEMICOLON_TERMINATION
