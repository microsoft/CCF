// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

// Test-only capture of connection engine worker passes as NDJSON records,
// which lean/tls replays against its model. The declarations below exist only
// in builds with CCF_TLS_TRACING, where capture starts once start() finds
// CCF_TLS_TRACE_FILE and TLS_TRACE(...) runs its statements only while capture
// is active. In other builds TLS_TRACE(...) expands to an empty statement.
// Hooks only read connection state: they must not change what the engine does.
#ifdef CCF_TLS_TRACING
#  include <atomic>
#  include <cstdint>
#  include <cstdlib>
#  include <filesystem>
#  include <fstream>
#  include <mutex>
#  include <stdexcept>
#  include <string>
#  include <string_view>
#  include <vector>

namespace ccf::tls::trace
{
  // The mutex orders every record by seq. It is a leaf lock: tracing never
  // acquires an engine lock while holding it.
  struct Sink
  {
    std::mutex mutex;
    std::ofstream output;
    uint64_t seq = 0;
  };

  inline Sink& sink()
  {
    static Sink instance;
    return instance;
  }

  // Set only while a sink is active. Inline so that hooks in a tracing build
  // which is not capturing pay one load, rather than a call.
  inline std::atomic<bool> capturing{false};

  // Distinguishes the engines of one process, whose connection ids overlap.
  inline std::atomic<uint64_t> next_engine{1};

  inline bool enabled()
  {
    return capturing.load(std::memory_order_acquire);
  }

  // Writes one record. `fields` is the rest of a JSON object, starting with a
  // comma, whose values are numbers, booleans and strings of plain ASCII.
  inline void event(std::string_view type, std::string_view fields = {})
  {
    auto& out = sink();
    std::lock_guard<std::mutex> guard(out.mutex);
    if (!out.output.is_open())
    {
      return;
    }
    out.output << "{\"seq\":" << ++out.seq << ",\"type\":\"" << type << "\""
               << fields << "}\n";
  }

  inline void start()
  {
    const char* path = std::getenv("CCF_TLS_TRACE_FILE");
    if (path == nullptr)
    {
      return;
    }
    if (!std::filesystem::path(path).is_absolute())
    {
      throw std::logic_error("CCF_TLS_TRACE_FILE must be absolute");
    }
    {
      auto& out = sink();
      std::lock_guard<std::mutex> guard(out.mutex);
      out.output.open(path, std::ios::out | std::ios::trunc);
      if (!out.output)
      {
        throw std::runtime_error("Cannot open CCF_TLS_TRACE_FILE");
      }
      out.seq = 0;
    }
    capturing.store(true, std::memory_order_release);
    event("trace_start", ",\"schema\":1");
  }

  // Throws if any record could not be written, so that a truncated trace is
  // not mistaken for a complete one.
  inline void finish()
  {
    if (!capturing.exchange(false, std::memory_order_acq_rel))
    {
      return;
    }
    auto& out = sink();
    std::lock_guard<std::mutex> guard(out.mutex);
    out.output << "{\"seq\":" << out.seq + 1
               << ",\"type\":\"trace_end\",\"events\":" << out.seq << "}\n";
    out.output.flush();
    const bool written = out.output.good();
    out.output.close();
    if (!written)
    {
      throw std::runtime_error("Cannot write CCF_TLS_TRACE_FILE");
    }
  }

  inline std::string quoted(std::string_view text)
  {
    std::string result = "\"";
    for (const char c : text)
    {
      // Names come from the tests. Anything which would need escaping is
      // replaced, since the names only label diagnostics.
      const bool plain = c >= ' ' && c <= '~' && c != '"' && c != '\\';
      result.push_back(plain ? c : '?');
    }
    result.push_back('"');
    return result;
  }

  // What a worker pass saw before it drove the connection.
  struct Pass
  {
    // Set once the connection is established with a traffic-key policy.
    bool traced = false;
    // This pass is the one which completed the handshake.
    bool first = false;
    bool readable = false;
    bool pending_input = false;
    size_t queued = 0;
  };
}

#  define TLS_TRACE(...) \
    do \
    { \
      if (ccf::tls::trace::enabled()) \
      { \
        __VA_ARGS__; \
      } \
    } while (false)
#else
#  define TLS_TRACE(...) \
    do \
    { \
    } while (false)
#endif
