// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "tasks/worker.h"

#include <cstdlib>
#include <cxxabi.h>
#include <dlfcn.h>
#include <execinfo.h>
#include <sstream>

namespace ccf::tasks
{
  // Maximum number of frames to capture at the throw-point
  static constexpr int throw_trace_max_frames = 128;

  struct ThrowTrace
  {
    void* frames[throw_trace_max_frames] = {};
    int num_frames = 0;
  };

  static thread_local ThrowTrace current_throw_trace = {};

  static std::string demangle_symbol(const char* raw)
  {
    // backtrace_symbols format: "binary(mangled+0xoffset) [0xaddr]"
    // Try to extract and demangle the symbol name between '(' and '+'/')'
    std::string entry(raw);
    auto open = entry.find('(');
    auto plus = entry.find('+', open != std::string::npos ? open : 0);
    auto close = entry.find(')', open != std::string::npos ? open : 0);

    if (
      open != std::string::npos && close != std::string::npos &&
      close > open + 1)
    {
      auto end = (plus != std::string::npos && plus < close) ? plus : close;
      std::string mangled = entry.substr(open + 1, end - open - 1);

      if (!mangled.empty())
      {
        int status = 0;
        char* demangled =
          abi::__cxa_demangle(mangled.c_str(), nullptr, nullptr, &status);
        if (status == 0 && demangled != nullptr)
        {
          std::string rest = entry.substr(end);
          entry = entry.substr(0, open + 1) + demangled + rest;
        }
        free(demangled);
      }
    }

    return entry;
  }

  // Format a demangled stack trace as a string. Note: backtrace_symbols only
  // resolves symbols exported to the dynamic symbol table (e.g. via
  // -rdynamic). Static/internal functions will appear as raw addresses. For
  // broader coverage, consider integrating libbacktrace (reads DWARF directly)
  // or invoking addr2line at runtime.
  static std::string format_stacktrace(void** frames, int num_frames)
  {
    std::ostringstream oss;
    char** symbols = backtrace_symbols(frames, num_frames);
    for (int i = 0; i < num_frames; ++i)
    {
      oss << "  #" << i << ": " << demangle_symbol(symbols[i]) << "\n";
    }
    free(symbols);
    return oss.str();
  }

  void dump_stacktrace(const std::string& msg)
  {
    LOG_FATAL_FMT("{}", msg);

    auto& throw_trace = current_throw_trace;
    if (throw_trace.num_frames > 0)
    {
      LOG_FATAL_FMT(
        "Stack trace:\n{}",
        format_stacktrace(throw_trace.frames, throw_trace.num_frames));

      // Reset so that a subsequent dump does not re-use a stale trace
      // (e.g. if an earlier throw was caught internally and a later
      // throw; / re-throw escapes without calling __cxa_throw).
      throw_trace.num_frames = 0;
    }
    else
    {
      LOG_FATAL_FMT("No throw-point stack trace available");
    }
  }
}

// Interpose __cxa_throw to capture a backtrace at each throw-point.
// This is called by the C++ runtime whenever `throw` is executed.
extern "C"
{
  using CxaThrowFn = void (*)(void*, std::type_info*, void (*)(void*));

  void __cxa_throw(
    void* thrown_exception, std::type_info* tinfo, void (*dest)(void*))
  {
    // Capture the backtrace at the throw site
    auto& trace = ccf::tasks::current_throw_trace;
    trace.num_frames =
      backtrace(trace.frames, ccf::tasks::throw_trace_max_frames);

    // Forward to the real __cxa_throw
    static CxaThrowFn real_cxa_throw =
      reinterpret_cast<CxaThrowFn>(dlsym(RTLD_NEXT, "__cxa_throw"));
    real_cxa_throw(thrown_exception, tinfo, dest);

    // __cxa_throw is [[noreturn]], but the compiler may not know that about the
    // function pointer call. This satisfies the compiler.
    __builtin_unreachable();
  }
}