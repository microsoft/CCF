// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "tasks/worker.h"

#include <cstdio>
#include <cstdlib>
#include <cxxabi.h>
#include <dlfcn.h>
#include <execinfo.h>

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

  static const ThrowTrace& get_throw_trace()
  {
    return current_throw_trace;
  }

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

  static void print_stacktrace(void** frames, int num_frames)
  {
    char** symbols = backtrace_symbols(frames, num_frames);
    for (int i = 0; i < num_frames; ++i)
    {
      fprintf(stderr, "  #%d: %s\n", i, demangle_symbol(symbols[i]).c_str());
    }
    free(symbols);
  }

  void dump_stacktrace(const std::string& msg)
  {
    LOG_FATAL_FMT("{}", msg);
    fprintf(stderr, "Fatal: %s\n", msg.c_str());

    // Prefer the throw-point backtrace captured by our __cxa_throw
    // interposition. Fall back to a backtrace from the current location.
    const auto& throw_trace = get_throw_trace();
    if (throw_trace.num_frames > 0)
    {
      fprintf(stderr, "Stack trace (from throw-point):\n");
      print_stacktrace(
        const_cast<void**>(throw_trace.frames), throw_trace.num_frames);
    }
    else
    {
      fprintf(stderr, "Stack trace (from catch-point):\n");
      static constexpr int max_frames = 128;
      void* buffer[max_frames];
      auto nptrs = backtrace(buffer, max_frames);
      print_stacktrace(buffer, nptrs);
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