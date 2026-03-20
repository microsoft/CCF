// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "tasks/worker.h"

#include <backtrace.h>
#include <cstdlib>
#include <cxxabi.h>
#include <dlfcn.h>
#include <memory>
#include <sstream>

namespace ccf::tasks
{
  // Maximum number of frames to capture at the throw-point
  static constexpr int throw_trace_max_frames = 128;

  struct ThrowTrace
  {
    void* frames[throw_trace_max_frames] = {};
    size_t num_frames = 0;
  };

  namespace
  {
    thread_local ThrowTrace current_throw_trace = {};

    struct FreeDeleter
    {
      void operator()(char* p) const
      {
        // NOLINTNEXTLINE(cppcoreguidelines-no-malloc,cppcoreguidelines-owning-memory)
        free(p);
      }
    };

    // Lazily initialise and return the process-wide backtrace_state.
    // backtrace_create_state allocates resources that cannot be freed, so
    // we call it at most once and cache the result.
    backtrace_state* get_backtrace_state()
    {
      static backtrace_state* state = backtrace_create_state(
        nullptr, // let libbacktrace find the executable
        1, // threaded = true
        nullptr, // ignore errors during init
        nullptr);
      return state;
    }

    // Demangle a C++ mangled symbol name. Returns the original string
    // unchanged if demangling fails.
    std::string demangle(const char* name)
    {
      if (name == nullptr)
      {
        return "<unknown>";
      }

      int status = 0;
      std::unique_ptr<char, FreeDeleter> demangled(
        abi::__cxa_demangle(name, nullptr, nullptr, &status));
      if (status == 0 && demangled != nullptr)
      {
        return demangled.get();
      }
      return name;
    }

    // Data passed through libbacktrace callbacks to build up each frame's
    // description.
    struct PcinfoResult
    {
      bool resolved = false;
      std::string function;
      std::string filename;
      int lineno = 0;
    };

    // Called by backtrace_pcinfo for each source location (may be called
    // multiple times per PC when inlined calls are present).
    int pcinfo_callback(
      void* data,
      uintptr_t /*pc*/,
      const char* filename,
      int lineno,
      const char* function)
    {
      auto* result = static_cast<PcinfoResult*>(data);
      if (function != nullptr)
      {
        result->resolved = true;
        result->function = demangle(function);
        result->filename = (filename != nullptr) ? filename : "";
        result->lineno = lineno;
      }
      return 0; // continue
    }

    // Called by backtrace_syminfo when DWARF info is unavailable but the
    // dynamic symbol table has an entry.
    void syminfo_callback(
      void* data,
      uintptr_t /*pc*/,
      const char* symname,
      uintptr_t /*symval*/,
      uintptr_t /*symsize*/)
    {
      auto* result = static_cast<PcinfoResult*>(data);
      if (symname != nullptr)
      {
        result->resolved = true;
        result->function = demangle(symname);
      }
    }

    // Silently ignore libbacktrace errors in individual frame resolution —
    // we fall back to printing the raw PC address.
    void error_callback(void* /*data*/, const char* /*msg*/, int /*errnum*/) {}

    // Format a stack trace using libbacktrace for DWARF-aware symbol,
    // file and line resolution. This works in all build configurations
    // without requiring -rdynamic.
    std::string format_stacktrace(void** frames, int num_frames)
    {
      std::ostringstream oss;
      auto* state = get_backtrace_state();

      for (int i = 0; i < num_frames; ++i)
      {
        auto pc = reinterpret_cast<uintptr_t>(frames[i]);
        PcinfoResult result;

        if (state != nullptr)
        {
          // Try DWARF-based resolution first (gives file + line + function)
          backtrace_pcinfo(state, pc, pcinfo_callback, error_callback, &result);

          // If DWARF info wasn't available, try the symbol table
          if (!result.resolved)
          {
            backtrace_syminfo(
              state, pc, syminfo_callback, error_callback, &result);
          }
        }

        oss << "  #" << i << ": ";
        if (result.resolved)
        {
          oss << result.function;
          if (!result.filename.empty())
          {
            oss << " at " << result.filename << ":" << result.lineno;
          }
        }
        else
        {
          oss << "0x" << std::hex << pc << std::dec;
        }
        oss << "\n";
      }
      return oss.str();
    }
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
    // Capture the backtrace at the throw site using libbacktrace's own
    // unwinder. glibc backtrace() can lose frames whose return address
    // falls exactly at the end of a .eh_frame FDE range; libbacktrace's
    // DWARF unwinder handles this correctly.
    auto& trace = ccf::tasks::current_throw_trace;
    trace.num_frames = 0;
    auto* bt_state = ccf::tasks::get_backtrace_state();
    if (bt_state != nullptr)
    {
      backtrace_simple(
        bt_state,
        0, // skip = 0, capture from here
        [](void* data, uintptr_t pc) -> int {
          auto* t = static_cast<ccf::tasks::ThrowTrace*>(data);
          if (t->num_frames < ccf::tasks::throw_trace_max_frames)
          {
            t->frames[t->num_frames++] = reinterpret_cast<void*>(pc); // NOLINT
          }
          return 0;
        },
        nullptr, // ignore errors
        &trace);
    }

    // Forward to the real __cxa_throw
    static auto real_cxa_throw =
      reinterpret_cast<CxaThrowFn>(dlsym(RTLD_NEXT, "__cxa_throw"));
    if (real_cxa_throw != nullptr)
    {
      real_cxa_throw(thrown_exception, tinfo, dest);
      // real_cxa_throw is [[noreturn]], so we never reach here
    }
    else
    {
      // If dlsym failed, we cannot safely proceed. Abort to prevent undefined
      // behavior.
      std::abort();
    }
    // Both real_cxa_throw and std::abort() are [[noreturn]], but the compiler
    // may not recognize that for function pointers. This satisfies the compiler
    // that we never return from this function.
    __builtin_unreachable();
  }
}
