// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "logger.h"
#ifndef INSIDE_ENCLAVE
// #  pragma clang diagnostic push
// #  pragma clang diagnostic ignored "-Wundef"
#  include <backward-cpp/backward.hpp>
// #  pragma clang diagnostic pop
#else
#  include <execinfo.h>
#endif

#include <iostream>

namespace stacktrace
{
  /** Print a stack backtrace of the caller function to std out.
   * In-enclave version will contain mangled names, and uses the standard
   * ringbuffer logging mechanism.
   */
  static inline void print_stacktrace()
  {
#ifndef INSIDE_ENCLAVE
    backward::StackTrace st;
    st.load_here();
    backward::Printer p;
    p.print(st, std::cout);
#else
    static constexpr int max_frames = 32;
    void* frames[max_frames];

    const int num_frames = backtrace(frames, max_frames);
    char** symbols = backtrace_symbols(frames, num_frames);
    if (symbols != NULL)
    {
      std::string s;
      for (int i = 0; i < num_frames; ++i)
      {
        s += fmt::format(" [{:>2}]: {}\n", i, symbols[i]);
      }
      LOG_INFO_FMT("Printing {} stack frames:\n {}", num_frames, s);
    }
    free(symbols);
#endif
  }

#ifndef INSIDE_ENCLAVE
  static void sig_handler(int signo, siginfo_t* info, void* _ctx)
  {
    backward::SignalHandling::handleSignal(signo, info, _ctx);
    LOG_FATAL_FMT("Handled fatal signal {}", signo);

    // SA_RESETHAND seems to be insufficient, so we manually reset the handler
    // before re-raising
    signal(signo, SIG_DFL);
    raise(signo);
  }

  static inline void init_sig_handlers()
  {
    // This is based on the constructor of backward::SignalHandling, but avoids
    // infinitely recursing stacktraces
    constexpr size_t stack_size = 1024 * 1024 * 8;
    static std::unique_ptr<char[]> stack_content = nullptr;

    stack_content.reset(new char[stack_size]);

    stack_t ss;
    ss.ss_sp = stack_content.get();
    ss.ss_size = stack_size;
    ss.ss_flags = 0;
    const auto ret = sigaltstack(&ss, nullptr);
    if (ret < 0)
    {
      LOG_FATAL_FMT("sigalstack returned error");
    }

    const int posix_signals[] = {
      // Signals for which the default action is "Core".
      SIGABRT, // Abort signal from abort(3)
      SIGBUS, // Bus error (bad memory access)
      SIGFPE, // Floating point exception
      SIGILL, // Illegal Instruction
      SIGIOT, // IOT trap. A synonym for SIGABRT
      SIGQUIT, // Quit from keyboard
      SIGSEGV, // Invalid memory reference
      SIGSYS, // Bad argument to routine (SVr4)
      SIGTRAP, // Trace/breakpoint trap
      SIGXCPU, // CPU time limit exceeded (4.2BSD)
      SIGXFSZ, // File size limit exceeded (4.2BSD)
#  if defined(BACKWARD_SYSTEM_DARWIN)
      SIGEMT, // emulation instruction executed
#  endif
    };

    for (const int signal : posix_signals)
    {
      struct sigaction action;
      memset(&action, 0, sizeof action);
      action.sa_flags =
        static_cast<int>(SA_SIGINFO | SA_ONSTACK | SA_NODEFER | SA_RESETHAND);
      sigfillset(&action.sa_mask);
      sigdelset(&action.sa_mask, signal);
#  if defined(__clang__)
#    pragma clang diagnostic push
#    pragma clang diagnostic ignored "-Wdisabled-macro-expansion"
#  endif
      action.sa_sigaction = &sig_handler;
#  if defined(__clang__)
#    pragma clang diagnostic pop
#  endif

      int r = sigaction(signal, &action, nullptr);
      if (r < 0)
      {
        LOG_FATAL_FMT("Error installing signal {} ({})", signal, r);
      }
    }
  }
#endif
}
