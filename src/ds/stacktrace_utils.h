// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.
#pragma once

#ifndef INSIDE_ENCLAVE
// #  pragma clang diagnostic push
// #  pragma clang diagnostic ignored "-Wundef"
#  include <backward-cpp/backward.hpp>
// #  pragma clang diagnostic pop
#endif

#include <iostream>

namespace stacktrace
{
  /** Print a demangled stack backtrace of the caller function to std out. */
  static inline void print_stacktrace()
  {
#ifndef INSIDE_ENCLAVE
    std::cout << "stack trace:" << std::endl;
    backward::StackTrace st;
    st.load_here();
    backward::Printer p;
    p.print(st);
#endif
  }

  static inline void init_sig_handlers()
  {
#ifndef INSIDE_ENCLAVE
    // This registers signal handlers on construction, and these remain after
    // destruction.
    backward::SignalHandling sh;
#endif
  }
}
