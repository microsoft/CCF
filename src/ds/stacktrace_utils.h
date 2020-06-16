// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.
#pragma once

#include "../3rdparty/backward-cpp/backward.hpp"

#include <cstring>
#include <fstream>
#include <optional>
#include <signal.h>
#include <sstream>
#include <string>

namespace logger
{
  /** Print a demangled stack backtrace of the caller function to std out. */
  static inline void print_stacktrace()
  {
    std::cout << "stack trace:" << std::endl;
    backward::StackTrace st;
    st.load_here();
    backward::Printer p;
    p.print(st);
  }

  static void handler(int sig)
  {
    std::cout << "Error: signal " << sig << ":" << std::endl;
    print_stacktrace();
    exit(1);
  }
}
