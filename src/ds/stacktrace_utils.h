// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.
#pragma once

#include "../3rdparty/backward-cpp/backward.hpp"

#include <chrono>
#include <cstring>
#include <cxxabi.h>
#include <execinfo.h>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <signal.h>
#include <sstream>
#include <string>

namespace logger
{
  /** Print a demangled stack backtrace of the caller function to FILE* out. */
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

  static inline void Init(const char* file_name_extention)
  {
    signal(SIGSEGV, handler); // install our handler

    std::string output_file("out");
    output_file.append(file_name_extention);
    output_file.append(".txt");

    std::string error_file("err");
    error_file.append(file_name_extention);
    error_file.append(".txt");

    freopen(output_file.c_str(), "w", stdout);
    freopen(error_file.c_str(), "w", stderr);
  }
}
