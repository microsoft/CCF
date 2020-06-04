// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.
#pragma once

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
  static inline void print_stacktrace(
    FILE* out = stdout, unsigned int max_frames = 63)
  {
    std::cout << "stack trace:" << std::endl;

    void* addrlist[max_frames + 1];
    int addrlen = backtrace(addrlist, sizeof(addrlist) / sizeof(void*));

    if (addrlen == 0)
    {
      std::cout << "  <empty, possibly corrupt>" << std::endl;
      return;
    }

    char** symbollist = backtrace_symbols(addrlist, addrlen);
    size_t funcnamesize = 256;
    char* funcname = (char*)malloc(funcnamesize);

    for (int i = 1; i < addrlen; i++)
    {
      char *begin_name = 0, *begin_offset = 0, *end_offset = 0;

      for (char* p = symbollist[i]; *p; ++p)
      {
        if (*p == '(')
        {
          begin_name = p;
        }
        else if (*p == '+')
        {
          begin_offset = p;
        }
        else if (*p == ')' && begin_offset)
        {
          end_offset = p;
          break;
        }
      }

      if (begin_name && begin_offset && end_offset && begin_name < begin_offset)
      {
        *begin_name++ = '\0';
        *begin_offset++ = '\0';
        *end_offset = '\0';

        int status;
        char* ret =
          abi::__cxa_demangle(begin_name, funcname, &funcnamesize, &status);
        if (status == 0)
        {
          funcname = ret;
          std::cout << "  " << symbollist[i] << " : " << funcname << "+"
                    << begin_offset << std::endl;
        }
        else
        {
          std::cout << "  " << symbollist[i] << " : " << begin_name << "()+"
                    << begin_offset << std::endl;
        }
      }
      else
      {
        std::cout << "  " << symbollist[i] << std::endl;
      }
    }

    free(funcname);
    free(symbollist);
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
