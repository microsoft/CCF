// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#ifdef VIRTUAL_ENCLAVE
#  pragma clang diagnostic push
#  pragma clang diagnostic ignored "-Wundef"
#  include <backward-cpp/backward.hpp>
#  pragma clang diagnostic pop
#endif
#include "logger.h"

#include <exception>
#include <string>

namespace ccf
{
  class ccf_logic_error : public std::exception
  {
  public:
    ccf_logic_error(const std::string& what_arg)
    {
      if (!what_arg.empty())
      {
        result.append(what_arg.c_str());
        result.append("\n");
      }

#ifdef VIRTUAL_ENCLAVE
      backward::StackTrace st;
      st.load_here();

      std::ostringstream stream;
      backward::Printer p;
      p.print(st, stream);
      result.append(stream.str());
#endif
    }

    ccf_logic_error() : ccf_logic_error("") {}

    const char* what() const throw() override
    {
      return result.c_str();
    }

  private:
    std::string result;
  };
};
