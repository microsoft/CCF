// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/logger.h"

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
    }

    ccf_logic_error() : ccf_logic_error("") {}

    const char* what() const throw() override
    {
      return result.c_str();
    }

  private:
    std::string result;
  };

  class ccf_openssl_rdrand_init_error : public ccf_logic_error
  {
  public:
    ccf_openssl_rdrand_init_error(const std::string& what_arg) :
      ccf_logic_error(what_arg)
    {}
  };
};