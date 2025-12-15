// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/odata_error.h"

#include <exception>
#include <string>

namespace ccf
{
  struct RpcException : public std::exception
  {
    ErrorDetails error;

    RpcException(
      ccf::http_status status, const std::string& code, std::string&& msg) :
      error{status, code, std::move(msg)}
    {}

    [[nodiscard]] const char* what() const noexcept override
    {
      return error.msg.c_str();
    }
  };
}