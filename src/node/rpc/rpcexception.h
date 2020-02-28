// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include <exception>
#include <string>

namespace ccf
{
  struct RpcException : public std::exception
  {
    const std::string msg;
    const int status;

    RpcException(std::string msg, int status) : msg(msg), status(status) {}

    const char* what() const throw() override
    {
      return msg.c_str();
    }
  };
}