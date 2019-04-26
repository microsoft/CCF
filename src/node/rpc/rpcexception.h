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
    const int error_id;

    RpcException(std::string msg, int error_id) : msg(msg), error_id(error_id)
    {}

    const char* what() const throw() override
    {
      return msg.c_str();
    }
  };
}