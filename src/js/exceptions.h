// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#define FMT_HEADER_ONLY
#include <fmt/format.h>

namespace ccf
{
  namespace js
  {
    class NewObjException : public std::exception
    {
    private:
      std::string msg;

    public:
      NewObjException(const std::string& msg_) : msg(msg_) {}

      const char* what() const throw() override
      {
        return msg.c_str();
      }
    };

    class SetPropException : public std::exception
    {
    private:
      std::string msg;

    public:
      SetPropException(const std::string& msg_) : msg(msg_) {}

      const char* what() const throw() override
      {
        return msg.c_str();
      }
    };

    JSValue check_new(JSValue val, const std::string& name)
    {
      if (JS_IsException(val))
      {
        throw NewObjException(fmt::format("Failed to create {}", name));
      }
      return val;
    };

    void check_set_prop(int return_code, const std::string& name)
    {
      if (return_code == -1)
      {
        throw SetPropException(fmt::format("Failed to set property {}", name));
      }
    };
  }
}