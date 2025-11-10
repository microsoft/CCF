// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <string>

namespace ccf::kv
{
  struct GetName
  {
  protected:
    std::string name;

  public:
    GetName(std::string s) : name(std::move(s)) {}
    virtual ~GetName() = default;

    [[nodiscard]] const std::string& get_name() const
    {
      return name;
    }
  };
}
