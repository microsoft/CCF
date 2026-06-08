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
    GetName(const std::string& s) : name(s) {}
    virtual ~GetName() = default;

    const std::string& get_name() const
    {
      return name;
    }
  };
}
