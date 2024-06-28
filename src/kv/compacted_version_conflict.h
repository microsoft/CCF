// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <string>

namespace ccf::kv
{
  class CompactedVersionConflict
  {
  private:
    std::string msg;

  public:
    CompactedVersionConflict(const std::string& s) : msg(s) {}

    char const* what() const
    {
      return msg.c_str();
    }
  };
}
