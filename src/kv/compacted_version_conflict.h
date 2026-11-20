// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <string>
#include <utility>

namespace ccf::kv
{
  // Also thrown when a map was invalidated after the transaction selected its
  // read snapshot. Both conditions require retrying the entire transaction.
  class CompactedVersionConflict
  {
  private:
    std::string msg;

  public:
    CompactedVersionConflict(std::string s) : msg(std::move(s)) {}

    [[nodiscard]] char const* what() const
    {
      return msg.c_str();
    }
  };
}
