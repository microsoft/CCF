// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <string>
#include <utility>

namespace ccf::kv
{
  // Also thrown when acquiring a new map view after a store rollback since
  // the transaction's read snapshot was selected. Both conditions need a retry.
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
