// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <stdexcept>

namespace ccf::kv
{
  class MapAccessDenied : public std::logic_error
  {
  public:
    using std::logic_error::logic_error;
  };
}
