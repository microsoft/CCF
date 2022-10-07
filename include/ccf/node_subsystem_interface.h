// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

namespace ccf
{
  class AbstractNodeSubSystem
  {
  public:
    virtual ~AbstractNodeSubSystem() = default;

    // Must contain a static function with signature:
    // static char const* get_subsystem_name()
  };
}
