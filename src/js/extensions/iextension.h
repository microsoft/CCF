// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <memory>
#include <vector>

namespace ccf::js::core
{
  class Context;
}

namespace ccf::js::extensions
{
  class IExtension
  {
  public:
    virtual ~IExtension() = default;

    virtual void install(js::core::Context& ctx) = 0;
  };

  using ExtensionPtr = std::shared_ptr<IExtension>;
  using Extensions = std::vector<ExtensionPtr>;
}
