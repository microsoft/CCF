// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <memory>

namespace kv
{
  class Store;
  using StorePtr = std::shared_ptr<kv::Store>;
}
