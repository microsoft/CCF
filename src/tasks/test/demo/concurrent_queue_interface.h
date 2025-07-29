// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <memory>
#include <optional>

namespace ccf::tasks
{
  template <typename T>
  class IConcurrentQueue
  {
  public:
    using ValueType = T;

    virtual ~IConcurrentQueue() = default;

    virtual bool empty() = 0;

    virtual void push_back(const T& t) = 0;
    virtual void emplace_back(T&& t) = 0;

    virtual std::optional<T> try_pop() = 0;
  };
}