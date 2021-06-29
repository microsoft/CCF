// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/logger.h"

#include <atomic>
#include <string>

namespace ds
{
  template <typename T>
  class StateMachine
  {
    std::atomic<T> s;
    const std::string label;

  public:
    StateMachine(std::string&& l, T s) : label(std::move(l)), s(s) {}

    void expect(T s) const
    {
      auto state = this->s.load();
      if (s != state)
      {
        throw std::logic_error(
          fmt::format("[{}] State is {}, but expected {}", label, state, s));
      }
    }

    bool check(T s) const
    {
      return s == this->s.load();
    }

    T value() const
    {
      return this->s.load();
    }

    void advance(T s)
    {
      LOG_DEBUG_FMT(
        "[{}] Advancing to state {} (from {})", label, s, this->s.load());
      this->s.store(s);
    }
  };
}