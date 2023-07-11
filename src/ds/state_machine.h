// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/logger.h"

#include <atomic>
#include <string>

namespace ds
{
  template <typename T>
  class StateMachine
  {
    const std::string label;
    std::atomic<T> s;

  public:
    StateMachine(std::string&& l, T s_) : label(std::move(l)), s(s_) {}

    void expect(T s_) const
    {
      auto state = s.load();
      if (s_ != state)
      {
        throw std::logic_error(
          fmt::format("[{}] State is {}, but expected {}", label, state, s_));
      }
    }

    bool check(T s_) const
    {
      return s_ == this->s.load();
    }

    T value() const
    {
      return s.load();
    }

    void advance(T s_)
    {
      LOG_DEBUG_FMT(
        "[{}] Advancing to state {} (from {})", label, s_, s.load());
      s.store(s_);
    }
  };
}
