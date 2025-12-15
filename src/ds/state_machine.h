// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/internal_logger.h"

#include <atomic>
#include <string>
#include <utility>

namespace ds
{
  template <typename T>
  class StateMachine
  {
    const std::string label;
    std::atomic<T> state;

  public:
    StateMachine(std::string label_, T state_) :
      label(std::move(label_)),
      state(state_)
    {}

    void expect(T state_) const
    {
      auto state_snapshot = state.load();
      if (state_ != state_snapshot)
      {
        throw std::logic_error(fmt::format(
          "[{}] State is {}, but expected {}", label, state_snapshot, state_));
      }
    }

    [[nodiscard]] bool check(T state_) const
    {
      return state_ == state.load();
    }

    [[nodiscard]] T value() const
    {
      return state.load();
    }

    void advance(T state_)
    {
      LOG_DEBUG_FMT("[{}] Advancing to state {}", label, state_);
      state.store(state_);
    }
  };
}
