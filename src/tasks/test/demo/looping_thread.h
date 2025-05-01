// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/threading/thread_ids.h"

#include <atomic>
#include <string>
#include <thread>

template <typename TState>
struct LoopingThread
{
  using State = TState;

  // Derived instances will likely access state inside their loop_behaviour,
  // which should be destroyed _after_ the loop ends. That means (because of C++
  // destructor order) it needs to be defined as a member here, so that it is
  // destructed _after_ the destructor runs
  TState state;

  std::atomic<bool> stop_signal = false;
  std::thread thread;

  template <typename... Ts>
  LoopingThread(const std::string& name, Ts&&... args) :
    state(std::forward<Ts>(args)...)
  {
    thread = std::thread([this, name]() {
      ccf::threading::set_current_thread_name(name);
      while (!stop_signal)
      {
        if (this->loop_behaviour())
        {
          break;
        }

        if (this->idle_behaviour())
        {
          break;
        }
      }
    });
  }

  virtual ~LoopingThread()
  {
    LOG_DEBUG_FMT("Exiting");
    stop_signal = true;
    thread.join();
    LOG_DEBUG_FMT("Exited");
  }

  virtual bool loop_behaviour()
  {
    return true;
  }

  virtual bool idle_behaviour()
  {
    std::this_thread::yield();
    return false;
  }
};