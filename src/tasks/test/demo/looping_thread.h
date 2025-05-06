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

  const std::string name;

  template <typename... Ts>
  LoopingThread(const std::string& _name, Ts&&... args) :
    state(std::forward<Ts>(args)...),
    name(_name)
  {}

  virtual ~LoopingThread() = 0;

  virtual void shutdown()
  {
    LOG_DEBUG_FMT("Stopping {}", name);
    stop_signal = true;
    thread.join();
  }

  virtual void start()
  {
    thread = std::thread([this]() {
      ccf::threading::set_current_thread_name(name);

      this->init_behaviour();

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

      LOG_DEBUG_FMT("Terminating thread");
    });
  }

  virtual void init_behaviour() {}

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

template <typename T>
inline LoopingThread<T>::~LoopingThread<T>()
{}
