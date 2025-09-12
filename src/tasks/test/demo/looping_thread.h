// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/threading/thread_ids.h"

#include <atomic>
#include <string>
#include <thread>

enum class Stage
{
  PreInit,
  Running,
  ShuttingDown,
  Terminated,
};
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

  std::atomic<Stage> lifetime_stage;

  template <typename... Ts>
  LoopingThread(const std::string& _name, Ts&&... args) :
    state(std::forward<Ts>(args)...),
    name(_name),
    lifetime_stage(Stage::PreInit)
  {}

  virtual ~LoopingThread() = 0;

  virtual void shutdown()
  {
    LOG_DEBUG_FMT("Stopping {}", name);
    stop_signal.store(true);

    if (thread.joinable())
    {
      thread.join();
    }

    lifetime_stage.store(Stage::Terminated);
  }

  virtual void start()
  {
    thread = std::thread([this]() {
      lifetime_stage.store(Stage::PreInit);

      this->init_behaviour();

      lifetime_stage.store(Stage::Running);

      while (!stop_signal)
      {
        auto loop_behaviour_target_stage = this->loop_behaviour();
        REQUIRE(loop_behaviour_target_stage >= lifetime_stage);
        lifetime_stage.store(loop_behaviour_target_stage);
        if (lifetime_stage.load() == Stage::Terminated)
        {
          break;
        }

        auto idle_behaviour_target_stage = this->idle_behaviour();
        REQUIRE(idle_behaviour_target_stage >= lifetime_stage);
        lifetime_stage.store(idle_behaviour_target_stage);
        if (lifetime_stage.load() == Stage::Terminated)
        {
          break;
        }
      }

      LOG_DEBUG_FMT("Terminating thread");
    });
  }

  virtual void init_behaviour() {}

  virtual Stage loop_behaviour()
  {
    // Base loop_behaviour is to terminate immediately
    return Stage::Terminated;
  }

  virtual Stage idle_behaviour()
  {
    std::this_thread::yield();
    return lifetime_stage.load();
  }
};

template <typename T>
inline LoopingThread<T>::~LoopingThread<T>()
{}
