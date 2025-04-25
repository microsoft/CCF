// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/threading/thread_ids.h"

#include <atomic>
#include <string_view>
#include <thread>

struct LoopingThread
{
  std::atomic<bool> stop_signal = false;
  std::thread thread;

  LoopingThread(std::string_view name)
  {
    thread = std::thread([this, name]() {
      ccf::threading::set_current_thread_name(name);
      while (!stop_signal)
      {
        if (!this->loop_behaviour())
        {
          break;
        }

        if (!this->idle_behaviour())
        {
          break;
        }
      }
    });
  }

  virtual ~LoopingThread()
  {
    stop_signal = true;
    thread.join();
  }

  virtual bool loop_behaviour() = 0;

  virtual bool idle_behaviour()
  {
    std::this_thread::yield();
    return false;
  }
};