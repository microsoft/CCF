// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <mutex>
#include <queue>
#include <thread>
#include <condition_variable>
#include "ds/messaging.h"
#include "enclave/interface.h"

namespace asynchost
{
  class ProcessLauncher
  {
    using Msg = std::tuple<std::vector<std::string>>;

    static constexpr size_t num_threads = 4;

    std::queue<Msg> queue;

    std::vector<std::thread> threads;
    std::mutex m;
    std::condition_variable cv;
    
    bool stopping = false;

    void process_msg(Msg&& msg)
    {
      // TODO launch exec-style to avoid arg escape issues
      auto args = std::get<0>(msg);
      std::ostringstream cmd_s;
      std::copy(args.begin(), args.end(),
                std::ostream_iterator<std::string>(cmd_s, " "));
      auto cmd = cmd_s.str();

      std::system(cmd.c_str());
    }

    void worker()
    {
      while (!stopping)
      {
        std::unique_lock<std::mutex> lock(m);
        cv.wait(lock);
        if (queue.empty())
          continue;
        auto msg = std::move(queue.front());
        queue.pop();
        lock.unlock();
        process_msg(std::move(msg));
      }
    }

    void stop()
    {
      stopping = true;
      cv.notify_all();
      for (auto& thread : threads)
      {
        thread.join();
      }
    }

  public:
    ProcessLauncher()
    {
      for (size_t i=0; i < num_threads; i++)
      {
        std::thread t(&ProcessLauncher::worker, this);
        threads.push_back(std::move(t));
      }
    }

    ~ProcessLauncher()
    {
      stop();
    }

    void register_message_handlers(
      messaging::Dispatcher<ringbuffer::Message>& disp)
    {
      DISPATCHER_SET_MESSAGE_HANDLER(
        disp, AppMessage::launch_host_process, [this](const uint8_t* data, size_t size) {
          auto msg =
            ringbuffer::read_message<AppMessage::launch_host_process>(data, size);

          std::lock_guard<std::mutex> lock(m);
          queue.push(std::move(msg));
          cv.notify_one();
        });
    }
  };
}
