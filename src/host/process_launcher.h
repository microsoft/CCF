// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/messaging.h"
#include "enclave/interface.h"

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <queue>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

namespace asynchost
{
  class ProcessLauncher
  {
    static constexpr size_t num_threads = 8;

    struct QueueEntry
    {
      LaunchHostProcessMessage msg;
      std::chrono::steady_clock::time_point queued_at;
    };

    std::queue<QueueEntry> queue;

    std::vector<std::thread> threads;
    std::mutex m;
    std::condition_variable cv;

    bool stopping = false;

    void handle_entry(QueueEntry&& entry)
    {
      auto now = std::chrono::steady_clock::now();
      auto queue_time_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(
          now - entry.queued_at)
          .count();

      auto& msg = entry.msg;
      auto& args = msg.args;

      std::vector<const char*> argv;
      for (size_t i = 0; i < args.size(); i++)
      {
        argv.push_back(args.at(i).c_str());
      }
      argv.push_back(nullptr);
      auto pid = fork();
      if (pid == -1)
      {
        LOG_FAIL_FMT(
          "Error running host process [fork]: {}", std::strerror(errno));
        return;
      }
      auto t_begin = std::chrono::steady_clock::now();
      if (pid == 0)
      {
        // child
        if (execv(argv.at(0), (char* const*)argv.data()) == -1)
        {
          LOG_FAIL_FMT(
            "Error running host process [execv]: {} cmd={}",
            std::strerror(errno),
            fmt::join(args, " "));
          exit(1);
        }
      }
      else
      {
        // parent
        LOG_DEBUG_FMT(
          "Launching host process: pid={} queuetime={}ms cmd={}",
          pid,
          queue_time_ms,
          fmt::join(args, " "));
        int exit_code;
        waitpid(pid, &exit_code, 0);
        auto t_end = std::chrono::steady_clock::now();
        auto runtime_ms =
          std::chrono::duration_cast<std::chrono::milliseconds>(t_end - t_begin)
            .count();
        LOG_DEBUG_FMT(
          "Host process exited: pid={} status={} runtime={}ms cmd={}",
          pid,
          exit_code,
          runtime_ms,
          fmt::join(args, " "));
      }
    }

    void worker()
    {
      while (!stopping)
      {
        std::unique_lock<std::mutex> lock(m);
        if (queue.empty())
        {
          cv.wait(lock);
          if (queue.empty())
            continue;
        }
        auto entry = std::move(queue.front());
        queue.pop();
        lock.unlock();
        handle_entry(std::move(entry));
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
      for (size_t i = 0; i < num_threads; i++)
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
        disp,
        AppMessage::launch_host_process,
        [this](const uint8_t* data, size_t size) {
          auto [json] =
            ringbuffer::read_message<AppMessage::launch_host_process>(
              data, size);

          auto obj = nlohmann::json::parse(json);
          auto msg = obj.get<LaunchHostProcessMessage>();

          auto queued_at = std::chrono::steady_clock::now();
          QueueEntry entry{msg, queued_at};

          LOG_DEBUG_FMT("Queueing host process launch: {}", json);

          std::lock_guard<std::mutex> lock(m);
          queue.push(std::move(entry));
          cv.notify_one();
        });
    }
  };
}
