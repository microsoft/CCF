// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "tasks/queues/locking_concurrent_queue.h"

#include <atomic>
#include <thread>
#include <unordered_map>
#include <vector>

struct OrderedTasks
{}; // TODO

struct Node
{
  struct IO
  {
    ccf::tasks::LockingConcurrentQueue<std::string> to_node;
    ccf::tasks::LockingConcurrentQueue<std::string> from_node;
  };

  using IOPtr = std::unique_ptr<IO>;

  std::vector<IOPtr> io_collection;
  std::mutex io_mutex;

  IO& add_client()
  {
    std::lock_guard<std::mutex> lock(io_mutex);
    return *io_collection.emplace_back();
  }

  std::atomic<bool> stop_signal = false;
  std::thread dispatcher_thread;
  std::vector<std::thread> workers;

  std::unordered_map<IO*, OrderedTasks> ordered_tasks_per_client;

  Node(size_t num_workers)
  {
    dispatcher_thread = std::thread([&]() {
      while (!stop_signal)
      {
        {
          // Handle incoming IO, producing tasks to process each item
          std::lock_guard<std::mutex> lock(io_mutex);
          for (auto& io : io_collection)
          {
            auto it = ordered_tasks_per_client.find(io.get());
            if (it == ordered_tasks_per_client.end())
            {
              it = ordered_tasks_per_client.emplace_hint(it, io.get(), {});
            }

            auto incoming = io->to_node.try_pop();
            if (incoming.has_value())
            {
              it->add_task(...);
            }
          }
        }

        std::this_thread::yield();
      }
    });

    for (size_t i = 0; i < num_workers; ++i)
    {
      workers.emplace_back([&]() {
        while (!stop_signal)
        {
          // Wait at-most 100ms for a task
          auto task = job_board.wait_for_task(std::chrono::milliseconds(100));
          if (task.has_value())
          {
            task.do_task();
          }

          std::this_thread::yield();
        }
      });
    }
  }

  ~Node()
  {
    stop_signal.store(true);
    for (auto& worker : workers)
    {
      worker.join();
    }
    dispatcher_thread.join();
  }
};