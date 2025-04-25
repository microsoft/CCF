// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "./actions.h"
#include "./job_board.h"
#include "./ordered_tasks.h"
#include "tasks/queues/locking_concurrent_queue.h"

#include <atomic>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

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
    return *io_collection.emplace_back(std::make_unique<IO>());
  }

  std::atomic<bool> stop_signal = false;
  std::thread dispatcher_thread;
  std::vector<std::thread> workers;

  std::unordered_map<IO*, std::shared_ptr<OrderedTasks>>
    ordered_tasks_per_client;

  IJobBoard& job_board;

  Node(size_t num_workers, IJobBoard& jb) : job_board(jb)
  {
    dispatcher_thread = std::thread([&]() {
      ccf::threading::set_current_thread_name("dsp");
      size_t ot_idx = 0;
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
              it = ordered_tasks_per_client.emplace_hint(
                it,
                io.get(),
                std::make_shared<OrderedTasks>(
                  job_board, fmt::format("[Ordered {}]", ot_idx++)));
            }

            auto& tasks = *it->second;

            auto incoming = io->to_node.try_pop();
            while (incoming.has_value())
            {
              auto [idx, remainder] =
                ccf::nonstd::split_1(incoming.value(), "|");
              auto task = make_task(
                [incoming = incoming, io = io.get()]() {
                  // TODO: This is where the real work happens! Make it a custom
                  // Task type to clarify?
                  // Separate into parse, exec, and respond tasks, to show it is
                  // possible?
                  auto received_action = deserialise_action(incoming.value());
                  auto result = received_action->do_action();

                  // TODO: Add some CallObligation type to ensure this is
                  // eventually done?
                  io->from_node.push_back(std::move(result));
                },
                fmt::format("[do {}]", idx));
              tasks.add_task(std::move(task));

              incoming = io->to_node.try_pop();
            }
          }
        }

        std::this_thread::yield();
      }
    });

    for (size_t i = 0; i < num_workers; ++i)
    {
      workers.emplace_back([&, i]() {
        ccf::threading::set_current_thread_name(fmt::format("w{}", i));

        while (!stop_signal)
        {
          // Wait at-most 100ms for a task
          auto task = job_board.wait_for_task(std::chrono::milliseconds(100));
          if (task != nullptr)
          {
            task->do_task();
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