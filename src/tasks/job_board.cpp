// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "tasks/job_board.h"

namespace ccf::tasks
{
  struct Consumer
  {
    Task& task;
    std::condition_variable& cv;
  };

  struct JobBoard::PImpl
  {
    std::mutex mutex;
    std::queue<Task> pending_tasks;
    std::vector<Consumer*> waiting_consumers;

    void add_task(Task&& task)
    {
      std::unique_lock<std::mutex> lock(mutex);

      for (Consumer* consumer : waiting_consumers)
      {
        // NB: Although waiting_consumers is modified under lock, it's possible
        // that another call to add_task arrives the notified thread wakes up
        // and removes itself from this collection. In this case we must avoid
        // overwriting a previously-assigned task.
        if (consumer->task == nullptr)
        {
          consumer->task = std::move(task);
          consumer->cv.notify_one();
          return;
        }
      }

      // There are no waiting_consumers currently, or none waiting for a task
      pending_tasks.emplace(std::move(task));
    }

    Task get_task()
    {
      using namespace std::chrono_literals;
      return wait_for_task(0ms);
    }

    Task wait_for_task(const std::chrono::milliseconds& timeout)
    {
      Task to_return = nullptr;

      {
        std::unique_lock<std::mutex> lock(mutex);

        if (pending_tasks.empty())
        {
          std::condition_variable cv;
          Consumer* consumer = new Consumer{to_return, cv};
          waiting_consumers.push_back(consumer);

          cv.wait_for(lock, timeout);

          // TODO: What if this resume happens after destructor? Do we need to
          // extend lifetime of PImpl?
          auto it = std::find(
            waiting_consumers.begin(), waiting_consumers.end(), consumer);
          waiting_consumers.erase(it);

          delete consumer;
        }
        else
        {
          to_return = pending_tasks.front();
          pending_tasks.pop();
        }
      }
      return to_return;
    }
  };

  JobBoard::JobBoard() : pimpl(std::make_unique<PImpl>()) {}

  JobBoard::~JobBoard() = default;

  void JobBoard::add_task(Task&& task)
  {
    pimpl->add_task(std::move(task));
  }

  Task JobBoard::get_task()
  {
    return pimpl->get_task();
  }

  // TODO: Remove?
  bool JobBoard::empty()
  {
    std::lock_guard<std::mutex> lock(pimpl->mutex);
    return pimpl->pending_tasks.empty();
  }

  Task JobBoard::wait_for_task(const std::chrono::milliseconds& timeout)
  {
    return pimpl->wait_for_task(timeout);
  }
}
