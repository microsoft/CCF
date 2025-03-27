// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "tasks/task_system.h"

#include "ccf/ds/logger.h"
#include "tasks/queues/locking_concurrent_queue.h"

#include <thread>
#include <uv.h>

namespace ccf::tasks
{
  namespace
  {
    static void do_uv_task(uv_work_t* req)
    {
      auto task = static_cast<ccf::tasks::Task*>(req->data);

      try
      {
        task->execute_task();
      }
      catch (const std::exception& e)
      {
        LOG_FAIL_FMT("Exception thrown while executing task: {}", e.what());
      }
    }

    static void after_uv_task(uv_work_t* req, int status)
    {
      auto task = static_cast<ccf::tasks::Task*>(req->data);

      try
      {
        task->after_task_cb(status == UV_ECANCELED);
      }
      catch (const std::exception& e)
      {
        LOG_FAIL_FMT(
          "Exception thrown while executing post-task callback: {}", e.what());
      }

      delete task;
      delete req;
    }

    static LockingConcurrentQueue<uv_work_t*> pending_work = {};
    static uv_async_t async_handle = {};
    static std::thread::id main_thread_id = std::this_thread::get_id();

    static void enqueue_pending_work(uv_async_t* async)
    {
      auto request_opt = pending_work.try_pop();

      while (request_opt.has_value())
      {
        uv_queue_work(
          uv_default_loop(), request_opt.value(), &do_uv_task, &after_uv_task);

        request_opt = pending_work.try_pop();
      }
    }

    static void stop_loop_cb(uv_timer_t* handle)
    {
      uv_stop(uv_default_loop());
    }
  }

  void TaskSystem::init()
  {
    uv_async_init(uv_default_loop(), &async_handle, enqueue_pending_work);
  }

  TaskHandle TaskSystem::enqueue_task(std::unique_ptr<ccf::tasks::Task>&& task)
  {
    uv_work_t* request = new uv_work_t;

    request->data = task.release();

    if (std::this_thread::get_id() == main_thread_id)
    {
      uv_queue_work(uv_default_loop(), request, &do_uv_task, &after_uv_task);
    }
    else
    {
      // uv_queue_work cannot be called directly from the thread pool, so need
      // to queue and handle later with an async.
      pending_work.push_back(request);
      uv_async_send(&async_handle);
    }

    return request;
  }

  bool TaskSystem::cancel_task(TaskHandle&& token)
  {
    auto request = reinterpret_cast<uv_req_t*>(token);
    if (request->type != UV_WORK)
    {
      throw std::logic_error(
        "The given cancellation token is not a valid uv_work handle");
    }

    const auto return_code = uv_cancel(request);
    // if (return_code != 0)
    // {
    //   fmt::print(
    //     "Unexpected return code when trying to cancel: {} {}\n",
    //     return_code,
    //     uv_strerror(return_code));
    // }
    return return_code == 0;
  }

  void TaskSystem::run_for(const std::chrono::milliseconds& s)
  {
    uv_timer_t stop_timer;

    uv_timer_init(uv_default_loop(), &stop_timer);
    uv_timer_start(&stop_timer, &stop_loop_cb, s.count(), 0);

    uv_run(uv_default_loop(), UV_RUN_DEFAULT);
  }
}