// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

//#define USE_MPSCQ

#include "ds/logger.h"
#ifdef USE_MPSCQ
#  include "snmalloc/src/ds/mpscq.h"
#endif

#include <atomic>
#include <cstddef>
#include <map>
#include <thread>

extern std::map<std::thread::id, uint16_t> thread_ids;

namespace enclave
{
  struct ThreadMsg
  {
    void (*cb)(std::unique_ptr<ThreadMsg>);
    std::atomic<ThreadMsg*> next = nullptr;

    ThreadMsg(void (*_cb)(std::unique_ptr<ThreadMsg>)) : cb(_cb) {}

    virtual ~ThreadMsg() = default;
  };

  template <typename Payload>
  struct alignas(16) Tmsg : public ThreadMsg
  {
    Payload data;

    template <typename... Args>
    Tmsg(void (*_cb)(std::unique_ptr<Tmsg<Payload>>), Args&&... args) :
      ThreadMsg(reinterpret_cast<void (*)(std::unique_ptr<ThreadMsg>)>(_cb)),
      data(std::forward<Args>(args)...)
    {}

    virtual ~Tmsg() = default;
  };

  static void init_cb(std::unique_ptr<ThreadMsg> m)
  {
    LOG_INFO_FMT("Init was called");
  }

  class Task
  {
#ifdef USE_MPSCQ
    queue::MPSCQ<ThreadMsg> queue;
#else
    std::atomic<ThreadMsg*> item_head = nullptr;
    ThreadMsg* local_msg = nullptr;
#endif

  public:
    Task()
    {
#ifdef USE_MPSCQ
      auto msg = new ThreadMsg;
      msg->cb = &init_cb;
      queue.init(msg);
#endif
    }

    bool run_next_task()
    {
#ifdef USE_MPSCQ
      if (queue.is_empty())
      {
        return false;
      }

      ThreadMsg* current;
      bool result;
      std::tie(current, result) = queue.dequeue();

      if (result)
      {
        current->cb(std::unique_ptr<ThreadMsg>(current));
      }
#else
      if (local_msg == nullptr && item_head != nullptr)
      {
        local_msg = item_head.exchange(nullptr);
        reverse_local_messages();
      }

      if (local_msg == nullptr)
      {
        return false;
      }

      ThreadMsg* current = local_msg;
      local_msg = local_msg->next;

      current->cb(std::unique_ptr<ThreadMsg>(current));
#endif
      return true;
    }

    void add_task(ThreadMsg* item)
    {
#ifdef USE_MPSCQ
      queue.enqueue(item, item);
#else
      ThreadMsg* tmp_head;
      do
      {
        tmp_head = item_head.load();
        item->next = tmp_head;
      } while (!item_head.compare_exchange_strong(tmp_head, item));
#endif
    }

  private:
#ifndef USE_MPSCQ
    void reverse_local_messages()
    {
      if (local_msg == NULL)
        return;

      ThreadMsg *prev = NULL, *current = NULL, *next = NULL;
      current = local_msg;
      while (current != NULL)
      {
        next = current->next;
        current->next = prev;
        prev = current;
        current = next;
      }
      // now let the head point at the last node (prev)
      local_msg = prev;
    }
#endif
  };

  class ThreadMessaging
  {
    std::atomic<bool> finished;
    std::vector<Task> tasks;

  public:
    static ThreadMessaging thread_messaging;
    static std::atomic<uint16_t> thread_count;
    static const uint16_t main_thread = 0;

    static const uint16_t max_num_threads = 24;

  public:
    ThreadMessaging(uint16_t num_threads = max_num_threads) :
      finished(false),
      tasks(num_threads)
    {}

    void set_finished(bool v = true)
    {
      finished.store(v);
    }

    void run()
    {
      Task& task = tasks[thread_ids[std::this_thread::get_id()]];

      while (!is_finished())
      {
        task.run_next_task();
      }
    }

    Task& get_task(uint16_t tid)
    {
      return tasks[tid];
    }

    bool run_one(Task& task)
    {
      return task.run_next_task();
    }

    template <typename Payload>
    void add_task(uint16_t tid, std::unique_ptr<Tmsg<Payload>> msg)
    {
      Task& task = tasks[tid];

      task.add_task(reinterpret_cast<ThreadMsg*>(msg.release()));
    }

    uint16_t get_thread_id()
    {
      return thread_ids[std::this_thread::get_id()];
    }

    static uint16_t get_execution_thread(uint32_t i)
    {
      uint16_t tid = 0;
      if (enclave::ThreadMessaging::thread_count > 1)
      {
        tid = (i % (enclave::ThreadMessaging::thread_count - 1));
        ++tid;
      }

      return tid;
    }

    template <typename Payload>
    static void ChangeTmsgCallback(
      std::unique_ptr<Tmsg<Payload>>& msg,
      void (*cb_)(std::unique_ptr<Tmsg<Payload>>))
    {
      msg->cb = (reinterpret_cast<void (*)(std::unique_ptr<ThreadMsg>)>(cb_));
    }

  private:
    bool is_finished()
    {
      return finished.load();
    }
  };
};
