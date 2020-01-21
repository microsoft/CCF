// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/logger.h"
#ifdef USE_MPSCQ
#  include "ds/mpscq.h"
#endif
#include "ds/ts.h"

#include <atomic>
#include <cstddef>

namespace enclave
{
  struct thread_msg
  {
    void (*cb)(std::unique_ptr<thread_msg>);
    std::atomic<thread_msg*> next = nullptr;
    uint64_t padding[14];
  };

  template <typename Tpayload>
  struct tmsg
  {
    tmsg(void (*_cb)(std::unique_ptr<tmsg<Tpayload>>)) :
      cb(reinterpret_cast<void (*)(std::unique_ptr<thread_msg>)>(_cb)),
      next(nullptr)
    {
      CheckInvariants();
    }

    void (*cb)(std::unique_ptr<thread_msg>);
    std::atomic<thread_msg*> next;
    union
    {
      Tpayload data;
      uint64_t padding[14];
    };

    static void CheckInvariants()
    {
      static_assert(
        sizeof(thread_msg) == sizeof(tmsg<Tpayload>), "message is too large");
      static_assert(
        sizeof(Tpayload) <= sizeof(thread_msg::padding),
        "message payload is too large");

      static_assert(
        offsetof(tmsg, cb) == offsetof(thread_msg, cb),
        "Expected cb at start of struct");
      static_assert(
        offsetof(tmsg, next) == offsetof(thread_msg, next),
        "Expected next after cb in struct");
      static_assert(
        offsetof(tmsg, data) == offsetof(thread_msg, padding),
        "Expected payload after next in struct");
    }
  };

  static void init_cb(std::unique_ptr<thread_msg> stuff)
  {
    LOG_INFO << "Init was called" << std::endl;
  }

  class Task
  {
#ifdef USE_MPSCQ
    queue::MPSCQ<thread_msg> queue;
#else
    std::atomic<thread_msg*> item_head = nullptr;
    thread_msg* local_msg = nullptr;
#endif

  public:
    Task()
    {
#ifdef USE_MPSCQ
      auto msg = new thread_msg;
      msg->cb = &init_cb;
      queue.init(msg);
#endif
    }

    bool run_next_task(bool print)
    {
#ifdef USE_MPSCQ
      if (queue.is_empty())
      {
        return false;
      }

      thread_msg* current;
      bool result;
      std::tie(current, result) = queue.dequeue();

      if (result)
      {
        current->cb(std::unique_ptr<thread_msg>(current));
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

      thread_msg* current = local_msg;
      local_msg = local_msg->next;

      current->cb(std::unique_ptr<thread_msg>(current));
#endif
      return true;
    }

    void add_task(thread_msg* item)
    {
#ifdef USE_MPSCQ
      queue.enqueue(item, item);
#else
      thread_msg* tmp_head;
      do
      {
        tmp_head = item_head.load();
        item->next = tmp_head;
      } while (!item_head.compare_exchange_strong(tmp_head, item));
#endif
    }

  private:
    void reverse_local_messages()
    {
      if (local_msg == NULL)
        return;

      thread_msg *prev = NULL, *current = NULL, *next = NULL;
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
  };

  class ThreadMessaging
  {
    std::atomic<bool> finished;
    std::vector<Task> tasks;

  public:
    static ThreadMessaging thread_messaging;
    static std::atomic<uint16_t> worker_thread_count;

  public:
    ThreadMessaging(uint16_t num_threads = 64) :
      finished(false),
      tasks(num_threads)
    {}

    void set_finished(bool v = true)
    {
      finished.store(v);
    }

    void run()
    {
      assert(tls_thread_id < tasks.size());
      Task& task = tasks[tls_thread_id];

      bool print = true;

      while (!is_finished())
      {
        task.run_next_task(print);
        print = false;
      }
    }

    bool run_one(bool print)
    {
      assert(tls_thread_id < tasks.size());
      Task& task = tasks[tls_thread_id];

      return task.run_next_task(print);
    }

    template <typename Tpayload>
    void add_task(uint16_t tid, std::unique_ptr<tmsg<Tpayload>> msg)
    {
      assert(tls_thread_id < tasks.size());
      Task& task = tasks[tid];

      task.add_task(reinterpret_cast<thread_msg*>(msg.release()));
    }

  private:
    bool is_finished()
    {
      return finished.load();
    }
  };
};
