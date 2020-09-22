// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

//#define USE_MPSCQ

#include "ds/ccf_assert.h"
#include "ds/logger.h"
#include "ds/thread_ids.h"
#ifdef USE_MPSCQ
#  include "snmalloc/src/ds/mpscq.h"
#endif

#include <atomic>
#include <chrono>
#include <cstddef>

namespace threading
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

#ifdef USE_MPSCQ
  static void init_cb(std::unique_ptr<ThreadMsg> m)
  {
    LOG_INFO_FMT("Init was called");
  }
#endif

  class ThreadMessaging;

  class Task
  {
#ifdef USE_MPSCQ
    queue::MPSCQ<ThreadMsg> queue;
#else
    std::atomic<ThreadMsg*> item_head = nullptr;
    ThreadMsg* local_msg = nullptr;
#endif

    struct TimerEntry
    {
      std::chrono::milliseconds time_offset;
      uint64_t counter;
    };

    struct TimerEntryCompare
    {
      bool operator()(const TimerEntry& lhs, const TimerEntry& rhs) const
      {
        if (lhs.time_offset != rhs.time_offset)
        {
          return lhs.time_offset < rhs.time_offset;
        }

        return lhs.counter < rhs.counter;
      }
    };

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

    TimerEntry add_task_after(
      std::unique_ptr<ThreadMsg> item, std::chrono::milliseconds ms)
    {
      TimerEntry entry = {time_offset + ms, time_entry_counter++};
      timer_map.emplace(entry, std::move(item));
      return entry;
    }

    bool cancel_timer_task(TimerEntry timer_entry)
    {
      auto num_erased = timer_map.erase(timer_entry);
      CCF_ASSERT(num_erased <= 1, "Too many items erased");
      return num_erased != 0;
    }

    void tick(std::chrono::milliseconds elapsed)
    {
      time_offset += elapsed;

      while (!timer_map.empty() &&
             timer_map.begin()->first.time_offset <= time_offset)
      {
        auto it = timer_map.begin();

        auto& cb = it->second->cb;
        auto msg = std::move(it->second);
        timer_map.erase(it);
        cb(std::move(msg));
      }
    }

  private:
    std::chrono::milliseconds time_offset;
    uint64_t time_entry_counter = 0;
    std::map<TimerEntry, std::unique_ptr<ThreadMsg>, TimerEntryCompare>
      timer_map;

#ifndef USE_MPSCQ
    void reverse_local_messages()
    {
      if (local_msg == nullptr)
        return;

      ThreadMsg *prev = nullptr, *current = nullptr, *next = nullptr;
      current = local_msg;
      while (current != nullptr)
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

    void drop()
    {
#ifdef USE_MPSCQ
      while (!queue.is_empty())
      {
        ThreadMsg* current;
        bool result;
        std::tie(current, result) = queue.dequeue();
        if (result)
        {
          delete current;
        }
      }
#else
      while (true)
      {
        if (local_msg == nullptr && item_head != nullptr)
        {
          local_msg = item_head.exchange(nullptr);
          reverse_local_messages();
        }

        if (local_msg == nullptr)
        {
          break;
        }

        ThreadMsg* current = local_msg;
        local_msg = local_msg->next;
        delete current;
      }
#endif
    }

    friend ThreadMessaging;
  };

  class ThreadMessaging
  {
    std::atomic<bool> finished;
    std::vector<Task> tasks;

  public:
    static ThreadMessaging thread_messaging;
    static std::atomic<uint16_t> thread_count;
    static const uint16_t main_thread = MAIN_THREAD_ID;

    static const uint16_t max_num_threads = 24;

    ThreadMessaging(uint16_t num_threads = max_num_threads) :
      finished(false),
      tasks(num_threads)
    {}

    // Drop all pending tasks, this is only ever to be used
    // on shutdown, to avoid leaks, and after all thread but
    // the main one have been shut down.
    void drop_tasks()
    {
      for (auto& t : tasks)
      {
        t.drop();
      }
    }

    void set_finished(bool v = true)
    {
      finished.store(v);
    }

    void run()
    {
      Task& task = get_task(get_current_thread_id());

      while (!is_finished())
      {
        task.run_next_task();
      }
    }

    inline Task& get_task(uint16_t tid)
    {
      CCF_ASSERT_FMT(
        tid <= thread_count,
        "Attempting to add task to tid > thread_count, tid:{}, thread_count:{}",
        tid,
        thread_count);
      return tasks[tid];
    }

    bool run_one(Task& task)
    {
      return task.run_next_task();
    }

    template <typename Payload>
    void add_task(uint16_t tid, std::unique_ptr<Tmsg<Payload>> msg)
    {
      Task& task = get_task(tid);

      task.add_task(reinterpret_cast<ThreadMsg*>(msg.release()));
    }

    template <typename Payload>
    void add_task_after(
      std::unique_ptr<Tmsg<Payload>> msg, std::chrono::milliseconds ms)
    {
      Task& task = get_task(get_current_thread_id());
      task.add_task_after(std::move(msg), ms);
    }

    struct TickMsg
    {
      TickMsg(std::chrono::milliseconds elapsed_, Task& task_) :
        elapsed(elapsed_),
        task(task_)
      {}

      std::chrono::milliseconds elapsed;
      Task& task;
    };

    static void tick_cb(std::unique_ptr<Tmsg<TickMsg>> msg)
    {
      msg->data.task.tick(msg->data.elapsed);
    }

    void tick(std::chrono::milliseconds elapsed)
    {
      for (auto i = 0; i < thread_count; ++i)
      {
        auto& task = get_task(i);
        auto msg = std::make_unique<Tmsg<TickMsg>>(&tick_cb, elapsed, task);
        task.add_task(msg.release());
      }
    }

    static uint16_t get_execution_thread(uint32_t i)
    {
      uint16_t tid = MAIN_THREAD_ID;
      if (thread_count > 1)
      {
        tid = (i % (thread_count - 1));
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
