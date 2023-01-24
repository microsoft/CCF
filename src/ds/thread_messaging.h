// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ccf_assert.h"
#include "ccf/ds/logger.h"
#include "ccf/ds/thread_ids.h"

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

    void reset_cb(void (*_cb)(std::unique_ptr<Tmsg<Payload>>))
    {
      cb = reinterpret_cast<void (*)(std::unique_ptr<ThreadMsg>)>(_cb);
    }

    virtual ~Tmsg() = default;
  };

  class ThreadMessaging;

  class Task
  {
    std::atomic<ThreadMsg*> item_head = nullptr;
    ThreadMsg* local_msg = nullptr;

  public:
    Task() = default;

    bool run_next_task()
    {
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
      return true;
    }

    void add_task(ThreadMsg* item)
    {
      ThreadMsg* tmp_head;
      do
      {
        tmp_head = item_head.load();
        item->next = tmp_head;
      } while (!item_head.compare_exchange_strong(tmp_head, item));
    }

    struct TimerEntry
    {
      TimerEntry() : time_offset(0), counter(0) {}
      TimerEntry(std::chrono::milliseconds time_offset_, uint64_t counter_) :
        time_offset(time_offset_),
        counter(counter_)
      {}

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

    TimerEntry add_task_after(
      std::unique_ptr<ThreadMsg> item, std::chrono::milliseconds ms)
    {
      TimerEntry entry = {time_offset + ms, time_entry_counter++};
      if (timer_map.empty() || entry.time_offset <= next_time_offset)
      {
        next_time_offset = entry.time_offset;
      }

      timer_map.emplace(entry, std::move(item));
      return entry;
    }

    bool cancel_timer_task(TimerEntry timer_entry)
    {
      auto num_erased = timer_map.erase(timer_entry);
      CCF_ASSERT(num_erased <= 1, "Too many items erased");
      if (!timer_map.empty() && timer_entry.time_offset <= next_time_offset)
      {
        next_time_offset = timer_map.begin()->first.time_offset;
      }
      return num_erased != 0;
    }

    void tick(std::chrono::milliseconds elapsed)
    {
      time_offset += elapsed;

      bool updated = false;

      while (!timer_map.empty() && next_time_offset <= time_offset &&
             timer_map.begin()->first.time_offset <= time_offset)
      {
        updated = true;
        auto it = timer_map.begin();

        auto& cb = it->second->cb;
        auto msg = std::move(it->second);
        timer_map.erase(it);
        cb(std::move(msg));
      }

      if (updated)
      {
        next_time_offset = timer_map.begin()->first.time_offset;
      }
    }

    std::chrono::milliseconds get_current_time_offset()
    {
      return time_offset;
    }

  private:
    std::chrono::milliseconds time_offset = std::chrono::milliseconds(0);
    uint64_t time_entry_counter = 0;
    std::map<TimerEntry, std::unique_ptr<ThreadMsg>, TimerEntryCompare>
      timer_map;
    std::chrono::milliseconds next_time_offset;

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

    void drop()
    {
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
    }

    friend ThreadMessaging;
  };

  class ThreadMessaging
  {
    std::atomic<bool> finished;
    std::vector<Task> tasks;

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

  public:
    static ThreadMessaging thread_messaging;
    static std::atomic<uint16_t> thread_count;

    static const uint16_t max_num_threads = 24;

    ThreadMessaging(uint16_t num_threads = max_num_threads) :
      finished(false),
      tasks(num_threads)
    {}

    ~ThreadMessaging()
    {
      drop_tasks();
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
      if (tid >= tasks.size())
      {
        throw std::runtime_error(fmt::format(
          "Attempting to add task to tid >= thread_count, tid:{}, "
          "thread_count:{}",
          tid,
          tasks.size()));
      }
      return tasks[tid];
    }

    bool run_one()
    {
      Task& task = get_task(get_current_thread_id());
      return task.run_next_task();
    }

    template <typename Payload>
    void add_task(uint16_t tid, std::unique_ptr<Tmsg<Payload>> msg)
    {
      Task& task = get_task(tid);

      task.add_task(reinterpret_cast<ThreadMsg*>(msg.release()));
    }

    template <typename Payload>
    Task::TimerEntry add_task_after(
      std::unique_ptr<Tmsg<Payload>> msg, std::chrono::milliseconds ms)
    {
      Task& task = get_task(get_current_thread_id());
      return task.add_task_after(std::move(msg), ms);
    }

    bool cancel_timer_task(Task::TimerEntry timer_entry)
    {
      Task& task = get_task(get_current_thread_id());
      return task.cancel_timer_task(timer_entry);
    }

    std::chrono::milliseconds get_current_time_offset()
    {
      Task& task = get_task(get_current_thread_id());
      return task.get_current_time_offset();
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
