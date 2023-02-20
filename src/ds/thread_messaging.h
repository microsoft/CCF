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

  class TaskQueue
  {
    std::atomic<ThreadMsg*> item_head = nullptr;
    ThreadMsg* local_msg = nullptr;

  public:
    TaskQueue() = default;

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

      if (updated && !timer_map.empty())
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
    std::vector<TaskQueue> tasks; // Fixed-size at construction

    // Mutex guarding access to shared_task
    ccf::pal::Mutex shared_task_lock;
    // For tasks that should be shared among threads
    TaskQueue shared_task;


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

    inline TaskQueue& get_tasks(uint16_t task_id)
    {
      if (task_id >= tasks.size())
      {
        throw std::runtime_error(fmt::format(
          "Attempting to access task_id >= task_count, task_id:{}, "
          "task_count:{}",
          task_id,
          tasks.size()));
      }
      return tasks[task_id];
    }

    static std::unique_ptr<ThreadMessaging> singleton;

  public:
    static constexpr uint16_t max_num_threads = 24;

    ThreadMessaging(uint16_t num_task_queues) :
      finished(false),
      tasks(num_task_queues)
    {
      if (num_task_queues > max_num_threads)
      {
        throw std::logic_error(fmt::format(
          "ThreadMessaging constructed with too many tasks: {} > {}",
          num_task_queues,
          max_num_threads));
      }
    }

    ~ThreadMessaging()
    {
      drop_tasks();
    }

    static void init(uint16_t num_task_queues)
    {
      if (singleton != nullptr)
      {
        throw std::logic_error("Called init() multiple times");
      }

      singleton = std::make_unique<ThreadMessaging>(num_task_queues);
    }

    static ThreadMessaging& instance()
    {
      if (singleton == nullptr)
      {
        throw std::logic_error(
          "Attempted to access global ThreadMessaging instance without first "
          "calling init()");
      }

      return *singleton;
    }

    void set_finished(bool v = true)
    {
      finished.store(v);
    }

    void run()
    {
      TaskQueue& task = get_tasks(get_current_thread_id());

      while (!is_finished())
      {
        task.run_next_task();
      }
    }

    bool run_one()
    {
      TaskQueue& task = get_tasks(get_current_thread_id());
      return task.run_next_task();
    }

    template <typename Payload>
    void add_task(uint16_t tid, std::unique_ptr<Tmsg<Payload>> msg)
    {
      TaskQueue& task = get_tasks(tid);

      task.add_task(reinterpret_cast<ThreadMsg*>(msg.release()));
    }

    template <typename Payload>
    TaskQueue::TimerEntry add_task_after(
      std::unique_ptr<Tmsg<Payload>> msg, std::chrono::milliseconds ms)
    {
      TaskQueue& task = get_tasks(get_current_thread_id());
      return task.add_task_after(std::move(msg), ms);
    }

    template <typename Payload>
    TaskQueue::TimerEntry add_shared_task_after(
      std::unique_ptr<Tmsg<Payload>> msg, std::chrono::milliseconds ms)
    {
      std::lock_guard<ccf::pal::Mutex> guard(shared_task_lock);
      return shared_task.add_task_after(std::move(msg), ms);
    }

    bool cancel_timer_task(TaskQueue::TimerEntry timer_entry)
    {
      TaskQueue& task = get_tasks(get_current_thread_id());
      return task.cancel_timer_task(timer_entry);
    }

    bool cancel_shared_timer_task(TaskQueue::TimerEntry timer_entry)
    {
      std::lock_guard<ccf::pal::Mutex> guard(shared_task_lock);
      return shared_task.cancel_timer_task(timer_entry);
    }

    std::chrono::milliseconds get_current_time_offset()
    {
      TaskQueue& task = get_tasks(get_current_thread_id());
      return task.get_current_time_offset();
    }

    struct TickMsg
    {
      TickMsg(std::chrono::milliseconds elapsed_, TaskQueue& task_) :
        elapsed(elapsed_),
        task(task_)
      {}

      std::chrono::milliseconds elapsed;
      TaskQueue& task;
    };

    static void tick_cb(std::unique_ptr<Tmsg<TickMsg>> msg)
    {
      msg->data.task.tick(msg->data.elapsed);
    }

    void tick(std::chrono::milliseconds elapsed)
    {
      for (auto i = 0ul; i < tasks.size(); ++i)
      {
        auto& task = get_tasks(i);
        auto msg = std::make_unique<Tmsg<TickMsg>>(&tick_cb, elapsed, task);
        task.add_task(msg.release());
      }
    }

    uint16_t get_execution_thread(uint32_t i)
    {
      uint16_t tid = MAIN_THREAD_ID;
      if (tasks.size() > 1)
      {
        // If we have multiple task queues, then we distinguish the main thread
        // from the remaining workers; anything asking for an execution thread
        // does _not_ go to the main thread's queue
        tid = (i % (tasks.size() - 1));
        ++tid;
      }

      return tid;
    }

    uint16_t thread_count() const
    {
      return tasks.size();
    }

  private:
    bool is_finished()
    {
      return finished.load();
    }
  };
};
