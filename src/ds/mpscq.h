// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <atomic>
#include <cassert>

namespace queue
{
  enum StateMarks
  {
    DisableMarks,
    EnableMarks
  };

  template <class T, StateMarks state_marks = DisableMarks>
  class MPSCQ
  {
  private:
    static_assert(
      std::is_same<decltype(((T*)0)->next), std::atomic<T*>>::value,
      "T->next must be a std::atomic<T*>");

    // Embedding state into last two bits.
    enum STATE
    {
      NONE = 0x0,
      EMPTY = 0x1,
      DELAY = 0x2,
      NOTIFY = 0x3,
      STATES = 0x3,
    };

    static constexpr uintptr_t MASK = (uintptr_t)~STATES;

    std::atomic<T*> head;
    T* tail;

    inline static bool has_state(T* p, STATE f)
    {
      return ((uintptr_t)p & STATES) == f;
    }

    inline static T* set_state(T* p, STATE f)
    {
      assert(is_clear(p));
      return (T*)((uintptr_t)p | f);
    }

    inline static bool is_clear(T* p)
    {
      return clear_state(p) == p;
    }

    inline static STATE get_state(T* p)
    {
      return static_cast<STATE>((uintptr_t)p & STATES);
    }

  public:
    void invariant()
    {
#ifndef NDEBUG
      assert(head != nullptr);
      assert(tail != nullptr);
#endif
    }

    // Called by actor.h
    static bool is_notify_set(T* p)
    {
      return has_state(p, NOTIFY);
    }

    // Called by actor.h
    static T* clear_state(T* p)
    {
      return (T*)((uintptr_t)p & MASK);
    }

    void init(T* stub)
    {
      stub->next.store(nullptr, std::memory_order_relaxed);
      tail = stub;

      if constexpr (state_marks == EnableMarks)
        stub = set_state(stub, EMPTY);

      head.store(stub, std::memory_order_relaxed);
      invariant();
    }

    T* destroy()
    {
      T* tl = tail;
      head.store(nullptr, std::memory_order_relaxed);
      tail = nullptr;
      return tl;
    }

    T* get_head()
    {
      return head.load(std::memory_order_relaxed);
    }

    inline bool push(T* item)
    {
      return push(item, item);
    }

    inline bool is_empty()
    {
      T* hd = head.load(std::memory_order_relaxed);

      if constexpr (state_marks == EnableMarks)
      {
        return has_state(hd, EMPTY);
      }
      else
      {
        return hd == tail;
      }
    }

    bool push(T* first, T* last)
    {
      assert(is_clear(last));

      // Pushes a list of messages to the queue. Each message from first to
      // last should be linked together through their next pointers.
      invariant();
      last->next.store(nullptr, std::memory_order_relaxed);
      std::atomic_thread_fence(std::memory_order_release);
      T* prev = head.exchange(last, std::memory_order_relaxed);
      bool was_empty;

      if constexpr (state_marks == EnableMarks)
      {
        // Pass on the notify info if set
        if (has_state(prev, NOTIFY))
        {
          first = set_state(first, NOTIFY);
        }

        was_empty = has_state(prev, EMPTY);
        prev = clear_state(prev);
      }
      else
      {
        was_empty = false;
      }

      prev->next.store(first, std::memory_order_relaxed);
      return was_empty;
    }

    std::pair<T*, T*> pop()
    {
      // Returns the next message and the tail message. If the next message
      // is not null, the tail message should be freed by the caller.
      invariant();
      T* tl = tail;
      assert(is_clear(tl));
      T* next = tl->next.load(std::memory_order_relaxed);

      if (next != nullptr)
      {
        if constexpr (state_marks == EnableMarks)
          tail = clear_state(next);
        else
          tail = next;

        assert(tail);
        std::atomic_thread_fence(std::memory_order_acquire);
      }

      invariant();
      return std::make_pair(next, tl);
    }

    T* peek()
    {
      return tail->next.load(std::memory_order_relaxed);
    }

    /**
     * State transition:
     *   NONE   -> NOTIFY; return false
     *   EMPTY  -> NOTIFY; return true
     *   DELAY  -> NOTIFY; return false
     *   NOTIFY -> NOTIFY; return false
     * Scheduling is required when the queue was EMPTY, but not other states.
     */
    bool mark_notify()
    {
      if constexpr (state_marks == EnableMarks)
      {
        auto hd = head.load(std::memory_order_relaxed);
        auto was_empty = false;

        while (true)
        {
          if (has_state(hd, NOTIFY))
          {
            break;
          }

          auto notify = set_state(clear_state(hd), NOTIFY);

          if (head.compare_exchange_strong(
                hd, notify, std::memory_order_release))
          {
            if constexpr (state_marks == EnableMarks)
              was_empty = has_state(hd, EMPTY);
            break;
          }
        }

        return was_empty;
      }
      else
      {
        return false;
      }
    }

    /**
     * State transition:
     *   NONE   -> EMPTY;  return true
     *   EMPTY  -> ABORT;  invalid input
     *   DELAY  -> NONE;   return false
     *   NOTIFY -> NONE;   return false, and set notify argument to true
     * Actor is descheduled for `NONE -> EMPTY`. Only safe to call from the
     * consumer.
     */
    bool mark_empty(bool& notify)
    {
      if constexpr (state_marks == EnableMarks)
      {
        T* tl = tail;
        T* hd = head.load(std::memory_order_relaxed);

        if (hd != tl)
        {
          switch (get_state(hd))
          {
            case NONE:
              return false;
            case EMPTY:
              // Only scheduler can call `mark_empty`, and it's impossible to
              // for scheduler to release this actor twice
              abort();
            case DELAY:
            {
              T* clear = clear_state(hd);
              head.compare_exchange_strong(
                hd, clear, std::memory_order_release);
              return false;
            }
            case NOTIFY:
            {
              notify = true;
              T* clear = clear_state(hd);
              head.compare_exchange_strong(
                hd, clear, std::memory_order_release);
              return false;
            }

            default:
              abort();
          }
        }

        hd = set_state(tl, EMPTY);
        return head.compare_exchange_strong(tl, hd, std::memory_order_release);
      }
      else
      {
        return false;
      }
    }

    /**
     * State transition:
     *   NONE   -> DELAY|Other;  return false
     *   EMPTY  -> NONE;         return true
     *   DELAY  -> DELAY;        return false
     *   NOTIFY -> NOTIFY;       return false
     * Returns whether the queue was previously marked empty or not. Actor is
     * scheduled if the queue was EMPTY. Safe to call from a producer.
     * (`Other` means that another thread beats us in CAS so we don't know for
     * sure what the state is now.)
     */
    bool mark_non_empty()
    {
      if constexpr (state_marks == EnableMarks)
      {
        T* hd = head.load(std::memory_order_relaxed);
        T* clear = clear_state(hd);
        T* delay = set_state(clear, DELAY);

        if (hd == delay)
          return false;

        if (has_state(hd, NOTIFY))
        {
          // Preserve NOTIFY bit
          return false;
        }

        if (
          (hd == clear) &&
          head.compare_exchange_strong(hd, delay, std::memory_order_release))
        {
          return false;
        }

        T* empty = set_state(clear, EMPTY);
        return head.compare_exchange_strong(
          empty, clear, std::memory_order_release);
      }
      else
      {
        return false;
      }
    }
  };
}
