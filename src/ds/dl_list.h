// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <cassert>
#include <type_traits>

namespace ds
{
  // Adapted from snmalloc 0.5.3.
  // Intrusive doubly-linked list. Elements added via `insert()` and
  // `insert_back()` become owned by the list (i.e. deleted on `clear()`).
  template <class T>
  class DLList final
  {
  private:
    static_assert(
      std::is_same_v<decltype(T::prev), T*>, "T->prev must be a T*");
    static_assert(
      std::is_same_v<decltype(T::next), T*>, "T->next must be a T*");

    T* head = nullptr;
    T* tail = nullptr;

  public:
    DLList() = default;

    DLList(DLList&& o) noexcept : head(o.head), tail(o.tail)
    {
      o.head = nullptr;
      o.tail = nullptr;
    }

    ~DLList()
    {
      clear();
    }

    DLList& operator=(DLList&& o) noexcept
    {
      head = o.head;
      tail = o.tail;

      o.head = nullptr;
      o.tail = nullptr;
      return *this;
    }

    bool is_empty()
    {
      return head == nullptr;
    }

    T* get_head()
    {
      return head;
    }

    T* get_tail()
    {
      return tail;
    }

    T* pop()
    {
      T* item = head;

      if (item != nullptr)
      {
        remove(item);
      }

      return item;
    }

    T* pop_tail()
    {
      T* item = tail;

      if (item != nullptr)
      {
        remove(item);
      }

      return item;
    }

    void insert(T* item)
    {
#ifndef NDEBUG
      debug_check_not_contains(item);
#endif

      item->next = head;
      item->prev = nullptr;

      if (head != nullptr)
      {
        head->prev = item;
      }
      else
      {
        tail = item;
      }

      head = item;
#ifndef NDEBUG
      debug_check();
#endif
    }

    void insert_back(T* item)
    {
#ifndef NDEBUG
      debug_check_not_contains(item);
#endif

      item->prev = tail;
      item->next = nullptr;

      if (tail != nullptr)
      {
        tail->next = item;
      }
      else
      {
        head = item;
      }

      tail = item;
#ifndef NDEBUG
      debug_check();
#endif
    }

    void remove(T* item)
    {
#ifndef NDEBUG
      debug_check_contains(item);
#endif

      if (item->next != nullptr)
      {
        item->next->prev = item->prev;
      }
      else
      {
        tail = item->prev;
      }

      if (item->prev != nullptr)
      {
        item->prev->next = item->next;
      }
      else
      {
        head = item->next;
      }

#ifndef NDEBUG
      debug_check();
#endif
    }

    void clear()
    {
      while (head != nullptr)
      {
        auto c = head;
        // The analysis does not seem to take into account that the
        // penultimate remove will result in head->next == nullptr
        // and head == nullptr on the next iteration
        // This is perhaps related to
        // https://github.com/llvm/llvm-project/issues/43395
        remove(c); // NOLINT(clang-analyzer-cplusplus.NewDelete)
        delete c; // NOLINT(cppcoreguidelines-owning-memory)
      }
    }

    void debug_check_contains(T* item)
    {
#ifndef NDEBUG
      debug_check();
      T* curr = head;

      while (curr != item)
      {
        assert(curr != nullptr);
        curr = curr->next;
      }
#else
      (void)(item);
#endif
    }

    void debug_check_not_contains(T* item)
    {
#ifndef NDEBUG
      debug_check();
      T* curr = head;

      while (curr != nullptr)
      {
        assert(curr != item);
        curr = curr->next;
      }
#else
      (void)(item);
#endif
    }

    void debug_check()
    {
#ifndef NDEBUG
      T* item = head;
      T* prev = nullptr;

      while (item != nullptr)
      {
        assert(item->prev == prev);
        prev = item;
        item = item->next;
      }
#endif
    }
  };
}