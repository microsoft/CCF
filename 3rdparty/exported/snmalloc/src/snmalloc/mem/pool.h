#pragma once

#include "../ds/ds.h"
#include "pooled.h"

#include <new>

namespace snmalloc
{
  /**
   * Pool of a particular type of object.
   *
   * This pool will never return objects to the OS.  It maintains a list of all
   * objects ever allocated that can be iterated (not concurrency safe).  Pooled
   * types can be acquired from the pool, and released back to the pool. This is
   * concurrency safe.
   *
   * This is used to bootstrap the allocation of allocators.
   */
  template<class T>
  class PoolState
  {
    template<
      typename TT,
      SNMALLOC_CONCEPT(IsConfig) Config,
      PoolState<TT>& get_state()>
    friend class Pool;

  private:
    // Queue of elements in not currently in use
    // Must hold lock to modify
    capptr::Alloc<T> front{nullptr};
    capptr::Alloc<T> back{nullptr};

    FlagWord lock{};
    capptr::Alloc<T> list{nullptr};

  public:
    constexpr PoolState() = default;
  };

  /**
   * Helper class used to instantiate a global PoolState.
   *
   * SingletonPoolState::pool is the default provider for the PoolState within
   * the Pool class.
   */
  template<typename T, SNMALLOC_CONCEPT(IsConfig) Config>
  class SingletonPoolState
  {
    /**
     * SFINAE helper.  Matched only if `T` implements `ensure_init`.  Calls it
     * if it exists.
     */
    template<typename SharedStateHandle_>
    SNMALLOC_FAST_PATH static auto call_ensure_init(SharedStateHandle_*, int)
      -> decltype(SharedStateHandle_::ensure_init())
    {
      static_assert(
        std::is_same<Config, SharedStateHandle_>::value,
        "SFINAE parameter, should only be used with Config");
      SharedStateHandle_::ensure_init();
    }

    /**
     * SFINAE helper.  Matched only if `T` does not implement `ensure_init`.
     * Does nothing if called.
     */
    template<typename SharedStateHandle_>
    SNMALLOC_FAST_PATH static auto call_ensure_init(SharedStateHandle_*, long)
    {
      static_assert(
        std::is_same<Config, SharedStateHandle_>::value,
        "SFINAE parameter, should only be used with Config");
    }

    /**
     * Call `Config::ensure_init()` if it is implemented, do nothing
     * otherwise.
     */
    SNMALLOC_FAST_PATH static void ensure_init()
    {
      call_ensure_init<Config>(nullptr, 0);
    }

    static void make_pool(PoolState<T>*) noexcept
    {
      ensure_init();
      // Default initializer already called on PoolState, no need to use
      // placement new.
    }

  public:
    /**
     * Returns a reference for the global PoolState for the given type.
     * Also forces the initialization of the backend state, if needed.
     */
    SNMALLOC_FAST_PATH static PoolState<T>& pool()
    {
      return Singleton<PoolState<T>, &make_pool>::get();
    }
  };

  /**
   * Wrapper class to access a pool of a particular type of object.
   *
   * The third template argument is a method to retrieve the actual PoolState.
   *
   * For the pool of allocators, refer to the AllocPool alias defined in
   * corealloc.h.
   *
   * For a pool of another type, it is recommended to leave the
   * third template argument with its default value. The SingletonPoolState
   * class is used as a helper to provide a default PoolState management for
   * this use case.
   */
  template<
    typename T,
    SNMALLOC_CONCEPT(IsConfig) Config,
    PoolState<T>& get_state() = SingletonPoolState<T, Config>::pool>
  class Pool
  {
  public:
    template<typename... Args>
    static T* acquire(Args&&... args)
    {
      PoolState<T>& pool = get_state();
      {
        FlagLock f(pool.lock);
        if (pool.front != nullptr)
        {
          auto p = pool.front;
          auto next = p->next;
          if (next == nullptr)
          {
            pool.back = nullptr;
          }
          pool.front = next;
          p->set_in_use();
          return p.unsafe_ptr();
        }
      }

      auto raw =
        Config::Backend::template alloc_meta_data<T>(nullptr, sizeof(T));

      if (raw == nullptr)
      {
        Config::Pal::error("Failed to initialise thread local allocator.");
      }

      auto p = capptr::Alloc<T>::unsafe_from(new (raw.unsafe_ptr())
                                               T(std::forward<Args>(args)...));

      FlagLock f(pool.lock);
      p->list_next = pool.list;
      pool.list = p;

      p->set_in_use();
      return p.unsafe_ptr();
    }

    /**
     * Return to the pool an object previously retrieved by `acquire`
     *
     * Do not return objects from `extract`.
     */
    static void release(T* p)
    {
      // The object's destructor is not run. If the object is "reallocated", it
      // is returned without the constructor being run, so the object is reused
      // without re-initialisation.
      p->reset_in_use();
      restore(p, p);
    }

    static T* extract(T* p = nullptr)
    {
      PoolState<T>& pool = get_state();
      // Returns a linked list of all objects in the stack, emptying the stack.
      if (p == nullptr)
      {
        FlagLock f(pool.lock);
        auto result = pool.front;
        pool.front = nullptr;
        pool.back = nullptr;
        return result.unsafe_ptr();
      }

      return p->next.unsafe_ptr();
    }

    /**
     * Return to the pool a list of object previously retrieved by `extract`
     *
     * Do not return objects from `acquire`.
     */
    static void restore(T* first, T* last)
    {
      PoolState<T>& pool = get_state();
      last->next = nullptr;
      FlagLock f(pool.lock);

      if (pool.front == nullptr)
      {
        pool.front = capptr::Alloc<T>::unsafe_from(first);
      }
      else
      {
        pool.back->next = capptr::Alloc<T>::unsafe_from(first);
      }

      pool.back = capptr::Alloc<T>::unsafe_from(last);
    }

    /**
     * Return to the pool a list of object previously retrieved by `extract`
     *
     * Do not return objects from `acquire`.
     */
    static void restore_front(T* first, T* last)
    {
      PoolState<T>& pool = get_state();
      last->next = nullptr;
      FlagLock f(pool.lock);

      if (pool.front == nullptr)
      {
        pool.back = capptr::Alloc<T>::unsafe_from(last);
      }
      else
      {
        last->next = pool.front;
        pool.back->next = capptr::Alloc<T>::unsafe_from(first);
      }
      pool.front = capptr::Alloc<T>::unsafe_from(first);
    }

    static T* iterate(T* p = nullptr)
    {
      if (p == nullptr)
        return get_state().list.unsafe_ptr();

      return p->list_next.unsafe_ptr();
    }

    /**
     * Put the stack in a consistent order.  This is helpful for systematic
     * testing based systems. It is not thread safe, and the caller should
     * ensure no other thread can be performing a `sort` concurrently with this
     * call.
     */
    static void sort()
    {
      // Marker is used to signify free elements.
      auto marker = capptr::Alloc<T>::unsafe_from(reinterpret_cast<T*>(1));

      // Extract all the elements and mark them as free.
      T* curr = extract();
      T* prev = nullptr;
      while (curr != nullptr)
      {
        prev = curr;
        curr = extract(curr);
        // Assignment must occur after extract, otherwise extract would read the
        // marker
        prev->next = marker;
      }

      // Build a list of the free elements in the correct order.
      // This is the opposite order to the list of all elements
      // so that iterate works correctly.
      curr = iterate();
      while (curr != nullptr)
      {
        if (curr->next == marker)
        {
          restore_front(curr, curr);
        }
        curr = iterate(curr);
      }
    }
  };
} // namespace snmalloc
