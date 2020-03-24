// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "../kv.h"
#include "../kv_serialiser.h"
#include "ds/logger.h"
#include "enclave/app_interface.h"

#define DOCTEST_CONFIG_NO_SHORT_MACRO_NAMES

#include <atomic>
#include <chrono>
#include <doctest/doctest.h>
#include <string>
#include <thread>
#include <vector>

using namespace ccf;

DOCTEST_TEST_CASE("Concurrent kv access" * doctest::test_suite("concurrency"))
{
  logger::config::level() = logger::INFO;

  // Multiple threads write random entries into random tables, and attempt to
  // commit them. A single thread continually compacts the kv to the latest
  // entry. The goal is for these commits and compactions to avoid deadlock
  Store kv_store;

  using MapType = Store::Map<size_t, size_t>;
  constexpr size_t max_k = 32;

  constexpr size_t thread_count = 16;
  std::thread tx_threads[thread_count] = {};

  constexpr size_t tx_count = 100;
  constexpr size_t tx_size = 100;

  // Keep atomic count of running threads
  std::atomic<size_t> active_tx_threads(thread_count);

  struct ThreadArgs
  {
    std::vector<MapType*> maps;
    Store* kv_store;
    std::atomic<size_t>* counter;
  };
  ThreadArgs args[thread_count] = {};

  srand(42);
  constexpr size_t map_count = 8;
  for (size_t i = 0u; i < map_count; ++i)
  {
    const auto name = std::to_string(i);
    auto& map = kv_store.create<MapType>(name, kv::SecurityDomain::PUBLIC);

    // Every thread gets the first map, and a random half of the others
    for (size_t j = 0u; j < thread_count; ++j)
    {
      if (i == 0u || rand() % 2)
      {
        args[j].maps.push_back(&map);
      }
    }
  }

  auto thread_fn = [](void* a) {
    auto args = static_cast<ThreadArgs*>(a);

    for (size_t i = 0u; i < tx_count; ++i)
    {
      // Generate a set of random reads and writes across our maps
      std::vector<std::tuple<size_t, size_t, size_t, size_t>> writes;
      for (size_t j = 0u; j < tx_size; ++j)
      {
        writes.push_back({rand() % args->maps.size(),
                          rand() % max_k,
                          rand() % args->maps.size(),
                          rand() % max_k});
      }

      // Keep trying until you're able to commit it
      while (true)
      {
        // Start a transaction over selected maps
        Store::Tx tx;

        std::vector<MapType::TxView*> views;
        for (const auto map : args->maps)
        {
          views.push_back(tx.get_view(*map));
        }

        for (const auto& [from_map, from_k, to_map, to_k] : writes)
        {
          auto from_view = views[from_map];
          const auto v = from_view->get(from_k).value_or(from_k);

          auto to_view = views[to_map];
          to_view->put(to_k, v);
        }

        // Yield now, to increase the chance of conflicts
        std::this_thread::yield();

        // Try to commit
        const auto result = tx.commit();
        if (result == kv::CommitSuccess::OK)
        {
          break;
        }
      }
    }

    // Notify that this thread has finished
    --*args->counter;
  };

  // Start a thread which continually compacts at the latest version, until all
  // tx_threads have finished
  std::thread compact_thread;
  enum CompacterState
  {
    NotStarted,
    Running,
    Done
  };
  std::atomic<CompacterState> compact_state(NotStarted);

  struct CompactArgs
  {
    Store* kv_store;
    std::atomic<size_t>* tx_counter;
    decltype(compact_state)* compact_state;
  } ca{&kv_store, &active_tx_threads, &compact_state};

  // Start compact thread
  {
    compact_thread = std::thread(
      [](void* a) {
        auto ca = static_cast<CompactArgs*>(a);
        auto& store = *ca->kv_store;

        ca->compact_state->store(Running);

        while (ca->tx_counter->load() > 0)
        {
          store.compact(store.current_version());
        }

        // Ensure store is compacted one last time _after_ all threads have
        // finished
        store.compact(store.current_version());

        ca->compact_state->store(Done);
      },
      &ca);
  }

  const auto initial_version = kv_store.commit_version();

  // Start tx threads
  for (size_t i = 0u; i < thread_count; ++i)
  {
    args[i].kv_store = &kv_store;
    args[i].counter = &active_tx_threads;

    tx_threads[i] = std::thread(thread_fn, &args[i]);
  }

  // Wait for the compact thread to start
  while (compact_state.load() == NotStarted)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }

  // Wait for the compact thread to finish, with an overall timeout to detect
  // deadlock
  using Clock = std::chrono::system_clock;
  const auto start = Clock::now();
  const auto timeout = std::chrono::seconds(30);
  while (compact_state.load() == Running)
  {
    const auto elapsed = Clock::now() - start;
    DOCTEST_REQUIRE(elapsed < timeout);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }

  DOCTEST_REQUIRE(compact_state.load() == Done);

  // Sanity check that all transactions were compacted
  const auto now_compacted = kv_store.commit_version();
  DOCTEST_REQUIRE(now_compacted > initial_version);
  const auto expected = initial_version + (tx_count * thread_count);
  DOCTEST_REQUIRE(now_compacted == expected);

  // Wait for tx threads to complete
  for (size_t i = 0u; i < thread_count; ++i)
  {
    tx_threads[i].join();
  }

  // Wait for compact thread to complete
  {
    compact_thread.join();
  }
}
