// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "../kv.h"
#include "../kvserialiser.h"
#include "ds/logger.h"
#include "enclave/appinterface.h"

#include <atomic>
#include <chrono>
#include <doctest/doctest.h>
#include <string>
#include <thread>
#include <vector>

using namespace ccf;

TEST_CASE("Concurrent kv access" * doctest::test_suite("concurrency"))
{
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
        args[j].maps.push_back(&map);
    }
  }

  auto thread_fn = [](void* a) {
    auto args = static_cast<ThreadArgs*>(a);

    for (size_t i = 0u; i < tx_count; ++i)
    {
      // Start a transaction over selected maps
      Store::Tx tx;

      std::vector<MapType::TxView*> views;
      for (const auto map : args->maps)
        views.push_back(tx.get_view(*map));

      // Write random ks and vs to random maps
      for (size_t j = 0u; j < tx_size; ++j)
        views[rand() % views.size()]->put(rand() % max_k, rand());

      // Try to commit, don't actually care if it succeeds
      tx.commit();
    }

    --*args->counter;
  };

  // Start a thread which continually compacts at the latest version, until all
  // tx_threads have finished
  std::thread compact_thread;
  std::atomic<size_t> compact_state(0); // 3 states: not started, running, done

  struct CompactArgs
  {
    Store* kv_store;
    std::atomic<size_t>* tx_counter;
    std::atomic<size_t>* compact_state;
  } ca{&kv_store, &active_tx_threads, &compact_state};

  // Start compact thread
  {
    compact_thread = std::thread(
      [](void* a) {
        auto ca = static_cast<CompactArgs*>(a);
        auto& store = *ca->kv_store;

        ca->compact_state->store(1);

        while (ca->tx_counter->load() > 0)
        {
          store.compact(store.current_version());
        }

        ca->compact_state->store(2);
      },
      &ca);
  }

  // Start tx threads
  for (size_t i = 0u; i < thread_count; ++i)
  {
    args[i].kv_store = &kv_store;
    args[i].counter = &active_tx_threads;

    tx_threads[i] = std::thread(thread_fn, &args[i]);
  }

  // Simple watchdog loop on this main thread. Wait for the compact thread to
  // start, and then it has either completed or it is still running and
  // increasing the compacted version
  while (compact_state.load() == 0)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }

  auto last_compacted = kv_store.commit_version();
  while (compact_state.load() == 1)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(400));
    auto now_compacted = kv_store.commit_version();
    REQUIRE(now_compacted > last_compacted);
    last_compacted = now_compacted;
  }

  REQUIRE(compact_state.load() == 2);

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
