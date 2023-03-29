// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ccf/ds/logger.h"
#include "kv/compacted_version_conflict.h"
#include "kv/kv_serialiser.h"
#include "kv/store.h"
#include "kv/test/null_encryptor.h"
#include "kv/test/stub_consensus.h"

#include <atomic>
#include <chrono>
#define DOCTEST_CONFIG_NO_SHORT_MACRO_NAMES

#include <doctest/doctest.h>
#include <string>
#include <thread>
#include <vector>

class SlowStubConsensus : public kv::test::StubConsensus
{
public:
  using kv::test::StubConsensus::StubConsensus;

  bool replicate(const kv::BatchVector& entries, ccf::View view) override
  {
    if (rand() % 2 == 0)
    {
      const auto delay = rand() % 5;
      std::this_thread::sleep_for(std::chrono::milliseconds(delay));
    }

    return kv::test::StubConsensus::replicate(entries, view);
  }
};

DOCTEST_TEST_CASE("Concurrent kv access" * doctest::test_suite("concurrency"))
{
  logger::config::level() = logger::INFO;

  // Multiple threads write random entries into random tables, and attempt to
  // commit them. A single thread continually compacts the kv to the latest
  // entry. The goal is for these commits and compactions to avoid deadlock

  using MapType = kv::Map<size_t, size_t>;
  constexpr size_t max_k = 32;

  constexpr size_t thread_count = 16;
  std::thread tx_threads[thread_count] = {};

  constexpr size_t tx_count = 10;
  constexpr size_t tx_size = 100;

  struct ThreadArgs
  {
    std::vector<MapType> maps;
    kv::Store* kv_store;
    std::atomic<size_t>* counter;
  };
  ThreadArgs args[thread_count] = {};

  const auto seed = time(NULL);
  DOCTEST_INFO("Using seed: ", seed);
  srand(seed);

  constexpr size_t map_count = 8;
  for (size_t i = 0u; i < map_count; ++i)
  {
    const auto name = fmt::format("public:{}", i);
    MapType map(name);

    // Every thread gets the first map, and a random half of the others
    for (size_t j = 0u; j < thread_count; ++j)
    {
      if (i == 0u || rand() % 2)
      {
        args[j].maps.push_back(map);
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
        writes.push_back(
          {rand() % args->maps.size(),
           rand() % max_k,
           rand() % args->maps.size(),
           rand() % max_k});
      }

      // Keep trying until you're able to commit it
      while (true)
      {
        try
        {
          // Start a transaction over selected maps
          auto tx = args->kv_store->create_tx();

          std::vector<MapType::Handle*> handles;
          for (const auto& map : args->maps)
          {
            handles.push_back(tx.rw(map));
          }

          for (const auto& [from_map, from_k, to_map, to_k] : writes)
          {
            auto from_handle = handles[from_map];
            const auto v = from_handle->get(from_k).value_or(from_k);

            auto to_handle = handles[to_map];
            to_handle->put(to_k, v);
          }

          // Yield now, to increase the chance of conflicts
          std::this_thread::yield();

          // Try to commit
          const auto result = tx.commit();
          if (result == kv::CommitResult::SUCCESS)
          {
            break;
          }
        }
        catch (const kv::CompactedVersionConflict& e)
        {
          // Retry on conflict
          continue;
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

  struct CompactArgs
  {
    kv::Store* kv_store;
    std::atomic<size_t>* tx_counter;
    std::atomic<CompacterState>* compact_state;
  };

  static constexpr auto iterations = 20;
  for (auto i = 0; i < iterations; ++i)
  {
    kv::Store kv_store;
    auto consensus = std::make_shared<SlowStubConsensus>();
    kv_store.set_consensus(consensus);
    auto encryptor = std::make_shared<kv::NullTxEncryptor>();
    kv_store.set_encryptor(encryptor);

    // Keep atomic count of running threads
    std::atomic<size_t> active_tx_threads(thread_count);

    // Start compact thread
    std::atomic<CompacterState> compact_state(NotStarted);
    CompactArgs ca{&kv_store, &active_tx_threads, &compact_state};
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

    const auto initial_version = kv_store.compacted_version();

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
    const auto now_compacted = kv_store.compacted_version();
    DOCTEST_REQUIRE(now_compacted > initial_version);
    const auto expected = initial_version + (tx_count * thread_count);
    DOCTEST_REQUIRE(now_compacted == expected);

    // Check that all transactions were passed through to consensus
    DOCTEST_REQUIRE(consensus->number_of_replicas() == expected);

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
}

DOCTEST_TEST_CASE(
  "get_version_of_previous_write ordering" * doctest::test_suite("concurrency"))
{
  // Many threads attempt to produce a chain of transactions pointing at the
  // previous write to a single key, at that key.
  kv::Store kv_store;
  auto encryptor = std::make_shared<kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);
  constexpr auto store_commit_term = 2;
  kv_store.initialise_term(store_commit_term);

  using MapType = kv::Map<size_t, nlohmann::json>;
  MapType map("public:foo");

  constexpr size_t k = 42;

  std::atomic<size_t> conflict_count = 0;

  auto point_at_previous_write = [&]() {
    auto sleep_time = std::chrono::microseconds(5);
    while (true)
    {
      auto tx = kv_store.create_tx();
      auto h = tx.rw(map);

      auto ver = h->get_version_of_previous_write(k);

      std::string message;
      if (ver.has_value())
      {
        message = fmt::format("Key {} was previously modified at {}", k, *ver);
      }
      else
      {
        message = fmt::format("Key {} has never been written to before", k);
      }

      auto j = nlohmann::json::object();
      j["version"] = ver;
      j["message"] = message;
      h->put(k, j);

      const auto result = tx.commit();
      if (result == kv::CommitResult::SUCCESS)
      {
        // Succeeded
        break;
      }

      DOCTEST_REQUIRE(result == kv::CommitResult::FAIL_CONFLICT);
      ++conflict_count;

      // Sleep before retrying
      std::this_thread::sleep_for(sleep_time);

      // Increase sleep time next iteration
      const auto factor = 1.0f + ((float)rand() / (float)RAND_MAX);
      sleep_time =
        std::chrono::microseconds((size_t)(sleep_time.count() * factor));
    }
  };

  std::vector<std::thread> threads;
  constexpr auto num_threads = 64;
  constexpr auto writes_per_thread = 10;
  for (size_t i = 0; i < num_threads; ++i)
  {
    threads.emplace_back([&]() {
      for (size_t n = 0; n < writes_per_thread; ++n)
      {
        point_at_previous_write();
      }
    });
  }

  for (auto& thread : threads)
  {
    thread.join();
  }

  DOCTEST_CHECK(conflict_count > 0);
  constexpr auto last_write_version = num_threads * writes_per_thread;

  {
    DOCTEST_INFO("Read final write from current state");
    auto tx = kv_store.create_tx();
    auto h = tx.ro(map);

    auto v = h->get(k);
    DOCTEST_REQUIRE(v.has_value());
    const auto j = v.value();
    DOCTEST_REQUIRE(j["version"] == last_write_version - 1);

    auto ver = h->get_version_of_previous_write(k);
    DOCTEST_REQUIRE(ver.has_value());
    DOCTEST_REQUIRE(ver.value() == last_write_version);
  }

  {
    DOCTEST_INFO("Read full chain of writes");

    // Use ReservedTx as a hack to read historic entries, rather than via
    // deserialisation
    for (size_t read_at = 1; read_at < last_write_version; ++read_at)
    {
      auto tx = kv_store.create_reserved_tx({store_commit_term, read_at + 1});
      auto h = tx.ro(map);

      auto v = h->get(k);
      DOCTEST_REQUIRE(v.has_value());

      const auto j = v.value();
      const auto claimed_prev_v = j["version"];

      if (read_at == 1)
      {
        // First write indicates there was no previous version
        DOCTEST_REQUIRE(claimed_prev_v == nullptr);
      }
      else
      {
        DOCTEST_REQUIRE(claimed_prev_v == read_at - 1);
      }
    }
  }
}
