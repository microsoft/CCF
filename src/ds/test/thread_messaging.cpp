// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "../thread_messaging.h"

#include <doctest/doctest.h>

struct Foo
{
  static size_t count;

  Foo()
  {
    count++;
  }

  ~Foo()
  {
    count--;
  }
};

size_t Foo::count = 0;

static bool happened = false;

static void always(std::unique_ptr<threading::Tmsg<Foo>> msg)
{
  happened = true;
}

static void never(std::unique_ptr<threading::Tmsg<Foo>> msg)
{
  CHECK(false);
}

// Note: this only works with ASAN turned on, which catches m2 not being
// freed.
TEST_CASE(
  "Unpopped messages are freed" * doctest::test_suite("threadmessaging"))
{
  {
    threading::ThreadMessaging tm(1);

    auto m1 = std::make_unique<threading::Tmsg<Foo>>(&always);
    tm.add_task<Foo>(0, std::move(m1));

    // Task payload (and TMsg) is freed after running
    tm.run_one();
    CHECK(Foo::count == 0);

    auto m2 = std::make_unique<threading::Tmsg<Foo>>(&never);
    tm.add_task<Foo>(0, std::move(m2));
    // Task is owned by the queue, hasn't run
    CHECK(Foo::count == 1);
  }
  // Task payload (and TMsg) is also freed if it hasn't run
  // but the queue was destructed
  CHECK(Foo::count == 0);

  CHECK(happened);
}

// TODO: Add another test for basic cross-thread interaction

// TODO: Add test that separate std::threads actually get unique thread IDs
TEST_CASE("Unique thread IDs" * doctest::test_suite("threadmessaging"))
{
  std::mutex assigned_ids_lock;
  std::vector<uint16_t> assigned_ids;

  std::mutex all_done_lock;
  std::condition_variable all_done;

  auto fn = [&]() {
    {
      std::lock_guard<std::mutex> guard(assigned_ids_lock);
      const auto current_thread_id = threading::get_current_thread_id();
      std::cout << "Current thread ID is " << current_thread_id << std::endl;
      assigned_ids.push_back(current_thread_id);
    }

    {
      std::unique_lock lock(all_done_lock);
      all_done.wait(lock);
    }
  };

  constexpr size_t num_threads = 9;
  std::vector<std::thread> threads;
  for (auto i = 0; i < num_threads; ++i)
  {
    threads.emplace_back(fn);
  }

  size_t attempts = 0;
  constexpr size_t max_attempts = 5;
  while (true)
  {
    {
      std::lock_guard<std::mutex> guard(assigned_ids_lock);
      if (assigned_ids.size() == num_threads)
      {
        all_done.notify_all();
        break;
      }
    }

    REQUIRE(++attempts < max_attempts);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }

  REQUIRE(assigned_ids.size() == num_threads);

  for (auto& thread : threads)
  {
    thread.join();
  }

  const auto unique = std::unique(assigned_ids.begin(), assigned_ids.end());
  REQUIRE_MESSAGE(
    unique == assigned_ids.end(),
    fmt::format(
      "Thread IDs are not unique: {}", fmt::join(assigned_ids, ", ")));
}