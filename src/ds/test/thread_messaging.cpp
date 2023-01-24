// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "../thread_messaging.h"

#include <doctest/doctest.h>

struct Foo
{
  bool& happened;

  static size_t count;

  Foo(bool& h) : happened(h)
  {
    count++;
  }

  ~Foo()
  {
    count--;
  }
};

size_t Foo::count = 0;

static void always(std::unique_ptr<threading::Tmsg<Foo>> msg)
{
  msg->data.happened = true;
}

static void never(std::unique_ptr<threading::Tmsg<Foo>> msg)
{
  CHECK(false);
}

TEST_CASE("ThreadMessaging API" * doctest::test_suite("threadmessaging"))
{
  {
    threading::ThreadMessaging tm;

    static constexpr auto worker_thread_id = threading::MAIN_THREAD_ID + 1;

    bool happened_main_thread = false;
    bool happened_worker_thread = false;

    tm.add_task<Foo>(
      threading::MAIN_THREAD_ID,
      std::make_unique<threading::Tmsg<Foo>>(&always, happened_main_thread));

    REQUIRE_THROWS(tm.add_task<Foo>(
      worker_thread_id,
      std::make_unique<threading::Tmsg<Foo>>(&always, happened_worker_thread)));

    REQUIRE(tm.run_one());
    REQUIRE_FALSE(tm.run_one());

    REQUIRE(happened_main_thread);
    REQUIRE_FALSE(happened_worker_thread);
  }

  {
    // Create a ThreadMessaging with task queues for main thread + 1 worker
    // thread
    threading::ThreadMessaging tm(2);

    static constexpr auto worker_a_id = threading::MAIN_THREAD_ID + 1;
    static constexpr auto worker_b_id = worker_a_id + 1;

    bool happened_0 = false;
    bool happened_1 = false;
    bool happened_2 = false;
    bool happened_3 = false;

    // Queue single task for main thread:
    // - set happened_0
    tm.add_task<Foo>(
      threading::MAIN_THREAD_ID,
      std::make_unique<threading::Tmsg<Foo>>(&always, happened_0));

    // Queue 2 tasks for worker a:
    // - set happened_1
    // - set happened_2
    tm.add_task<Foo>(
      worker_a_id, std::make_unique<threading::Tmsg<Foo>>(&always, happened_1));
    tm.add_task<Foo>(
      worker_a_id, std::make_unique<threading::Tmsg<Foo>>(&always, happened_2));

    // Fail to queue task for worker b, tm is too small
    REQUIRE_THROWS(tm.add_task<Foo>(
      worker_b_id,
      std::make_unique<threading::Tmsg<Foo>>(&always, happened_3)));

    // Run single task on main thread
    REQUIRE(tm.run_one());
    // Confirm there are no more tasks for main thread
    REQUIRE_FALSE(tm.run_one());

    // Confirm only first task has been executed
    REQUIRE(happened_0);
    REQUIRE_FALSE(happened_1);
    REQUIRE_FALSE(happened_2);
    REQUIRE_FALSE(happened_3);

    std::thread t([&]() {
      // Run tasks for worker "a"
      REQUIRE(threading::get_current_thread_id() == worker_a_id);

      REQUIRE(tm.run_one());
      REQUIRE(happened_1);
      REQUIRE_FALSE(happened_2);

      REQUIRE(tm.run_one());
      REQUIRE(happened_2);

      REQUIRE_FALSE(tm.run_one());
    });

    t.join();

    REQUIRE(happened_0);
    REQUIRE(happened_1);
    REQUIRE(happened_2);
    REQUIRE_FALSE(happened_3);
  }
}

// Note: this only works with ASAN turned on, which catches m2 not being
// freed.
TEST_CASE(
  "Unpopped messages are freed" * doctest::test_suite("threadmessaging"))
{
  bool happened = false;

  {
    threading::ThreadMessaging tm(1);

    auto m1 = std::make_unique<threading::Tmsg<Foo>>(&always, happened);
    tm.add_task<Foo>(0, std::move(m1));

    // Task payload (and TMsg) is freed after running
    tm.run_one();
    CHECK(Foo::count == 0);

    auto m2 = std::make_unique<threading::Tmsg<Foo>>(&never, happened);
    tm.add_task<Foo>(0, std::move(m2));
    // Task is owned by the queue, hasn't run
    CHECK(Foo::count == 1);
  }
  // Task payload (and TMsg) is also freed if it hasn't run
  // but the queue was destructed
  CHECK(Foo::count == 0);

  CHECK(happened);
}

TEST_CASE("Unique thread IDs" * doctest::test_suite("threadmessaging"))
{
  std::mutex assigned_ids_lock;
  std::vector<uint16_t> assigned_ids;

  const auto main_thread_id = threading::get_current_thread_id();
  REQUIRE(main_thread_id == threading::MAIN_THREAD_ID);
  assigned_ids.push_back(main_thread_id);

  std::mutex all_done_lock;
  std::condition_variable all_done;

  auto fn = [&]() {
    {
      std::lock_guard<std::mutex> guard(assigned_ids_lock);
      const auto current_thread_id = threading::get_current_thread_id();
      assigned_ids.push_back(current_thread_id);
    }

    {
      std::unique_lock lock(all_done_lock);
      all_done.wait(lock);
    }
  };

  constexpr size_t num_threads = 20;
  constexpr size_t expected_ids = num_threads + 1; // Includes MAIN_THREAD_ID
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
      if (assigned_ids.size() == expected_ids)
      {
        all_done.notify_all();
        break;
      }
    }

    REQUIRE(++attempts < max_attempts);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }

  REQUIRE(assigned_ids.size() == expected_ids);

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

// TODO: Add another test for basic cross-thread interaction