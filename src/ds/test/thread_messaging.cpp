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
TEST_CASE("Unpopped messages are freed")
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

    tm.drop_tasks();
  }
  // Task payload (and TMsg) is also freed if it hasn't run
  // but the queue was destructed
  CHECK(Foo::count == 0);

  CHECK(happened);
}