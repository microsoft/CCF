// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "../thread_messaging.h"

#include <doctest/doctest.h>

struct Nothing
{};

static bool happened = false;

static void always(std::unique_ptr<threading::Tmsg<Nothing>> msg)
{
  happened = true;
}

static void never(std::unique_ptr<threading::Tmsg<Nothing>> msg)
{
  CHECK(false);
}

// Note: this only works with ASAN turned on, which catches m2 not being
// freed.
TEST_CASE("Unpopped messages are freed")
{
  {
    threading::ThreadMessaging tm(1);

    auto m1 = std::make_unique<threading::Tmsg<Nothing>>(&always);
    tm.add_task<Nothing>(0, std::move(m1));

    threading::Task& task = tm.get_task(0);
    tm.run_one(task);

    auto m2 = std::make_unique<threading::Tmsg<Nothing>>(&never);
    tm.add_task<Nothing>(0, std::move(m2));
  }

  CHECK(happened);
}