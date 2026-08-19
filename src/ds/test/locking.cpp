// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/pal/locking.h"

#include <doctest/doctest.h>
#include <optional>

namespace
{
  class ProtectedValue
  {
  private:
    ccf::pal::Mutex mutex;
    int value CCF_GUARDED_BY(mutex) = 0;

    void set_unlocked(int new_value) CCF_REQUIRES(mutex)
    {
      value = new_value;
    }

  public:
    void set(int new_value)
    {
      mutex.lock();
      set_unlocked(new_value);
      mutex.unlock();
    }

    std::optional<int> try_get()
    {
      if (mutex.try_lock())
      {
        const auto result = value;
        mutex.unlock();
        return result;
      }

      return std::nullopt;
    }
  };
}

TEST_CASE("PAL mutex" * doctest::test_suite("locking"))
{
  ProtectedValue value;
  value.set(42);
  const auto result = value.try_get();
  REQUIRE(result.has_value());
  CHECK(result.value() == 42);
}
