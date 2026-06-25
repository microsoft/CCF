// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "../state_machine.h"

#include <doctest/doctest.h>

namespace
{
  enum class Example
  {
    A,
    B,
    C,
    D
  };
}

template <>
struct fmt::formatter<Example> : fmt::formatter<std::string_view>
{
  template <typename FormatContext>
  auto format(Example e, FormatContext& ctx) const
  {
    std::string_view name = "unknown";
    switch (e)
    {
      case Example::A:
        name = "A";
        break;
      case Example::B:
        name = "B";
        break;
      case Example::C:
        name = "C";
        break;
      case Example::D:
        name = "D";
        break;
    }
    return fmt::formatter<std::string_view>::format(name, ctx);
  }
};

TEST_CASE("Basic state machine" * doctest::test_suite("state_machine"))
{
  ds::StateMachine<Example> sm("example", Example::A);

  REQUIRE(sm.value() == Example::A);
  REQUIRE(sm.check(Example::A));
  REQUIRE_FALSE(sm.check(Example::B));
  REQUIRE_NOTHROW(sm.expect(Example::A));
  REQUIRE_THROWS_AS(sm.expect(Example::B), std::logic_error);

  sm.advance(Example::B);

  REQUIRE(sm.value() == Example::B);
  REQUIRE(sm.check(Example::B));
  REQUIRE_FALSE(sm.check(Example::A));
  REQUIRE_NOTHROW(sm.expect(Example::B));
  REQUIRE_THROWS_AS(sm.expect(Example::A), std::logic_error);
}

TEST_CASE("check_one_of" * doctest::test_suite("state_machine"))
{
  ds::StateMachine<Example> sm("example", Example::A);

  {
    INFO("Current state is part of the set");
    REQUIRE(sm.check_one_of({Example::A}));
    REQUIRE(sm.check_one_of({Example::A, Example::B}));
    REQUIRE(sm.check_one_of({Example::A, Example::B, Example::C}));
  }

  {
    INFO("Current state is not part of the set");
    REQUIRE_FALSE(sm.check_one_of({Example::B}));
    REQUIRE_FALSE(sm.check_one_of({Example::B, Example::C}));
    REQUIRE_FALSE(sm.check_one_of({Example::B, Example::C, Example::D}));
  }

  {
    INFO("Empty set never matches");
    REQUIRE_FALSE(sm.check_one_of({}));
  }

  {
    INFO("Set membership follows state transitions");
    const std::set<Example> states{Example::B, Example::C};
    REQUIRE_FALSE(sm.check_one_of(states));

    sm.advance(Example::B);
    REQUIRE(sm.check_one_of(states));

    sm.advance(Example::C);
    REQUIRE(sm.check_one_of(states));

    sm.advance(Example::D);
    REQUIRE_FALSE(sm.check_one_of(states));
  }
}
