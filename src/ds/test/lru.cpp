// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "../lru.h"

#include <doctest/doctest.h>
#include <string>

TEST_CASE("LRU" * doctest::test_suite("lru"))
{
  constexpr auto max_size = 3;
  LRU<size_t, std::string> lru(max_size);

  REQUIRE(lru.size() == 0);

  constexpr auto key_a = 0;
  constexpr auto key_b = 42;
  constexpr auto key_c = 100;
  constexpr auto key_d = 101;
  constexpr auto key_e = 500;

  lru[key_a] = "a";
  REQUIRE(lru.size() == 1);

  lru[key_b] = "b";
  REQUIRE(lru.size() == 2);

  lru[key_c] = "c";
  REQUIRE(lru.size() == 3);

  {
    INFO("Adding a 4th key pushes out oldest entry");
    lru[key_d] = "d";
    REQUIRE(lru.size() == 3);

    REQUIRE_FALSE(lru.contains(key_a));
    REQUIRE(lru.contains(key_b));
    REQUIRE(lru.contains(key_c));
    REQUIRE(lru.contains(key_d));
  }

  {
    INFO("Overwriting an existing key doesn't change which keys are present");
    lru[key_b] = "b";
    REQUIRE(lru.size() == 3);

    REQUIRE_FALSE(lru.contains(key_a));
    REQUIRE(lru.contains(key_b));
    REQUIRE(lru.contains(key_c));
    REQUIRE(lru.contains(key_d));
  }

  {
    INFO("Calling contains(k) does not make k recently accessed");
    REQUIRE(lru.contains(key_c));

    INFO("Adding a 5th key pushes out oldest entry");
    lru[key_e] = "e";

    REQUIRE_FALSE(lru.contains(key_a));
    REQUIRE(lru.contains(key_b));
    REQUIRE_FALSE(lru.contains(key_c));
    REQUIRE(lru.contains(key_d));
    REQUIRE(lru.contains(key_e));
  }

  {
    INFO("Adding entries always removes the oldest key");
    // e, b, d -> c, e, b
    lru[key_c] = "c";
    REQUIRE(lru.size() == 3);
    REQUIRE_FALSE(lru.contains(key_d));
    REQUIRE(lru.contains(key_c));

    // c, e, b -> b, c, e
    lru[key_b] = "b";
    REQUIRE(lru.size() == 3);
    REQUIRE(lru.contains(key_b));
    REQUIRE(lru.contains(key_c));
    REQUIRE(lru.contains(key_e));

    // b, c, e -> a, b, c
    lru[key_a] = "a";
    REQUIRE(lru.size() == 3);
    REQUIRE_FALSE(lru.contains(key_e));
    REQUIRE(lru.contains(key_a));
  }

  {
    INFO("LRU size can be modified");
    // a, b, c -> a, b
    lru.set_max_size(2);
    REQUIRE(lru.size() == 2);
    REQUIRE(lru.contains(key_a));
    REQUIRE(lru.contains(key_b));

    // a, b -> c, a
    lru[key_c] = "c";
    REQUIRE(lru.size() == 2);
    REQUIRE(lru.contains(key_a));
    REQUIRE_FALSE(lru.contains(key_b));
    REQUIRE(lru.contains(key_c));

    // c, a -> d, b, c, a
    lru.set_max_size(4);
    REQUIRE(lru.size() == 2);
    lru[key_b] = "b";
    lru[key_d] = "d";
    REQUIRE(lru.size() == 4);

    REQUIRE(lru.contains(key_a));
    REQUIRE(lru.contains(key_b));
    REQUIRE(lru.contains(key_c));
    REQUIRE(lru.contains(key_d));
    REQUIRE_FALSE(lru.contains(key_e));

    // d, b, c, a -> e, d, b, c
    lru[key_e] = "e";
    REQUIRE(lru.size() == 4);

    REQUIRE_FALSE(lru.contains(key_a));
    REQUIRE(lru.contains(key_b));
    REQUIRE(lru.contains(key_c));
    REQUIRE(lru.contains(key_d));
    REQUIRE(lru.contains(key_e));

    // e, d, b, c -> e, d, b
    lru.set_max_size(3);
    REQUIRE(lru.size() == 3);
    REQUIRE_FALSE(lru.contains(key_c));
  }

  using namespace std::string_literals;

  {
    INFO("Values can be retrieved from LRU");
    REQUIRE(lru[key_b] == "b"s);
    REQUIRE(lru[key_d] == "d"s);
    REQUIRE(lru[key_e] == "e"s);

    lru[key_b] = "bb";
    lru[key_e] = "ee";
    REQUIRE(lru[key_b] == "bb"s);
    REQUIRE(lru[key_d] == "d"s);
    REQUIRE(lru[key_e] == "ee"s);

    lru[key_c] = "cc";
    REQUIRE_FALSE(lru.contains(key_b));
    REQUIRE(lru[key_c] == "cc"s);
    REQUIRE(lru[key_d] == "d"s);
    REQUIRE(lru[key_e] == "ee"s);
  }

  {
    INFO("Other API functions are plausibly correct");
    lru[key_a] = "a";
    lru[key_b] = "b";
    lru[key_c] = "c";
    lru[key_d] = "d";
    lru[key_c] = "cc";
    // cc, d, b

    auto it = lru.begin();
    REQUIRE(it != lru.end());
    REQUIRE(it->first == key_c);
    REQUIRE(it->second == "cc"s);

    ++it;
    REQUIRE(it != lru.end());
    REQUIRE(it->first == key_d);
    REQUIRE(it->second == "d"s);

    ++it;
    REQUIRE(it != lru.end());
    REQUIRE(it->first == key_b);
    REQUIRE(it->second == "b"s);

    ++it;
    REQUIRE(it == lru.end());
  }
}