// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "../hash.h"

#include "../siphash.h"
#include "siphash_known_hashes.h"

#include <doctest/doctest.h>
#include <iostream>
#include <set>

TEST_CASE("SipHash-2-4 correctness" * doctest::test_suite("hash"))
{
  siphash::SipKey key{
    siphash::bytes_to_64_le("\000\001\002\003\004\005\006\007"),
    siphash::bytes_to_64_le("\010\011\012\013\014\015\016\017")};

  std::vector<uint8_t> in;

  for (auto i = 0; i < 64; ++i)
  {
    const auto& expected = siphash_2_4_vectors[i];

    auto out = siphash::siphash<2, 4>(in, key);
    uint8_t actual[8];

    siphash::u64_to_bytes_le(out, actual);

    for (auto j = 0; j < 8; ++j)
    {
      REQUIRE(actual[j] == expected[j]);
    }

    in.push_back(i);
  }
}

template <typename T>
void check_hash_uniqueness()
{
  std::hash<std::vector<T>> h{};

  std::set<size_t> taken;

  std::vector<T> identical;
  std::vector<T> different;
  for (size_t i = 0; i < 1024; ++i)
  {
    identical.push_back(1);
    different.push_back((T)i);

    REQUIRE(taken.insert(h(identical)).second);
    REQUIRE(taken.insert(h(different)).second);
  }

  REQUIRE(taken.insert(h({2, 4})).second);
  REQUIRE(taken.insert(h({4, 2})).second);
}

TEST_CASE("std::vector hash" * doctest::test_suite("hash"))
{
  check_hash_uniqueness<uint8_t>();
  check_hash_uniqueness<size_t>();
  check_hash_uniqueness<int>();

  {
    std::set<size_t> taken;
    using T = std::vector<std::string>;
    std::hash<T> h{};

    REQUIRE(taken.insert(h({})).second);
    REQUIRE(taken.insert(h({""})).second);
    REQUIRE(taken.insert(h({"hello world"})).second);
    REQUIRE(taken.insert(h({"hello", "world"})).second);
    REQUIRE(taken.insert(h({"world", "hello"})).second);
    REQUIRE(taken.insert(h({"hello", "hello"})).second);
    REQUIRE(taken.insert(h({"world", "world"})).second);
  }
}

TEST_CASE("std::pair hash" * doctest::test_suite("hash"))
{
  std::set<size_t> taken;

  {
    using UU = std::pair<size_t, size_t>;
    std::hash<UU> h{};
    REQUIRE(taken.insert(h({0, 0})).second);
    REQUIRE(taken.insert(h({0, 1})).second);
    REQUIRE(taken.insert(h({1, 0})).second);
    REQUIRE(taken.insert(h({1, 1})).second);
  }

  {
    using II = std::pair<int, int>;
    std::hash<II> h{};
    REQUIRE(taken.insert(h({2, 2})).second);
    REQUIRE(taken.insert(h({2, 3})).second);
    REQUIRE(taken.insert(h({3, 2})).second);
    REQUIRE(taken.insert(h({3, 3})).second);
  }

  {
    using SU = std::pair<std::string, size_t>;
    std::hash<SU> h{};
    REQUIRE(taken.insert(h({"A", 0})).second);
    REQUIRE(taken.insert(h({"A", 1})).second);
    REQUIRE(taken.insert(h({"B", 0})).second);
    REQUIRE(taken.insert(h({"B", 1})).second);
  }

  {
    using US = std::pair<size_t, std::string>;
    std::hash<US> h{};
    REQUIRE(taken.insert(h({0, "A"})).second);
    REQUIRE(taken.insert(h({1, "A"})).second);
    REQUIRE(taken.insert(h({0, "B"})).second);
    REQUIRE(taken.insert(h({1, "B"})).second);
  }
}

constexpr auto fnv_1a_32 = ds::fnv_1a<uint32_t>;
constexpr auto fnv_1a_64 = ds::fnv_1a<uint64_t>;

TEST_CASE("FNV-1a correctness" * doctest::test_suite("hash"))
{
  INFO("Comparing against known values from external calculators");
  REQUIRE(fnv_1a_32("") == 0x811c9dc5);
  REQUIRE(fnv_1a_64("") == 0xcbf29ce484222325);

  REQUIRE(fnv_1a_32("0") == 0x350ca8af);
  REQUIRE(fnv_1a_64("0") == 0xaf63ad4c86019caf);

  REQUIRE(fnv_1a_32("Hello world") == 0x594d29c7);
  REQUIRE(fnv_1a_64("Hello world") == 0x2713f785a33764c7);
}

TEST_CASE("FNV-1a collision resistance" * doctest::test_suite("hash"))
{
  // Build some hashes, check we have no collisions
  std::set<uint32_t> taken_32;
  std::set<uint64_t> taken_64;

  char cc[4] = {0};

  // Hash every single byte
  for (size_t i = 0; i < 256; ++i)
  {
    cc[0] = i;
    REQUIRE(taken_32.insert(fnv_1a_32(cc)).second);
    REQUIRE(taken_64.insert(fnv_1a_64(cc)).second);
  }

  // Hash every pair of lower-case characters
  for (char a = 'a'; a <= 'z'; ++a)
  {
    cc[0] = a;
    for (char b = 'a'; b <= 'z'; ++b)
    {
      cc[1] = b;
      REQUIRE(taken_32.insert(fnv_1a_32(cc)).second);
      REQUIRE(taken_64.insert(fnv_1a_64(cc)).second);
    }
  }

  // Hash every triple of lower-case characters
  for (char a = 'a'; a <= 'z'; ++a)
  {
    cc[0] = a;
    for (char b = 'a'; b <= 'z'; ++b)
    {
      cc[1] = b;
      for (char c = 'a'; c <= 'z'; ++c)
      {
        cc[2] = c;
        REQUIRE(taken_32.insert(fnv_1a_32(cc)).second);
        REQUIRE(taken_64.insert(fnv_1a_64(cc)).second);
      }
    }
  }

  cc[0] = 0;
  cc[1] = 0;
  cc[2] = 0;

  // And just for good measure, do upper-case as well
  for (char a = 'A'; a <= 'Z'; ++a)
  {
    cc[0] = a;
    for (char b = 'A'; b <= 'Z'; ++b)
    {
      cc[1] = b;
      for (char c = 'A'; c <= 'Z'; ++c)
      {
        cc[2] = c;
        REQUIRE(taken_32.insert(fnv_1a_32(cc)).second);
        REQUIRE(taken_64.insert(fnv_1a_64(cc)).second);
      }
    }
  }
}