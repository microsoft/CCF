// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "../serialized.h"

#include <doctest/doctest.h>

template <class T>
T peek_in_vec(const std::vector<uint8_t>& v, size_t offset)
{
  auto data = v.data();
  auto size = v.size();
  REQUIRE(offset < size);
  data += offset;
  size -= offset;
  return serialized::peek<T>(data, size);
}

TEST_CASE("peek unaligned" * doctest::test_suite("serialized"))
{
  std::vector<uint8_t> src{
    0x01,
    0x23,
    0x45,
    0x67,
    0x89,
    0xab,
    0xcd,
    0xef,
    0xfe,
    0xdc,
    0xba,
    0x98,
    0x76,
    0x54,
    0x32,
    0x10};

  // Confirm that we can read at any alignment
  {
    INFO("uint8_t");
    REQUIRE(peek_in_vec<uint8_t>(src, 0) == 0x01);
    REQUIRE(peek_in_vec<uint8_t>(src, 1) == 0x23);
    REQUIRE(peek_in_vec<uint8_t>(src, 2) == 0x45);
    REQUIRE(peek_in_vec<uint8_t>(src, 3) == 0x67);
    REQUIRE(peek_in_vec<uint8_t>(src, 4) == 0x89);
    REQUIRE(peek_in_vec<uint8_t>(src, 5) == 0xab);
    REQUIRE(peek_in_vec<uint8_t>(src, 6) == 0xcd);
    REQUIRE(peek_in_vec<uint8_t>(src, 7) == 0xef);
  }

  {
    INFO("uint16_t");
    REQUIRE(peek_in_vec<uint16_t>(src, 0) == 0x23'01);
    REQUIRE(peek_in_vec<uint16_t>(src, 1) == 0x45'23);
    REQUIRE(peek_in_vec<uint16_t>(src, 2) == 0x67'45);
    REQUIRE(peek_in_vec<uint16_t>(src, 3) == 0x89'67);
    REQUIRE(peek_in_vec<uint16_t>(src, 4) == 0xab'89);
    REQUIRE(peek_in_vec<uint16_t>(src, 5) == 0xcd'ab);
    REQUIRE(peek_in_vec<uint16_t>(src, 6) == 0xef'cd);
    REQUIRE(peek_in_vec<uint16_t>(src, 7) == 0xfe'ef);
  }

  {
    INFO("uint32_t");
    REQUIRE(peek_in_vec<uint32_t>(src, 0) == 0x67'45'23'01);
    REQUIRE(peek_in_vec<uint32_t>(src, 1) == 0x89'67'45'23);
    REQUIRE(peek_in_vec<uint32_t>(src, 2) == 0xab'89'67'45);
    REQUIRE(peek_in_vec<uint32_t>(src, 3) == 0xcd'ab'89'67);
    REQUIRE(peek_in_vec<uint32_t>(src, 4) == 0xef'cd'ab'89);
    REQUIRE(peek_in_vec<uint32_t>(src, 5) == 0xfe'ef'cd'ab);
    REQUIRE(peek_in_vec<uint32_t>(src, 6) == 0xdc'fe'ef'cd);
    REQUIRE(peek_in_vec<uint32_t>(src, 7) == 0xba'dc'fe'ef);
  }

  {
    INFO("uint64_t");
    REQUIRE(peek_in_vec<uint64_t>(src, 0) == 0xef'cd'ab'89'67'45'23'01);
    REQUIRE(peek_in_vec<uint64_t>(src, 1) == 0xfe'ef'cd'ab'89'67'45'23);
    REQUIRE(peek_in_vec<uint64_t>(src, 2) == 0xdc'fe'ef'cd'ab'89'67'45);
    REQUIRE(peek_in_vec<uint64_t>(src, 3) == 0xba'dc'fe'ef'cd'ab'89'67);
    REQUIRE(peek_in_vec<uint64_t>(src, 4) == 0x98'ba'dc'fe'ef'cd'ab'89);
    REQUIRE(peek_in_vec<uint64_t>(src, 5) == 0x76'98'ba'dc'fe'ef'cd'ab);
    REQUIRE(peek_in_vec<uint64_t>(src, 6) == 0x54'76'98'ba'dc'fe'ef'cd);
    REQUIRE(peek_in_vec<uint64_t>(src, 7) == 0x32'54'76'98'ba'dc'fe'ef);
  }
}
