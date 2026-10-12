// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/byte_vector.h"

#include <array>
#include <cstring>
#include <doctest/doctest.h>
#include <iterator>
#include <limits>
#include <random>
#include <ranges>
#include <sstream>
#include <type_traits>
#include <vector>

using Bytes = ccf::ByteVector;

static_assert(std::ranges::contiguous_range<Bytes>);
static_assert(std::ranges::contiguous_range<const Bytes>);
static_assert(std::is_nothrow_move_constructible_v<Bytes>);
static_assert(std::is_nothrow_move_assignable_v<Bytes>);
static_assert(sizeof(void*) != 8 || sizeof(Bytes) == 24);
static_assert(alignof(Bytes) >= alignof(uint64_t));

TEST_CASE("ByteVector interface" * doctest::test_suite("byte_vector"))
{
  Bytes bytes;
  CHECK(bytes.empty());
  CHECK(bytes.data() != nullptr);
  CHECK(bytes.capacity() == 16);
  CHECK(bytes.begin() == bytes.end());
  CHECK(bytes.rbegin() == bytes.rend());
  CHECK(bytes.max_size() == size_t(std::numeric_limits<ptrdiff_t>::max()));

  bytes.assign(size_t{3}, uint8_t{42});
  CHECK(bytes == Bytes{42, 42, 42});
  bytes.append({0, 128, 255});
  CHECK(bytes.size_in_bytes() == 6);
  CHECK(bytes.capacity_in_bytes() == bytes.capacity());
  CHECK(bytes.front() == 42);
  CHECK(bytes.back() == 255);

  const auto& immutable = bytes;
  CHECK(immutable[4] == 128);
  CHECK(*immutable.rbegin() == 255);
  CHECK(
    std::vector<uint8_t>(immutable.rbegin(), immutable.rend()) ==
    std::vector<uint8_t>{255, 128, 0, 42, 42, 42});

  CHECK(bytes.insert(bytes.begin() + 1, uint8_t{7}) == bytes.begin() + 1);
  CHECK(bytes.erase(bytes.begin()) == bytes.begin());
  CHECK(bytes.front() == 7);
  bytes.insert(bytes.begin() + 1, size_t{2}, uint8_t{9});
  const std::array<uint8_t, 3> additional{1, 2, 3};
  bytes.insert(bytes.end(), additional.begin(), additional.end());
  bytes.insert(bytes.begin(), {4, 5});
  CHECK(bytes == Bytes{4, 5, 7, 9, 9, 42, 42, 0, 128, 255, 1, 2, 3});
  bytes.erase(bytes.begin() + 2, bytes.begin() + 5);
  CHECK(bytes == Bytes{4, 5, 42, 42, 0, 128, 255, 1, 2, 3});

  bytes.emplace_back(uint8_t{6});
  CHECK(bytes.pop_back_val() == 6);
  bytes.pop_back();
  CHECK(bytes.back() == 2);
  bytes = {1, 2};
  bytes.resize(5);
  CHECK(bytes == Bytes{1, 2, 0, 0, 0});
  bytes.resize(8, uint8_t{10});
  CHECK(bytes == Bytes{1, 2, 0, 0, 0, 10, 10, 10});

  bytes.reserve(128);
  const auto capacity = bytes.capacity();
  const auto* data = bytes.data();
  bytes.clear();
  CHECK(bytes.empty());
  CHECK(bytes.capacity() == capacity);
  CHECK(bytes.data() == data);
  std::memcpy(bytes.data(), additional.data(), additional.size());
  bytes.set_size(additional.size());
  CHECK(bytes == Bytes{1, 2, 3});
}

TEST_CASE("ByteVector ownership" * doctest::test_suite("byte_vector"))
{
  for (const size_t size :
       {0, 1, 7, 8, 9, 15, 16, 17, 31, 32, 33, 64, 512, 4096})
  {
    INFO(size);
    Bytes original(size, uint8_t{42});
    const Bytes expected(original);
    Bytes copy(original);
    CHECK(copy == expected);
    if (size != 0)
    {
      copy[0] = 17;
      CHECK(original[0] == 42);
    }

    Bytes moved(std::move(original));
    CHECK(moved == expected);
    CHECK(original.empty());
    original.append({8, 9});
    CHECK(original == Bytes{8, 9});

    Bytes assigned(size_t{513}, uint8_t{99});
    assigned = expected;
    CHECK(assigned == expected);
    assigned = std::move(moved);
    CHECK(assigned == expected);
    CHECK(moved.empty());
    moved = Bytes{5, 6};
    CHECK(moved == Bytes{5, 6});

    auto& same = assigned;
    assigned = same;
    CHECK(assigned == expected);
    assigned = std::move(same);
    CHECK(assigned == expected);

    for (const size_t other_size : {0, 8, 16, 17, 64})
    {
      Bytes left(expected);
      Bytes right(other_size, uint8_t{7});
      const Bytes expected_right(right);
      left.swap(right);
      CHECK(left == expected_right);
      CHECK(right == expected);
      std::swap(left, right);
      CHECK(left == expected);
      left.swap(left);
      CHECK(left == expected);
    }
  }
}

TEST_CASE(
  "ByteVector standard container relocation" *
  doctest::test_suite("byte_vector"))
{
  const std::array<size_t, 7> sizes{0, 1, 8, 16, 17, 64, 512};
  std::vector<Bytes> values;
  for (size_t i = 0; i < 512; ++i)
    values.emplace_back(sizes[i % sizes.size()], static_cast<uint8_t>(i));
  for (size_t i = 0; i < values.size(); ++i)
    CHECK(values[i] == Bytes(sizes[i % sizes.size()], static_cast<uint8_t>(i)));

  values.erase(values.begin(), values.begin() + 128);
  values.shrink_to_fit();
  for (size_t i = 0; i < values.size(); ++i)
    CHECK(
      values[i] ==
      Bytes(sizes[(i + 128) % sizes.size()], static_cast<uint8_t>(i + 128)));
}

TEST_CASE("ByteVector model" * doctest::test_suite("byte_vector"))
{
  std::mt19937_64 random(0x12345678);
  Bytes bytes;
  std::vector<uint8_t> model;
  for (size_t iteration = 0; iteration < 5000; ++iteration)
  {
    const auto size = random() % 512;
    const auto value = static_cast<uint8_t>(random());
    switch (random() % 8)
    {
      case 0:
        bytes.resize(size);
        model.resize(size);
        break;
      case 1:
        bytes.resize(size, value);
        model.resize(size, value);
        break;
      case 2:
        bytes.assign(size, value);
        model.assign(size, value);
        break;
      case 3:
        bytes.push_back(value);
        model.push_back(value);
        break;
      case 4:
        bytes.reserve(size);
        break;
      case 5:
      {
        const auto position = random() % (model.size() + 1);
        bytes.insert(bytes.begin() + position, value);
        model.insert(model.begin() + position, value);
        break;
      }
      case 6:
        if (!model.empty())
        {
          const auto first = random() % model.size();
          const auto last = first + random() % (model.size() - first + 1);
          bytes.erase(bytes.begin() + first, bytes.begin() + last);
          model.erase(model.begin() + first, model.begin() + last);
        }
        break;
      case 7:
        bytes.clear();
        model.clear();
        break;
    }
    REQUIRE(bytes.size() == model.size());
    CHECK(std::equal(bytes.begin(), bytes.end(), model.begin()));
    CHECK(bytes.capacity() >= bytes.size());
  }
}

TEST_CASE(
  "ByteVector aliases survive growth" * doctest::test_suite("byte_vector"))
{
  for (const bool heap : {false, true})
  {
    for (size_t operation = 0; operation < 10; ++operation)
    {
      INFO(heap, operation);
      Bytes bytes;
      if (heap)
        bytes.reserve(64);
      bytes.resize(bytes.capacity());
      for (size_t i = 0; i < bytes.size(); ++i)
        bytes[i] = static_cast<uint8_t>(42 + i);
      std::vector<uint8_t> model(bytes.begin(), bytes.end());
      const auto value = bytes[1];
      switch (operation)
      {
        case 0:
          bytes.push_back(bytes[1]);
          model.push_back(value);
          break;
        case 1:
          bytes.emplace_back(bytes[1]);
          model.push_back(value);
          break;
        case 2:
          bytes.resize(bytes.size() + 3, bytes[1]);
          model.resize(model.size() + 3, value);
          break;
        case 3:
          bytes.assign(bytes.size() + 3, bytes[1]);
          model.assign(model.size() + 3, value);
          break;
        case 4:
          bytes.append(size_t{3}, bytes[1]);
          model.insert(model.end(), size_t{3}, value);
          break;
        case 5:
          bytes.insert(bytes.begin(), bytes[1]);
          model.insert(model.begin(), value);
          break;
        case 6:
          bytes.insert(bytes.begin(), size_t{3}, bytes[1]);
          model.insert(model.begin(), size_t{3}, value);
          break;
        case 7:
        {
          const auto copied = model;
          bytes.append(bytes.begin(), bytes.end());
          model.insert(model.end(), copied.begin(), copied.end());
          break;
        }
        case 8:
        {
          const auto copied = model;
          bytes.insert(bytes.begin() + 2, bytes.begin(), bytes.end());
          model.insert(model.begin() + 2, copied.begin(), copied.end());
          break;
        }
        case 9:
        {
          const std::vector<uint8_t> copied(model.rbegin(), model.rend());
          bytes.append(bytes.rbegin(), bytes.rend());
          model.insert(model.end(), copied.begin(), copied.end());
          break;
        }
      }
      REQUIRE(bytes.size() == model.size());
      CHECK(std::equal(bytes.begin(), bytes.end(), model.begin()));
    }
  }
}

TEST_CASE("ByteVector iterator ranges" * doctest::test_suite("byte_vector"))
{
  std::istringstream input("1 2 3 128 255");
  Bytes bytes{
    std::istream_iterator<unsigned>(input), std::istream_iterator<unsigned>()};
  CHECK(bytes == Bytes{1, 2, 3, 128, 255});

  std::istringstream additional("7 8 9");
  bytes.insert(
    bytes.begin() + 1,
    std::istream_iterator<unsigned>(additional),
    std::istream_iterator<unsigned>());
  CHECK(bytes == Bytes{1, 7, 8, 9, 2, 3, 128, 255});

  const std::array<char, 3> text{'a', '\0', '\xff'};
  Bytes binary(text.begin(), text.end());
  CHECK(binary == Bytes{'a', 0, 255});
  binary.insert(binary.end(), text.begin(), text.end());
  CHECK(binary == Bytes{'a', 0, 255, 'a', 0, 255});

  Bytes reversed{1, 2, 3};
  reversed.insert(reversed.begin() + 1, reversed.rbegin(), reversed.rend());
  CHECK(reversed == Bytes{1, 3, 2, 1, 2, 3});

  struct ConvertedByte
  {
    uint8_t value;
    operator uint8_t() const
    {
      return value ^ 0xff;
    }
  };
  static_assert(sizeof(ConvertedByte) == 1);
  const std::array<ConvertedByte, 3> converted{{{1}, {2}, {3}}};
  Bytes converted_bytes(converted.begin(), converted.end());
  CHECK(converted_bytes == Bytes{254, 253, 252});
  converted_bytes.append(converted.begin(), converted.end());
  converted_bytes.insert(
    converted_bytes.begin(), converted.begin(), converted.end());
  CHECK(converted_bytes == Bytes{254, 253, 252, 254, 253, 252, 254, 253, 252});

  volatile uint8_t volatile_bytes[]{1, 2, 3};
  Bytes from_volatile(std::begin(volatile_bytes), std::end(volatile_bytes));
  CHECK(from_volatile == Bytes{1, 2, 3});
  from_volatile.append(std::begin(volatile_bytes), std::end(volatile_bytes));
  from_volatile.insert(
    from_volatile.begin(),
    std::begin(volatile_bytes),
    std::end(volatile_bytes));
  CHECK(from_volatile == Bytes{1, 2, 3, 1, 2, 3, 1, 2, 3});

  const std::array<bool, 3> booleans{true, false, true};
  CHECK(Bytes(booleans.begin(), booleans.end()) == Bytes{1, 0, 1});
}

TEST_CASE(
  "ByteVector heap and inline transitions" * doctest::test_suite("byte_vector"))
{
  Bytes allocated;
  allocated.reserve(128);
  const auto* original_data = allocated.data();
  const auto original_capacity = allocated.capacity();
  allocated.append({1, 2, 3});
  const Bytes short_copy(allocated);
  CHECK(short_copy == Bytes{1, 2, 3});
  CHECK(short_copy.capacity() == 16);
  allocated.clear();
  CHECK(allocated.data() == original_data);
  CHECK(allocated.capacity() == original_capacity);

  Bytes moved(std::move(allocated));
  CHECK(moved.empty());
  CHECK(moved.data() == original_data);
  CHECK(moved.capacity() == original_capacity);
  CHECK(allocated.empty());
  CHECK(allocated.capacity() == 16);
  allocated.emplace_back();
  CHECK(allocated == Bytes{0});
  swap(allocated, moved);
  CHECK(allocated.empty());
  CHECK(allocated.data() == original_data);
  CHECK(moved == Bytes{0});

  const auto before = allocated;
  CHECK_THROWS_AS(
    allocated.set_size(allocated.capacity() + 1), std::length_error);
  CHECK(allocated == before);
}

TEST_CASE(
  "ByteVector initialized reserved ranges" * doctest::test_suite("byte_vector"))
{
  std::array<uint8_t, 32> input{};
  for (size_t i = 0; i < input.size(); ++i)
    input[i] = static_cast<uint8_t>(i);
  Bytes bytes;
  bytes.reserve(input.size());
  std::memcpy(bytes.data(), input.data(), input.size());
  bytes.set_size(8);
  bytes.append(bytes.data() + 6, bytes.data() + input.size());
  std::vector<uint8_t> expected(input.begin(), input.begin() + 8);
  expected.insert(expected.end(), input.begin() + 6, input.end());
  CHECK(std::vector<uint8_t>(bytes.begin(), bytes.end()) == expected);

  Bytes overlap;
  std::memcpy(overlap.data(), input.data(), overlap.capacity());
  overlap.set_size(4);
  overlap.append(overlap.data() + 2, overlap.data() + 14);
  expected.assign(input.begin(), input.begin() + 4);
  expected.insert(expected.end(), input.begin() + 2, input.begin() + 14);
  CHECK(std::vector<uint8_t>(overlap.begin(), overlap.end()) == expected);
}

TEST_CASE(
  "ByteVector failed iterator conversion" * doctest::test_suite("byte_vector"))
{
  struct ThrowingByte
  {
    uint8_t value;
    operator uint8_t() const
    {
      if (value == 24)
        throw std::runtime_error("Controlled conversion failure");
      return value;
    }
  };
  std::array<ThrowingByte, 32> input{};
  for (size_t i = 0; i < input.size(); ++i)
    input[i].value = static_cast<uint8_t>(i);
  CHECK_THROWS_AS(Bytes(input.begin(), input.end()), std::runtime_error);
  Bytes original{1, 2, 3};
  CHECK_THROWS_AS(
    original.append(input.begin(), input.end()), std::runtime_error);
  CHECK(original == Bytes{1, 2, 3});
  CHECK_THROWS_AS(
    original.insert(original.begin(), input.begin(), input.end()),
    std::runtime_error);
  CHECK(original == Bytes{1, 2, 3});
}

TEST_CASE(
  "ByteVector rejects impossible growth" * doctest::test_suite("byte_vector"))
{
  Bytes bytes{1, 2, 3};
  const auto maximum = std::numeric_limits<size_t>::max();
  CHECK_THROWS_AS(bytes.reserve(maximum), std::length_error);
  CHECK(bytes == Bytes{1, 2, 3});
  CHECK_THROWS_AS(bytes.resize(maximum), std::length_error);
  CHECK(bytes == Bytes{1, 2, 3});
  CHECK_THROWS_AS(bytes.append(maximum, uint8_t{42}), std::length_error);
  CHECK(bytes == Bytes{1, 2, 3});
}

TEST_CASE(
  "ByteVector hash, ordering and formatting" *
  doctest::test_suite("byte_vector"))
{
  CHECK(Bytes{0x7f} < Bytes{0x80});
  CHECK(Bytes{0x80} < Bytes{0xff});
  CHECK(Bytes{1} < Bytes{1, 0});
  CHECK(Bytes{} < Bytes{0});
  CHECK(fmt::format("{}", Bytes{'a', 'b'}) == "<uint8[2]: ascii=ab>");
  CHECK(fmt::format("{}", Bytes{0, 128, 255}) == "<uint8[3]: hex=00 80 ff>");

  static constexpr ccf::siphash::SipKey key{
    0x7720796f726c694b, 0x2165726568207361};
  Bytes bytes;
  for (size_t size = 0; size < 256; ++size)
  {
    CHECK(
      std::hash<Bytes>{}(bytes) ==
      ccf::siphash::siphash<2, 4>(bytes.data(), bytes.size(), key));
    bytes.push_back(static_cast<uint8_t>(size));
  }
}
