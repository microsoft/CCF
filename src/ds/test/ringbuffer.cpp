// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "../ring_buffer.h"

#include "../serialized.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <thread>
#include <vector>

using namespace ringbuffer;

enum : Message
{
  empty_message = Const::msg_min,
  small_message,
  awkward_message,
  big_message,
};

static constexpr auto awkward_size = 5;
static constexpr auto big_size = 512;

std::vector<uint8_t> last_message_body;

void handle_message(Message m, const uint8_t* data, size_t size)
{
  size_t expected_size = 0;
  switch (m)
  {
    case empty_message:
    {
      expected_size = 0;
      break;
    }
    case small_message:
    {
      expected_size = 1;
      break;
    }
    case awkward_message:
    {
      expected_size = awkward_size;
      break;
    }
    case big_message:
    {
      expected_size = big_size;
      break;
    }
  }

  REQUIRE(expected_size == size);
  last_message_body.clear();
  last_message_body.insert(last_message_body.end(), data, data + size);
}

void nop_handler(ringbuffer::Message, const uint8_t*, size_t) {}

TEST_CASE("Basic ringbuffer" * doctest::test_suite("ringbuffer"))
{
  constexpr uint8_t size = 32;
  constexpr uint8_t full_count = 2;

  Reader r(size);
  Writer w(r);

  INFO("Single write-read");
  {
    const uint8_t n = 42;
    REQUIRE(w.try_write(small_message, n));
    REQUIRE(r.read(1, handle_message) == 1);
    REQUIRE(last_message_body[0] == n);
  }

  INFO("Even write-read loop");
  {
    for (uint8_t i = 0; i < 10 * full_count; ++i)
    {
      REQUIRE(w.try_write(small_message, i));
      REQUIRE(r.read(1, handle_message) == 1);
      REQUIRE(last_message_body[0] == i);
    }
  }

  INFO("Over-writing fails politely");
  {
    for (uint8_t i = 0; i < full_count; ++i)
    {
      REQUIRE(w.try_write(small_message, i));
    }

    for (uint8_t i = 0; i < 2 * full_count; ++i)
    {
      REQUIRE_FALSE(w.try_write(small_message, i));
    }
  }

  INFO("Over-reading fails politely");
  {
    for (uint8_t i = 0; i < full_count; ++i)
    {
      REQUIRE(r.read(1, handle_message) == 1);
    }

    for (uint8_t i = 0; i < 2 * full_count; ++i)
    {
      REQUIRE(r.read(1, handle_message) == 0);
    }
  }

  INFO("Writer throws exception");
  {
    REQUIRE_THROWS_AS(w.write(Const::msg_none), std::logic_error);
    REQUIRE_THROWS_AS(
      w.write(small_message, serializer::ByteRange{nullptr, 0xffffffff}),
      std::logic_error);
    REQUIRE_THROWS_AS(
      w.write(small_message, serializer::ByteRange{nullptr, size + 1}),
      std::logic_error);
  }
}

TEST_CASE("Variadic write" * doctest::test_suite("ringbuffer"))
{
  constexpr size_t size = 1 << 8;

  Reader r(size);
  Writer w(r);

  const char v0 = 'h';
  const size_t v1 = 0xdeadbeef;
  const bool v2 = false;
  const float v3 = 3.14f;
  const std::vector<uint8_t> v4 = {0xab, 0xac, 0xad, 0xae, 0xaf};

  const size_t v5_limit = 3;
  const char v6 = 'x';

  // NB: byte-vector is dumped directly, not length-prefixed, so length must be
  // manually inserted where required
  w.write(
    Const::msg_min,
    v0,
    v1,
    v2,
    v3,
    v4.size(),
    v4,
    v5_limit,
    serializer::ByteRange{v4.data(), v5_limit},
    v6);

  r.read(1, [&](Message m, const uint8_t* data, size_t size) {
    REQUIRE(Const::msg_min == m);

    auto r0 = serialized::read<decltype(v0)>(data, size);
    REQUIRE(v0 == r0);

    auto r1 = serialized::read<decltype(v1)>(data, size);
    REQUIRE(v1 == r1);

    auto r2 = serialized::read<decltype(v2)>(data, size);
    REQUIRE(v2 == r2);

    auto r3 = serialized::read<decltype(v3)>(data, size);
    REQUIRE(v3 == r3);

    auto s4 = serialized::read<decltype(v4.size())>(data, size);
    REQUIRE(v4.size() == s4);

    for (size_t i = 0; i < s4; ++i)
    {
      auto r4i = serialized::read<decltype(v4)::value_type>(data, size);
      REQUIRE(v4[i] == r4i);
    }

    auto s5 = serialized::read<decltype(v5_limit)>(data, size);
    REQUIRE(v5_limit == s5);

    for (size_t i = 0; i < s5; ++i)
    {
      auto r5i = serialized::read<decltype(v4)::value_type>(data, size);
      REQUIRE(v4[i] == r5i);
    }

    auto r6 = serialized::read<decltype(v6)>(data, size);
    REQUIRE(v6 == r6);

    REQUIRE(size == 0);
  });
}

TEST_CASE("Writer progress" * doctest::test_suite("ringbuffer"))
{
  // In an empty buffer, regardless of head position (previous writes), any
  // write up to the maximum size will succeed

  constexpr uint8_t buf_size = 32;
  constexpr auto max_res_size = Const::max_reservation_size(buf_size);
  constexpr auto max_msg_size = max_res_size - Const::header_size();

  {
    // Confirm this is actually the maximum msg size
    Reader r(buf_size);
    Writer w(r);

    REQUIRE(w.prepare(small_message, max_msg_size, false).has_value());
    REQUIRE_THROWS_AS(
      w.prepare(small_message, max_msg_size + 1, false), std::logic_error);
  }

  // Use previous writes to set varied initial head positions
  std::vector<std::vector<size_t>> previous_writes = {
    {0},
    {1},
    {max_msg_size - 1},
    {max_msg_size},
    {1, 1},
    {1, max_msg_size},
    {max_msg_size, 1},
    {max_msg_size, max_msg_size},
    {1, 2, 3, 4, 5, 6, 7, 8}};

  // For each of these initial states...
  for (const auto& writes : previous_writes)
  {
    // For each allowed message size...
    for (size_t i = 0; i <= max_msg_size; ++i)
    {
      // Create a fresh buffer
      Reader r(buf_size);
      Writer w(r);

      // Apply the initial state
      for (size_t write_size : writes)
      {
        auto p = w.prepare(empty_message, write_size, false);
        REQUIRE(p.has_value());
        w.finish(p.value());
        REQUIRE(r.read(-1, nop_handler) == 1);
      }

      // Confirm that we can prepare the desired message
      auto p = w.prepare(empty_message, i, false);
      REQUIRE(p.has_value());
      w.finish(p.value());

      REQUIRE(r.read(-1, nop_handler) == 1);
    }
  }
}

TEST_CASE(
  "Reading multiple messages from ringbuffer" *
  doctest::test_suite("ringbuffer"))
{
  constexpr size_t size = 2 << 6;

  Reader r(size);
  Writer w(r);

  INFO("Can read less or more than was written");
  {
    REQUIRE_NOTHROW(w.write(empty_message));
    REQUIRE(r.read(0, handle_message) == 0);
    REQUIRE(r.read(2, handle_message) == 1);
  }

  for (size_t i = 0; i < 8; ++i)
  {
    REQUIRE_NOTHROW(w.write(empty_message));
  }

  INFO("Requesting multiple over-reads is safe");
  {
    REQUIRE(r.read(0, handle_message) == 0);
    REQUIRE(r.read(1, handle_message) == 1);
    REQUIRE(r.read(2, handle_message) == 2);
    REQUIRE(r.read(3, handle_message) == 3);
    REQUIRE(r.read(4, handle_message) == 2);
    REQUIRE(r.read(5, handle_message) == 0);
    REQUIRE(r.read(4, handle_message) == 0);
    REQUIRE(r.read(3, handle_message) == 0);
    REQUIRE(r.read(2, handle_message) == 0);
    REQUIRE(r.read(1, handle_message) == 0);
  }

  INFO("Reading over the ring edge requires multiple requests");
  {
    // Fill the buffer
    const uint8_t n = 42;
    size_t written = 0;
    while (w.try_write(small_message, n))
    {
      ++written;
    }

    const auto first_read = r.read(written, handle_message);
    CHECK(first_read < written);

    const auto second_read = r.read(written, handle_message);
    CHECK(second_read < written);

    REQUIRE(first_read + second_read == written);
  }
}

TEST_CASE(
  "Messages get a unique identifier" * doctest::test_suite("ringbuffer"))
{
  constexpr size_t size = 2 << 6;

  Reader r(size);
  Writer w(r);

  std::set<size_t> ids;

  for (size_t msg_size = 0; msg_size < 8; ++msg_size)
  {
    for (size_t i = 0; i < 5 * size; ++i)
    {
      size_t id;
      auto p = w.prepare(small_message, msg_size, false, &id);
      REQUIRE(p.has_value());
      REQUIRE(ids.insert(id).second);
      w.finish(p.value());
      REQUIRE(r.read(-1, nop_handler) == 1);
    }
  }
}

TEST_CASE("Ring buffer with mixed messages" * doctest::test_suite("ringbuffer"))
{
  constexpr size_t size = 2 << 10;

  Reader r(size);
  Writer w(r);

  std::vector<uint8_t> empty;
  std::vector<uint8_t> small = {42};

  std::vector<uint8_t> awkward(awkward_size);
  for (size_t i = 0; i < awkward_size; ++i)
  {
    awkward[i] = (uint8_t)(i);
  }

  std::vector<uint8_t> big(big_size);
  for (size_t i = 0; i < big_size; ++i)
  {
    big[i] = (uint8_t)(i * i);
  }

  auto write_read_check = [&](const std::vector<Message>& ms) {
    for (auto mk : ms)
    {
      std::vector<uint8_t> data;
      switch (mk)
      {
        case empty_message:
        {
          data = empty;
          break;
        }
        case small_message:
        {
          data = small;
          break;
        }
        case awkward_message:
        {
          data = awkward;
          break;
        }
        case big_message:
        {
          data = big;
          break;
        }
      }

      REQUIRE(w.try_write(mk, data));

      // If we reach the end of the buffer, we'll read 0 messages. Allow a
      // single retry
      const auto read_count = r.read(1, handle_message);
      if (read_count == 0)
      {
        REQUIRE(r.read(1, handle_message) == 1);
      }
      else
      {
        REQUIRE(read_count == 1);
      }
      REQUIRE(last_message_body == data);
    }
  };

  INFO("Empty messages");
  {
    write_read_check(
      {empty_message, empty_message, empty_message, empty_message});
  }

  INFO("Small messages");
  {
    write_read_check(
      {small_message, small_message, small_message, small_message});
  }

  INFO("Awkward messages");
  {
    write_read_check(
      {awkward_message, awkward_message, awkward_message, awkward_message});
  }

  INFO("Big messages");
  {
    write_read_check({big_message, big_message, big_message, big_message});
  }

  INFO("Mixed messages");
  {
    write_read_check(
      {empty_message,   small_message,   awkward_message, big_message,

       empty_message,   awkward_message, small_message,   big_message,

       big_message,     big_message,     small_message,   small_message,
       empty_message,   empty_message,   awkward_message, awkward_message,

       awkward_message, big_message,     empty_message,   empty_message,
       big_message,     awkward_message, small_message,   empty_message,
       big_message,     awkward_message, small_message,   small_message,
       small_message,   big_message,     big_message,     awkward_message});
  }
}

TEST_CASE("Multiple threads can wait" * doctest::test_suite("ringbuffer"))
{
  constexpr size_t size = 32u;
  auto pairify = std::make_pair<size_t, size_t>;

  for (auto [max_n, thread_count] : {
         pairify(2, 2), // Slight contention
         pairify(size * 3, 4), // Large workloads
         pairify(4, size * 3) // Many workers
       })
  {
    Reader r(size);

    std::vector<std::thread> writer_threads;

    size_t reads = 0;
    std::atomic<size_t> writes = 0;
    size_t target = thread_count * max_n;

    // Create several threads writing more data than can fit at once
    for (size_t i = 0; i < thread_count; ++i)
    {
      writer_threads.push_back(std::thread([&r, &writes, i, n = max_n]() {
        Writer w(r);

        for (uint8_t j = 0u; j < n; ++j)
        {
          ++writes;
          w.write(small_message, j);
        }
      }));
    }

    while (reads < target)
    {
      REQUIRE(reads <= writes.load());

      auto read_count = r.read(1, handle_message);
      if (read_count == 1)
      {
        REQUIRE(last_message_body.size() == 1);
        REQUIRE(last_message_body[0] < max_n);
        ++reads;
      }
      CCF_PAUSE();
    }

    REQUIRE(reads == target);
    REQUIRE(writes.load() == target);

    for (auto& thr : writer_threads)
    {
      thr.join();
    }
  }
}
