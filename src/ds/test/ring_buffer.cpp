// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "../ring_buffer.h"

#include "../serialized.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <map>
#include <queue>
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

  auto buffer = std::make_unique<ringbuffer::TestBuffer>(size);
  Reader r(buffer->bd);
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

TEST_CASE("Buffer size and alignment" * doctest::test_suite("ringbuffer"))
{
  {
    INFO("previous_power_of_2");
    REQUIRE(ringbuffer::Const::previous_power_of_2(1) == 1);
    REQUIRE(ringbuffer::Const::previous_power_of_2(2) == 2);
    REQUIRE(ringbuffer::Const::previous_power_of_2(3) == 2);
    REQUIRE(ringbuffer::Const::previous_power_of_2(4) == 4);
    REQUIRE(ringbuffer::Const::previous_power_of_2(5) == 4);

    REQUIRE(ringbuffer::Const::previous_power_of_2(4194303) == 2097152);
    REQUIRE(ringbuffer::Const::previous_power_of_2(4194304) == 4194304);
    REQUIRE(ringbuffer::Const::previous_power_of_2(4194305) == 4194304);
    REQUIRE(ringbuffer::Const::previous_power_of_2(5252525) == 4194304);

    REQUIRE(ringbuffer::Const::previous_power_of_2(8589934591) == 4294967296);
    REQUIRE(ringbuffer::Const::previous_power_of_2(8589934592) == 8589934592);
    REQUIRE(ringbuffer::Const::previous_power_of_2(8589934593) == 8589934592);
    REQUIRE(ringbuffer::Const::previous_power_of_2(8989898989) == 8589934592);

    REQUIRE(
      ringbuffer::Const::previous_power_of_2(1125899906842623) ==
      562949953421312);
    REQUIRE(
      ringbuffer::Const::previous_power_of_2(1125899906842624) ==
      1125899906842624);
    REQUIRE(
      ringbuffer::Const::previous_power_of_2(1125899906842625) ==
      1125899906842624);
    REQUIRE(
      ringbuffer::Const::previous_power_of_2(1234567890987654) ==
      1125899906842624);
  }

  {
    INFO("Explicit tests");
    constexpr uint8_t size = 32;
    auto buffer = std::make_unique<ringbuffer::TestBuffer>(size);

    REQUIRE_NOTHROW(Reader(buffer->bd));

    buffer->bd.size = 3;
    REQUIRE_THROWS(Reader(buffer->bd));

    buffer->bd.size = 7;
    REQUIRE_THROWS(Reader(buffer->bd));

    buffer->bd.size = 8;
    REQUIRE_NOTHROW(Reader(buffer->bd));

    buffer->bd.size = 9;
    REQUIRE_THROWS(Reader(buffer->bd));

    buffer->bd.size = 31;
    REQUIRE_THROWS(Reader(buffer->bd));

    buffer->bd.size = 32;
    REQUIRE_NOTHROW(Reader(buffer->bd));

    auto data = buffer->bd.data;
    for (auto i = 0; i < buffer->bd.size; ++i)
    {
      buffer->bd.data = data + i;
      if (i % 8 == 0)
      {
        REQUIRE_NOTHROW(Reader(buffer->bd));
      }
      else
      {
        REQUIRE_THROWS(Reader(buffer->bd));
      }
    }
  }

  {
    INFO("Correcting a misaligned buffer");
    constexpr size_t orig_size = 64;
    uint8_t* orig_data = new uint8_t[orig_size];

    ringbuffer::Offsets offsets;

    ringbuffer::BufferDef bd;
    bd.offsets = &offsets;

    for (size_t i = 0; i < orig_size; ++i)
    {
      auto data = orig_data + i;
      size_t size = orig_size - i;

      if (size >= 8)
      {
        REQUIRE(ringbuffer::Const::find_acceptable_sub_buffer(data, size));
        bd.data = data;
        bd.size = size;
        REQUIRE_NOTHROW(Reader r(bd));
      }
      else
      {
        REQUIRE_FALSE(
          ringbuffer::Const::find_acceptable_sub_buffer(data, size));
      }
    }

    delete[] orig_data;
  }
}

TEST_CASE("Variadic write" * doctest::test_suite("ringbuffer"))
{
  constexpr size_t size = 1 << 8;

  auto buffer = std::make_unique<ringbuffer::TestBuffer>(size);
  Reader r(buffer->bd);
  Writer w(r);

  enum TEnum
  {
    Foo,
    Bar = 42,
    Baz
  };

  const char v0 = 'h';
  const size_t v1 = 0xdeadbeef;
  const bool v2 = false;
  const TEnum v3 = Baz;
  const std::vector<uint8_t> v4 = {0xab, 0xac, 0xad, 0xae, 0xaf};
  const size_t v5_limit = 3;
  const char v6 = 'x';
  const std::vector<uint8_t> v7 = {0x1a, 0x1b, 0x1c};

  w.write(
    Const::msg_min,
    v0,
    v1,
    v2,
    v3,
    v4,
    serializer::ByteRange{v4.data(), v5_limit},
    v6,
    v7);

  r.read(1, [&](Message m, const uint8_t* data, size_t size) {
    REQUIRE(Const::msg_min == m);

    auto r0 = serialized::read<std::remove_const_t<decltype(v0)>>(data, size);
    REQUIRE(v0 == r0);

    auto r1 = serialized::read<std::remove_const_t<decltype(v1)>>(data, size);
    REQUIRE(v1 == r1);

    auto r2 = serialized::read<std::remove_const_t<decltype(v2)>>(data, size);
    REQUIRE(v2 == r2);

    auto r3 = serialized::read<std::remove_const_t<decltype(v3)>>(data, size);
    REQUIRE(v3 == r3);

    // Size prefix is inserted by writer
    auto s4 =
      serialized::read<std::remove_const_t<decltype(v4.size())>>(data, size);
    REQUIRE(v4.size() == s4);

    for (size_t i = 0; i < s4; ++i)
    {
      auto r4i =
        serialized::read<std::remove_const_t<decltype(v4)>::value_type>(
          data, size);
      REQUIRE(v4[i] == r4i);
    }

    // Size prefix is inserted by writer
    auto s5 =
      serialized::read<std::remove_const_t<decltype(v5_limit)>>(data, size);
    REQUIRE(v5_limit == s5);

    for (size_t i = 0; i < s5; ++i)
    {
      auto r5i =
        serialized::read<std::remove_const_t<decltype(v4)>::value_type>(
          data, size);
      REQUIRE(v4[i] == r5i);
    }

    auto r6 = serialized::read<std::remove_const_t<decltype(v6)>>(data, size);
    REQUIRE(v6 == r6);

    // Trailing variably sized value is not size-prefixed
    auto r7 = serialized::read(data, size, size);
    REQUIRE(v7 == r7);

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
    auto buffer = std::make_unique<ringbuffer::TestBuffer>(buf_size);
    Reader r(buffer->bd);
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
      auto buffer = std::make_unique<ringbuffer::TestBuffer>(buf_size);
      Reader r(buffer->bd);
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

  auto buffer = std::make_unique<ringbuffer::TestBuffer>(size);
  Reader r(buffer->bd);
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

  auto buffer = std::make_unique<ringbuffer::TestBuffer>(size);
  Reader r(buffer->bd);
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

  auto buffer = std::make_unique<ringbuffer::TestBuffer>(size);
  Reader r(buffer->bd);
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

  for (auto [max_n_, thread_count_] : {
         pairify(2, 2), // Slight contention
         pairify(size * 3, 4), // Large workloads
         pairify(4, size * 3) // Many workers
       })
  {
    auto& max_n = max_n_;
    auto& thread_count = thread_count_;
    auto buffer = std::make_unique<ringbuffer::TestBuffer>(size);
    Reader r(buffer->bd);
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

class SparseReader : public ringbuffer::Reader
{
public:
  std::map<size_t, uint64_t> writes;

  using ringbuffer::Reader::Reader;

  uint64_t read64(size_t index) override
  {
    const auto it = writes.find(index);
    if (it != writes.end())
    {
      return it->second;
    }

    return 0;
  }

  virtual void clear_mem(size_t index, size_t advance) override
  {
    writes.erase(
      writes.lower_bound(index), writes.upper_bound(index + advance));
  }
};

class SparseWriter : public ringbuffer::Writer
{
public:
  SparseReader& nr;

  SparseWriter(SparseReader& nr_) : ringbuffer::Writer(nr_), nr(nr_) {}

  uint64_t read64(size_t index) override
  {
    return nr.read64(index);
  }

  void write64(size_t index, uint64_t value) override
  {
    nr.writes[index] = value;
  }
};

// This test checks that the ringbuffer functions correctly when the offsets
// overflow and wrap around from their maximum representable size to 0
TEST_CASE(
  "Offset overflow" *
  doctest::test_suite("ringbuffer")
  // Skip when xAPIC mitigations are enabled, which are not correctly handled by
  // SparseReader
  * doctest::skip(ccf::pal::require_alignment_for_untrusted_reads()))
{
  const auto seed = time(NULL);
  INFO("Using seed: ", seed);
  srand(seed);

  // Pass a randomly constructed list of messages of mixed size, some extremely
  // large
  const std::vector<size_t> message_sizes = {
    0,
    3,
    ringbuffer::Const::max_size() / 3,
    ringbuffer::Const::max_size() - 3,
    ringbuffer::Const::max_size()};

  auto rand_message_type = []() {
    return (rand() % 100) + ringbuffer::Const::msg_min;
  };

  auto rand_message_size = [&message_sizes]() {
    return message_sizes[rand() % message_sizes.size()];
  };

  // Repeat test many times, with randomised parameters each time
  for (size_t iteration = 0; iteration < 100; ++iteration)
  {
    ringbuffer::Offsets offsets;

    // bd points to a single real byte, not null, so we can do maths on it
    auto buffer_start = std::make_unique<uint8_t>();
    ringbuffer::BufferDef bd{buffer_start.get(), 1ull << 32, &offsets};

    // Initially set the offsets to a large value (within a few max-sized
    // message writes of their maximum)
    offsets.head = offsets.head_cache = offsets.tail =
      UINT64_MAX - (rand() % (4ull * ringbuffer::Const::max_size()));

    // Construct test reader/writer which don't require huge allocations.
    SparseReader r(bd);
    SparseWriter w(r);

    // Loop until we've overflowed the offsets
    while (true)
    {
      // Record each message type and size that was written, for validation when
      // reading
      std::queue<std::pair<Message, size_t>> messages;

      // Write a few messages this time. Deliberately randomised so it may fill
      // the buffer, may wrap, or may write a few small messages.
      const auto message_count = (rand() % 4) + 1;
      for (size_t m = 0; m < message_count; ++m)
      {
        const auto message_type = rand_message_type();
        const auto message_size = rand_message_size();
        auto marker = w.prepare(message_type, message_size, false);
        if (!marker.has_value())
        {
          REQUIRE(!messages.empty());
          // Ring-buffer is full (but at least one message has been written)
          break;
        }
        messages.push({message_type, message_size});
        w.finish(marker);
      }

      // Read twice, because read() will early-out when it reaches the end of
      // the buffer
      for (size_t i = 0; i < 2; ++i)
      {
        r.read(-1, [&messages](Message m, const uint8_t* data, size_t size) {
          // Validate and pop each message as it is seen, in-order
          REQUIRE(!messages.empty());
          const auto expected = messages.front();
          REQUIRE(m == expected.first);
          REQUIRE(size == expected.second);
          messages.pop();
        });
      }

      // Confirm that all messages were processed
      REQUIRE(messages.empty());

      if (
        (offsets.head_cache < UINT64_MAX / 2) &&
        offsets.head_cache > ringbuffer::Const::max_size())
      {
        // If we have overflowed, and correctly written several messages
        // after wrapping, then exit this iteration
        break;
      }
    }
  }
}

TEST_CASE(
  "Malicious writer" *
  doctest::test_suite("ringbuffer")
  // Skip when xAPIC mitigations are enabled, since the core assertion that
  // reads are within the original buffer is deliberately broken by the Reader
  * doctest::skip(ccf::pal::require_alignment_for_untrusted_reads()))
{
  constexpr auto buffer_size = 256ull;

  std::unique_ptr<ringbuffer::TestBuffer> buffer;

  const auto read_fn = [&buffer](Message m, const uint8_t* data, size_t size) {
    REQUIRE(data > buffer->storage.data());
    REQUIRE(data + size <= buffer->storage.data() + buffer->storage.size());
  };

  for (size_t write_size :
       {(size_t)0,
        (size_t)1,
        (size_t)(buffer_size - ringbuffer::Const::header_size()),
        (size_t)(buffer_size - ringbuffer::Const::header_size() + 1),
        (size_t)(buffer_size),
        (size_t)UINT32_MAX})
  {
    for (ringbuffer::Message m :
         {(ringbuffer::Message)empty_message,
          (ringbuffer::Message)small_message,
          (ringbuffer::Message)ringbuffer::Const::msg_pad})
    {
      buffer = std::make_unique<ringbuffer::TestBuffer>(buffer_size);
      Reader r(buffer->bd);

      auto data = buffer->storage.data();
      auto size = buffer->storage.size();
      uint64_t bad_header =
        ringbuffer::Const::make_header(m, write_size, false);
      serialized::write(data, size, bad_header);

      const auto should_throw =
        write_size > buffer_size - ringbuffer::Const::header_size();
      if (should_throw)
      {
        REQUIRE_THROWS(r.read(-1, read_fn));
      }
      else
      {
        REQUIRE_NOTHROW(r.read(-1, read_fn));
      }
    }
  }
}
