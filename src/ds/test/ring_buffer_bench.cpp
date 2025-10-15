// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define PICOBENCH_IMPLEMENT_WITH_MAIN
#define PICOBENCH_DONT_BIND_TO_ONE_CORE
#include "../ring_buffer.h"

#include <picobench/picobench.hpp>
#include <thread>

using namespace ringbuffer;

constexpr Message msg_type = Const::msg_min + 1;

using ReadHandler = void (*)(ringbuffer::Message, const uint8_t*, size_t);

void nop_handler(ringbuffer::Message, const uint8_t*, size_t) {}

template <size_t N>
void spin_pause_handler(ringbuffer::Message m, const uint8_t*, size_t)
{
  size_t i = 0;
  while (i++ < N)
    std::this_thread::yield();
}

template <size_t N>
void sleep_handler(ringbuffer::Message m, const uint8_t*, size_t)
{
  auto t = std::chrono::duration<size_t, std::nano>(N);
  std::this_thread::sleep_for(t);
}

template <ReadHandler H>
static void write_impl(
  picobench::state& s,
  size_t buf_size,
  size_t message_size,
  size_t writer_count,
  size_t total_messages)
{
  auto buffer = std::make_unique<ringbuffer::TestBuffer>(buf_size);
  Reader r(buffer->bd);

  std::vector<std::thread> writer_threads;

  size_t reads = 0;

  // Final writer(s) may get less
  const size_t messages_per_writer = total_messages / writer_count;
  if (messages_per_writer == 0)
    throw std::logic_error("Too few messages!");

  s.start_timer();

  // Create several threads writing more data than can fit at once
  for (size_t m = 0; m < total_messages; m += messages_per_writer)
  {
    const auto msg_count = std::min(total_messages - m, messages_per_writer);
    writer_threads.emplace_back([message_size, msg_count, &r]() {
      Writer w(r);

      std::vector<uint8_t> raw(msg_count * message_size);
      std::iota(raw.begin(), raw.end(), 0);

      auto start = raw.data();
      for (size_t m = 0u; m < msg_count; ++m)
      {
        w.write(msg_type, serializer::ByteRange{start, message_size});
        start += message_size;
      }
    });
  }

  while (reads < total_messages)
  {
    auto read_count = r.read(-1, H);
    reads += read_count;
    std::this_thread::yield();
  }

  s.stop_timer();

  if (reads != total_messages)
    throw std::logic_error("Read more messages than expected");

  for (auto& thr : writer_threads)
  {
    thr.join();
  }
}

//
// Defaults
//
constexpr size_t DefaultBufSize = 64;
constexpr size_t DefaultMessageSize = 16;
constexpr size_t DefaultWriterCount = 4;

// If you want to use this many messages, keep samples low
const std::vector<int> msg_counts = {1000, 4000, 16000};

//
// Use s.iterations() as each test arg, template the remainder
//
template <
  size_t BufSize = DefaultBufSize,
  size_t MessageSize = DefaultMessageSize,
  size_t WriterCount = DefaultWriterCount,
  ReadHandler H = nop_handler>
static void specialize(picobench::state& s)
{
  const auto msg_count = s.iterations();

  write_impl<H>(s, BufSize, MessageSize, WriterCount, msg_count);
}

//
// Benchmark suites
//
#define FIXED_PICO(NAME) PICOBENCH(NAME).iterations(msg_counts)

PICOBENCH_SUITE("default");
auto base = specialize<>;
FIXED_PICO(base);

PICOBENCH_SUITE("increasing buffer size");
auto buf_64b = specialize<64>;
FIXED_PICO(buf_64b);
auto buf_256b = specialize<256>;
FIXED_PICO(buf_256b);
auto buf_1k = specialize<1024>;
FIXED_PICO(buf_1k);
auto buf_4k = specialize<4096>;
FIXED_PICO(buf_4k);
auto buf_16k = specialize<16384>;
FIXED_PICO(buf_16k);

PICOBENCH_SUITE("increasing message size (4k buffer)");
auto size_empty = specialize<4096, 0>;
FIXED_PICO(size_empty);
auto size_1b = specialize<4096, 1>;
FIXED_PICO(size_1b);
auto size_4b = specialize<4096, 4>;
FIXED_PICO(size_4b);
auto size_16b = specialize<4096, 16>;
FIXED_PICO(size_16b);
auto size_64b = specialize<4096, 64>;
FIXED_PICO(size_64b);
auto size_256b = specialize<4096, 256>;
FIXED_PICO(size_256b);
auto size_1k = specialize<4096, 1024>;
FIXED_PICO(size_1k);

PICOBENCH_SUITE("increasing writers (4k buffer, 64b per-message)");
auto writers_1 = specialize<4096, 64, 1>;
FIXED_PICO(writers_1);
auto writers_2 = specialize<4096, 64, 2>;
FIXED_PICO(writers_2);
auto writers_4 = specialize<4096, 64, 4>;
FIXED_PICO(writers_4);
auto writers_8 = specialize<4096, 64, 8>;
FIXED_PICO(writers_8);
auto writers_16 = specialize<4096, 64, 16>;
FIXED_PICO(writers_16);
auto writers_32 = specialize<4096, 64, 32>;
FIXED_PICO(writers_32);

PICOBENCH_SUITE("high contention (32b buffer, 4b per-message)");
auto contention_4 = specialize<32, 4, 4>;
FIXED_PICO(contention_4);
auto contention_8 = specialize<32, 4, 8>;
FIXED_PICO(contention_8);
auto contention_16 = specialize<32, 4, 16>;
FIXED_PICO(contention_16);
auto contention_32 = specialize<32, 4, 32>;
FIXED_PICO(contention_32);

PICOBENCH_SUITE("spinning reader (32b buffer, 1b per-message, 4 writers)");
auto spin_100 = specialize<32, 1, 4, spin_pause_handler<100>>;
FIXED_PICO(spin_100);
auto spin_200 = specialize<32, 1, 4, spin_pause_handler<200>>;
FIXED_PICO(spin_200);
auto spin_400 = specialize<32, 1, 4, spin_pause_handler<400>>;
FIXED_PICO(spin_400);
