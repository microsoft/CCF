// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "../oversized.h"

#include <doctest/doctest.h>

enum : ringbuffer::Message
{
  DEFINE_RINGBUFFER_MSG_TYPE(large_block_message),
  DEFINE_RINGBUFFER_MSG_TYPE(large_compound_message),
  DEFINE_RINGBUFFER_MSG_TYPE(large_complex_message),
  DEFINE_RINGBUFFER_MSG_TYPE(finish),
};

DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(large_block_message, std::vector<uint8_t>);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  large_compound_message, size_t, std::vector<uint8_t>);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
  large_complex_message,
  uint16_t,
  bool,
  uint32_t,
  std::string,
  bool,
  uint16_t,
  uint64_t,
  std::vector<uint8_t>);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(finish);

TEST_CASE(
  "Large message reconstruction" * doctest::test_suite("typed_messages"))
{
  constexpr size_t buf_size = 1 << 8;

  auto buffer = std::make_unique<ringbuffer::TestBuffer>(buf_size);
  ringbuffer::Reader rr(buffer->bd);

  constexpr auto fragment_max = buf_size / 8;
  constexpr auto total_max = buf_size / 3;
  oversized::Writer writer(
    std::make_unique<ringbuffer::Writer>(rr), fragment_max, total_max);
  auto writer_p = &writer;

  messaging::BufferProcessor bp("typed_messages");
  oversized::FragmentReconstructor fr(bp.get_dispatcher());
  DISPATCHER_SET_MESSAGE_HANDLER(
    bp, finish, [&bp](const uint8_t* data, size_t size) {
      bp.set_finished(true);
    });

  SUBCASE("block message")
  {
    bool message_seen = false;

    std::vector<uint8_t> sent(fragment_max * 2);
    std::iota(sent.begin(), sent.end(), 0);

    DISPATCHER_SET_MESSAGE_HANDLER(
      bp, large_block_message, [&](const uint8_t* data, size_t size) {
        auto [body] = ringbuffer::read_message<large_block_message>(data, size);
        REQUIRE(body == sent);

        REQUIRE(!message_seen);
        message_seen = true;
      });

    RINGBUFFER_WRITE_MESSAGE(large_block_message, writer_p, sent);
    RINGBUFFER_WRITE_MESSAGE(finish, writer_p);
    bp.run(rr);
    REQUIRE(message_seen);
  }

  SUBCASE("compound message")
  {
    bool message_seen = false;

    size_t sent_n = 42u;
    std::vector<uint8_t> sent_body(fragment_max * 2);
    std::iota(sent_body.begin(), sent_body.end(), 0);

    DISPATCHER_SET_MESSAGE_HANDLER(
      bp, large_compound_message, [&](const uint8_t* data, size_t size) {
        auto [n, body] =
          ringbuffer::read_message<large_compound_message>(data, size);

        REQUIRE(n == sent_n);
        REQUIRE(body == sent_body);

        REQUIRE(!message_seen);
        message_seen = true;
      });

    RINGBUFFER_WRITE_MESSAGE(
      large_compound_message, writer_p, sent_n, sent_body);
    RINGBUFFER_WRITE_MESSAGE(finish, writer_p);
    bp.run(rr);
    REQUIRE(message_seen);
  }

  SUBCASE("complex message")
  {
    bool message_seen = false;

    const uint16_t a = 16;
    const bool b = true;
    const uint32_t c = 42;
    const std::string d = "COMPLEX";
    const bool e = false;
    const uint16_t f = 1661;
    const uint64_t g = 0xdeadbeef;
    const std::vector<uint8_t> h{1, 2, 3, 4, 5};

    DISPATCHER_SET_MESSAGE_HANDLER(
      bp, large_complex_message, [&](const uint8_t* data, size_t size) {
        auto [aa, bb, cc, dd, ee, ff, gg, hh] =
          ringbuffer::read_message<large_complex_message>(data, size);

        REQUIRE(a == aa);
        REQUIRE(b == bb);
        REQUIRE(c == cc);
        REQUIRE(d == dd);
        REQUIRE(e == ee);
        REQUIRE(f == ff);
        REQUIRE(g == gg);
        REQUIRE(h == hh);

        REQUIRE(!message_seen);
        message_seen = true;
      });

    RINGBUFFER_WRITE_MESSAGE(
      large_complex_message, writer_p, a, b, c, d, e, f, g, h);
    RINGBUFFER_WRITE_MESSAGE(finish, writer_p);
    bp.run(rr);
    REQUIRE(message_seen);
  }
}
