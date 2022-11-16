// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "../oversized.h"

#include "../non_blocking.h"

#include <algorithm>
#include <doctest/doctest.h>
#include <functional>
#include <numeric>
#include <thread>
#include <vector>

enum : ringbuffer::Message
{
  DEFINE_RINGBUFFER_MSG_TYPE(ascending),
  DEFINE_RINGBUFFER_MSG_TYPE(descending),
  DEFINE_RINGBUFFER_MSG_TYPE(unfragmented),
  DEFINE_RINGBUFFER_MSG_TYPE(random_contents),
  DEFINE_RINGBUFFER_MSG_TYPE(finish),
};

constexpr uint8_t unfragmented_magic_value = 42;

TEST_CASE("Reconstruction" * doctest::test_suite("oversized"))
{
  constexpr size_t payload_size = 100;
  std::vector<uint8_t> whole_message_ascending(payload_size);
  std::iota(whole_message_ascending.begin(), whole_message_ascending.end(), 0);
  std::vector<uint8_t> whole_message_descending(
    whole_message_ascending.rbegin(), whole_message_ascending.rend());

  messaging::RingbufferDispatcher disp("oversized");
  size_t complete_messages = 0;

  SUBCASE("Handler for fragment is registered for object lifetime")
  {
    {
      REQUIRE_FALSE(disp.has_handler(oversized::OversizedMessage::fragment));
      oversized::FragmentReconstructor fr(disp);
      REQUIRE(disp.has_handler(oversized::OversizedMessage::fragment));
    }
    REQUIRE_FALSE(disp.has_handler(oversized::OversizedMessage::fragment));
  }

  DISPATCHER_SET_MESSAGE_HANDLER(
    disp, ascending, [&](const uint8_t* data, size_t size) {
      REQUIRE(size == payload_size);
      REQUIRE(std::is_sorted(data, data + size, std::less_equal<uint8_t>()));
      ++complete_messages;
    });

  DISPATCHER_SET_MESSAGE_HANDLER(
    disp, descending, [&](const uint8_t* data, size_t size) {
      REQUIRE(size == payload_size);
      REQUIRE(std::is_sorted(data, data + size, std::greater_equal<uint8_t>()));
      ++complete_messages;
    });

  DISPATCHER_SET_MESSAGE_HANDLER(
    disp, unfragmented, [&](const uint8_t* data, size_t size) {
      REQUIRE(size == 1);
      REQUIRE(*data == unfragmented_magic_value);
      ++complete_messages;
    });

  struct MessageStream
  {
    ringbuffer::Message type;
    size_t id;
    size_t progress;
  };

  auto write_unfragmented = [&]() {
    const uint8_t data = unfragmented_magic_value;
    disp.dispatch(unfragmented, &data, sizeof(data));
  };

  auto write_more = [&](MessageStream& ms, size_t fragment_size) {
    if (ms.type != ascending && ms.type != descending)
      REQUIRE_MESSAGE(false, "Unexpected ms type");

    const auto complete_prior = complete_messages;

    std::vector<uint8_t> fragment_body(sizeof(ms.id));
    {
      // Write the identifier of the larger message
      uint8_t* raw = fragment_body.data();
      size_t remaining = fragment_body.size();
      serialized::write(raw, remaining, ms.id);
      REQUIRE(remaining == 0);
    }

    if (ms.progress == 0)
    {
      // Write header
      const auto init_size = fragment_body.size();
      fragment_body.resize(init_size + sizeof(ms.type) + sizeof(payload_size));

      uint8_t* raw = fragment_body.data() + init_size;
      size_t remaining = fragment_body.size() - init_size;
      serialized::write(raw, remaining, ms.type);
      serialized::write(raw, remaining, payload_size);
      REQUIRE(remaining == 0);
    }

    {
      // Write the fragment body
      const auto init_size = fragment_body.size();
      const auto remaining_body =
        std::min(fragment_size, payload_size - ms.progress);
      fragment_body.resize(init_size + remaining_body);

      uint8_t* raw = fragment_body.data() + init_size;
      size_t remaining = fragment_body.size() - init_size;
      const uint8_t* source = (ms.type == ascending ? whole_message_ascending :
                                                      whole_message_descending)
                                .data();
      serialized::write(raw, remaining, source + ms.progress, remaining_body);
      ms.progress += remaining_body;
      REQUIRE(remaining == 0);
    }

    disp.dispatch(
      oversized::OversizedMessage::fragment,
      fragment_body.data(),
      fragment_body.size());

    // Return true iff dispatching completed another message
    return complete_prior < complete_messages;
  };

  constexpr size_t fragment_sizes[] = {
    payload_size,
    payload_size / 2,
    payload_size / 3,
    payload_size / 5,
    payload_size / 7};
  constexpr auto fragment_size_count =
    sizeof(fragment_sizes) / sizeof(fragment_sizes[0]);

  SUBCASE("Reconstruction of individual message")
  {
    oversized::FragmentReconstructor fr(disp);

    // Try several different message sizes, including awkward remainders
    for (size_t fragment_size : fragment_sizes)
    {
      const auto complete_prior = complete_messages;

      MessageStream ms{ascending, 0, 0};

      while (!write_more(ms, fragment_size))
      {
      }

      REQUIRE(complete_messages == complete_prior + 1);
    }
  }

  SUBCASE("Reconstruction from interleaved messages")
  {
    oversized::FragmentReconstructor fr(disp);

    std::vector<MessageStream> streams;
    streams.push_back({ascending, 0, 0});
    streams.push_back({ascending, 1, 0});
    streams.push_back({descending, 2, 0});
    streams.push_back({descending, 3, 0});

    const auto seed = time(NULL);
    INFO("Using seed: ", seed);
    srand(seed);

    while (!streams.empty())
    {
      const auto complete_prior = complete_messages;

      const auto choice = rand() % (streams.size() + 1);
      if (choice == streams.size())
      {
        write_unfragmented();
        REQUIRE(complete_messages == complete_prior + 1);
      }
      else
      {
        // Vary fragment size, even within a single message stream
        const auto fragment_size = fragment_sizes[rand() % fragment_size_count];

        if (write_more(streams[choice], fragment_size))
        {
          REQUIRE(complete_messages == complete_prior + 1);
          streams.erase(streams.begin() + choice);
        }
      }
    }
  }
}

TEST_CASE("Writing" * doctest::test_suite("oversized"))
{
  constexpr size_t buf_size = 1 << 8;
  auto buffer = std::make_unique<ringbuffer::TestBuffer>(buf_size);
  ringbuffer::Reader rr(buffer->bd);

  constexpr auto fragment_max = buf_size / 8;
  constexpr auto total_max = buf_size / 3;
  oversized::Writer writer(
    std::make_unique<ringbuffer::Writer>(rr), fragment_max, total_max);

  std::vector<uint8_t> whole_message_ascending(total_max);
  std::iota(whole_message_ascending.begin(), whole_message_ascending.end(), 0);
  std::vector<uint8_t> whole_message_descending(
    whole_message_ascending.rbegin(), whole_message_ascending.rend());

  SUBCASE("Bad maximum fragment sizes are disallowed")
  {
    REQUIRE_THROWS_AS(
      oversized::Writer(
        std::make_unique<ringbuffer::Writer>(rr),
        sizeof(oversized::InitialFragmentHeader),
        total_max),
      std::logic_error);
    REQUIRE_NOTHROW(oversized::Writer(
      std::make_unique<ringbuffer::Writer>(rr),
      sizeof(oversized::InitialFragmentHeader) + 1,
      total_max));

    REQUIRE_NOTHROW(oversized::Writer(
      std::make_unique<ringbuffer::Writer>(rr), total_max - 1, total_max));
    REQUIRE_THROWS_AS(
      oversized::Writer(
        std::make_unique<ringbuffer::Writer>(rr), total_max, total_max),
      std::logic_error);
  }

  SUBCASE("Attempting write larger than max will throw")
  {
    REQUIRE_THROWS_AS(
      writer.write(
        ascending,
        serializer::ByteRange{whole_message_ascending.data(), total_max + 1}),
      std::logic_error);
  }

  messaging::BufferProcessor bp("oversized");

  auto read_single = [&]() {
    // When reading the padding at the end of the ringbuffer, the first call to
    // read will return 0 even though there's still a message at the start to be
    // read. To guarantee a read of a single message (and be sure it was the
    // only message), we want to read up-to-1-message 3 times. That will either
    // return {1, 0, 0} (most of the time), or {0, 1, 0} occasionally.

    auto first_read = bp.read_n(1, rr);
    auto second_read = bp.read_n(1, rr);
    auto third_read = bp.read_n(1, rr);

    REQUIRE(first_read <= 1);

    if (first_read == 1)
      REQUIRE(second_read == 0);
    else
      REQUIRE(second_read == 1);

    REQUIRE(third_read == 0);
  };

  size_t last_message_size = 0;
  size_t ascending_reads = 0;
  size_t descending_reads = 0;

  DISPATCHER_SET_MESSAGE_HANDLER(
    bp, ascending, [&](const uint8_t* data, size_t size) {
      REQUIRE(std::is_sorted(data, data + size, std::less_equal<uint8_t>()));
      last_message_size = size;
      ++ascending_reads;
    });

  DISPATCHER_SET_MESSAGE_HANDLER(
    bp, descending, [&](const uint8_t* data, size_t size) {
      REQUIRE(std::is_sorted(data, data + size, std::greater_equal<uint8_t>()));
      last_message_size = size;
      ++descending_reads;
    });

  DISPATCHER_SET_MESSAGE_HANDLER(
    bp, finish, [&](const uint8_t* data, size_t size) {
      bp.set_finished(true);
    });

  SUBCASE("Small writes succeed")
  {
    for (size_t msg_size = 0; msg_size <= fragment_max; ++msg_size)
    {
      const size_t ascending_prior = ascending_reads;
      REQUIRE(writer.try_write(
        ascending,
        serializer::ByteRange{whole_message_ascending.data(), msg_size}));
      read_single();
      REQUIRE(last_message_size == msg_size);
      REQUIRE(ascending_reads == ascending_prior + 1);

      const size_t descending_prior = descending_reads;
      REQUIRE(writer.try_write(
        descending,
        serializer::ByteRange{whole_message_descending.data(), msg_size}));
      read_single();
      REQUIRE(last_message_size == msg_size);
      REQUIRE(descending_reads == descending_prior + 1);
    }
  }

  SUBCASE("Large writes can succeed")
  {
    size_t ascending_writes = ascending_reads;
    size_t descending_writes = descending_reads;
    constexpr auto last_send_size = total_max - 1;

    // If the caller is not willing to wait, then the write can fail due to
    // insufficient space
    while (writer.try_write(
      ascending,
      serializer::ByteRange{whole_message_ascending.data(), fragment_max}))
    {
      ++ascending_writes;
    }

    // If a reader is making progress (in this case - reconstructing the larger
    // message from fragments), large writes which are willing to wait will
    // eventually succeed
    std::thread reader_thread([&]() {
      oversized::FragmentReconstructor fr(bp.get_dispatcher());

      bp.run(rr);
    });

    REQUIRE_NOTHROW(writer.write(
      ascending,
      serializer::ByteRange{whole_message_ascending.data(), total_max}));
    ++ascending_writes;

    REQUIRE_NOTHROW(writer.write(
      ascending,
      serializer::ByteRange{whole_message_ascending.data(), total_max}));
    ++ascending_writes;

    REQUIRE_NOTHROW(writer.write(
      descending,
      serializer::ByteRange{whole_message_descending.data(), total_max}));
    ++descending_writes;

    REQUIRE_NOTHROW(writer.write(
      ascending,
      serializer::ByteRange{whole_message_ascending.data(), total_max}));
    ++ascending_writes;

    REQUIRE_NOTHROW(writer.write(
      descending,
      serializer::ByteRange{whole_message_descending.data(), total_max}));
    ++descending_writes;

    REQUIRE_NOTHROW(writer.write(
      ascending,
      serializer::ByteRange{whole_message_ascending.data(), last_send_size}));
    ++ascending_writes;

    REQUIRE_NOTHROW(writer.write(finish));

    reader_thread.join();

    REQUIRE(last_message_size == last_send_size);

    REQUIRE(ascending_reads == ascending_writes);
    REQUIRE(descending_reads == descending_writes);
  }

  SUBCASE("Progress with low limits")
  {
    // Construct a worst-case Writer, which can only fit the minimal payload in
    // each message. It will still complete, eventually
    constexpr auto small_fragment_limit =
      sizeof(oversized::InitialFragmentHeader) + 1;
    constexpr auto large_message_size = buf_size;
    oversized::Writer writer(
      std::make_unique<ringbuffer::Writer>(rr),
      small_fragment_limit,
      large_message_size);

    std::vector<uint8_t> large_ascending(large_message_size);
    std::iota(large_ascending.begin(), large_ascending.end(), 0);

    std::thread reader_thread([&]() {
      oversized::FragmentReconstructor fr(bp.get_dispatcher());

      bp.run(rr);
    });

    const auto ascending_prior = ascending_reads;

    REQUIRE_NOTHROW(writer.write(
      ascending,
      serializer::ByteRange{large_ascending.data(), large_message_size}));

    REQUIRE_NOTHROW(writer.write(finish));

    reader_thread.join();

    REQUIRE(last_message_size == large_message_size);
    REQUIRE(ascending_reads == ascending_prior + 1);
  }
}

TEST_CASE("Nesting" * doctest::test_suite("oversized"))
{
  INFO("Nested fragment messages are allowed, and parsed correctly");
  std::vector<uint8_t> payload;
  payload.push_back(unfragmented_magic_value);

  ringbuffer::Message type = unfragmented;

  // For some number of nested layers
  for (size_t i = 0; i < 20; ++i)
  {
    std::vector<uint8_t> wrapper;

    // Create a new fragment message containing the previous payload...
    {
      // [ID, type, total_size, payload...]
      wrapper.resize(
        sizeof(size_t) + sizeof(ringbuffer::Message) + sizeof(size_t) +
        payload.size());

      auto data = wrapper.data();
      auto size = wrapper.size();
      serialized::write(data, size, i);
      serialized::write(data, size, type);
      serialized::write(data, size, payload.size());
      serialized::write(data, size, payload.data(), payload.size());

      REQUIRE(size == 0);
    }

    // ...and set this to be the payload for the next iteration
    payload = wrapper;
    type = oversized::OversizedMessage::fragment;
  }

  // Dispatch the resulting coccoon
  messaging::RingbufferDispatcher disp("Nesting");

  bool core_received = false;
  DISPATCHER_SET_MESSAGE_HANDLER(
    disp, unfragmented, [&](const uint8_t* data, size_t size) {
      core_received = true;
    });

  {
    oversized::FragmentReconstructor fr(disp);
    disp.dispatch(type, payload.data(), payload.size());
    REQUIRE(core_received);
  }
}

TEST_CASE("Non-blocking" * doctest::test_suite("oversized"))
{
  using namespace ringbuffer;

  constexpr auto circuit_size = 1 << 8;

  auto in_buffer = std::make_unique<ringbuffer::TestBuffer>(circuit_size);
  auto out_buffer = std::make_unique<ringbuffer::TestBuffer>(circuit_size);

  ringbuffer::Circuit circuit(in_buffer->bd, out_buffer->bd);

  constexpr auto max_fragment_size = circuit_size / 5;
  constexpr auto max_total_size = circuit_size * 4;
  oversized::WriterConfig writer_config{max_fragment_size, max_total_size};

  // We want a basic writer...
  ringbuffer::WriterFactory basic_factory(circuit);

  // ...wrapped in a writer which will queue rather than blocking
  // indefinitely...
  ringbuffer::NonBlockingWriterFactory non_blocking_factory(basic_factory);

  // ...wrapped in a writer which will split large messages into fragments
  oversized::WriterFactory oversized_factory(
    non_blocking_factory, writer_config);

  auto writer = oversized_factory.create_writer_to_inside();

  // Build some large messages
  constexpr auto num_messages = 10;
  std::vector<std::vector<uint8_t>> messages;
  for (size_t i = 0; i < num_messages; ++i)
  {
    auto& message = messages.emplace_back(max_total_size);
    for (auto& n : message)
    {
      n = rand();
    }
  }

  // Write them all
  for (const auto& message : messages)
  {
    writer->write(random_contents, message);
  }

  decltype(messages) received;
  auto random_handler = [&](const uint8_t* data, size_t size) {
    received.emplace_back(data, data + size);
  };

  messaging::BufferProcessor processor_inside;
  DISPATCHER_SET_MESSAGE_HANDLER(
    processor_inside, random_contents, random_handler);

  oversized::FragmentReconstructor reconstructor(
    processor_inside.get_dispatcher());

  // Read them all, by flushing repeatedly
  while (true)
  {
    const bool done_flushing = non_blocking_factory.flush_all_inbound();

    size_t n_read = processor_inside.read_all(circuit.read_from_outside());

    REQUIRE(n_read > 0);

    if (received.size() == messages.size())
    {
      REQUIRE(done_flushing);
      REQUIRE(received == messages);
      break;
    }
  }
}