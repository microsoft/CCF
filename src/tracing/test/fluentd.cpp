// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "tracing/test/events.h"

#include <arpa/inet.h>
#include <doctest/doctest.h>

namespace request_trace
{
  struct EncodingProbe
  {
    bool& encoded;
  };
  inline void write_msgpack(std::vector<uint8_t>&, const EncodingProbe& probe)
  {
    probe.encoded = true;
  }
}

template <typename... Args>
concept EmitArguments =
  requires(const Args&... args) { ccf::tracing::emit("ccf.test", args...); };

static_assert(EmitArguments<>);
static_assert(EmitArguments<char[4], int, std::string_view, bool>);
static_assert(!EmitArguments<char[4]>);
static_assert(!EmitArguments<int, int>);

namespace
{
  thread_local bool forbid_allocation = false;
  thread_local size_t allocations = 0;
  thread_local size_t allocation_failure = 0;
  std::atomic<bool> stalled = false;
  std::atomic<size_t> calls = 0;
  std::atomic<size_t> fail_at = 0;
  std::atomic<bool> wrong_thread = false;
  std::thread::id producer;
  struct DropLogger : ccf::logger::AbstractLogger
  {
    std::atomic<size_t> reports = 0;
    void write(const ccf::logger::LogLine& line) override
    {
      if (line.msg.find("trace events") != std::string::npos)
        ++reports;
    }
  };
}

extern "C" ssize_t __real_send(int, const void*, size_t, int);
extern "C" void* __real__Znwm(size_t);
extern "C" void* __wrap__Znwm(size_t size)
{
  ++allocations;
  if (forbid_allocation || allocations == allocation_failure)
    throw std::bad_alloc();
  return __real__Znwm(size);
}
extern "C" ssize_t __wrap_send(int fd, const void* data, size_t size, int flags)
{
  const auto call = ++calls;
  if (call == fail_at)
  {
    errno = EPIPE;
    return -1;
  }
  if (std::this_thread::get_id() == producer)
    wrong_thread = true;
  if (stalled)
  {
    errno = EAGAIN;
    return -1;
  }
  // Every successful write is short, including the EventTime extension.
  return __real_send(fd, data, std::min(size, size_t(7)), flags);
}

TEST_CASE("SPSC queue owns records, rejects before allocating and wraps")
{
  using Queue = ccf::tracing::SPSCQueue;
  CHECK_THROWS_AS(Queue(0), std::invalid_argument);
  CHECK_NOTHROW(Queue(size_t{1024} * 1024 + 1));
  Queue queue(3);
  CHECK(queue.size() == 0);
  CHECK(queue.pop() == nullptr);
  std::array<uint8_t, 37> payload = {};
  for (size_t round = 0; round < 64; ++round)
  {
    for (uint8_t i = 0; i < 3; ++i)
    {
      payload.fill(i);
      REQUIRE(queue.push(payload));
      CHECK(queue.size() == i + 1);
    }
    const auto before = allocations;
    const auto full = queue.push(payload);
    const auto after = allocations;
    CHECK_FALSE(full);
    CHECK(after == before);
    CHECK(queue.size() == 3);
    for (size_t expected = 0; expected < 3; ++expected)
    {
      const auto before_pop = allocations;
      auto record = queue.pop();
      const auto after_pop = allocations;
      CHECK(before_pop == after_pop);
      REQUIRE(record != nullptr);
      CHECK(queue.size() == 2 - expected);
      CHECK(record->size() == payload.size());
      for (auto byte : *record)
        CHECK(byte == expected);
    }
    CHECK(queue.size() == 0);
    CHECK(queue.pop() == nullptr);
  }
  for (size_t failure = 1; failure <= 2; ++failure)
  {
    allocation_failure = allocations + failure;
    const auto pushed = queue.push(payload);
    allocation_failure = 0;
    CHECK_FALSE(pushed);
    CHECK(queue.pop() == nullptr);
    REQUIRE(queue.push(payload));
    CHECK(queue.pop() != nullptr);
  }
  std::vector<uint8_t> large(Queue::MAX_RECORD_SIZE + 1);
  const auto before = allocations;
  const auto oversized = queue.push(large);
  const auto after = allocations;
  CHECK_FALSE(oversized);
  CHECK(before == after);
  large.pop_back();
  REQUIRE(queue.push(large));
  auto record = queue.pop();
  REQUIRE(record != nullptr);
  CHECK(record->size() == Queue::MAX_RECORD_SIZE);
  REQUIRE(queue.push({}));
  auto empty = queue.pop();
  REQUIRE(empty != nullptr);
  CHECK(empty->empty());
}

TEST_CASE("Nested object encoding does not allocate into a reserved buffer")
{
  std::vector<uint8_t> bytes;
  bytes.reserve(2048);
  const auto before = allocations;
  request_trace::write_msgpack(bytes, request_trace::Nested{7, false});
  const auto after = allocations;
  CHECK(after == before);
  CHECK(nlohmann::json::from_msgpack(bytes)["number"] == 7);
}

TEST_CASE("Trace configuration has no arbitrary producer or capacity ceiling")
{
  using Sink = ccf::tracing::FluentdSink;
  Sink::Endpoint endpoint{"127.0.0.1", "24224"};
  endpoint.queue_capacity = size_t{1024} * 1024 + 1;
  CHECK(Sink::validate(endpoint, 65536) == endpoint.queue_capacity);
  CHECK_THROWS_AS(Sink::validate(endpoint, 0), std::invalid_argument);
  endpoint.queue_capacity = 0;
  CHECK_THROWS_AS(Sink::validate(endpoint), std::invalid_argument);
}

TEST_CASE("SPSC concurrent FIFO records outlive reused slots and the queue")
{
  auto queue = std::make_unique<ccf::tracing::SPSCQueue>(3);
  constexpr uint64_t count = 10000;
  const auto deadline =
    std::chrono::steady_clock::now() + std::chrono::seconds(5);
  std::thread writer([&] {
    std::array<uint8_t, 37> payload;
    for (uint64_t i = 0; i < count; ++i)
    {
      payload.fill(i % 251);
      std::memcpy(payload.data(), &i, sizeof(i));
      while (!queue->push(payload))
      {
        if (std::chrono::steady_clock::now() >= deadline)
          return;
        std::this_thread::yield();
      }
      payload.fill(0xff);
    }
  });
  std::vector<std::unique_ptr<std::vector<uint8_t>>> retained;
  retained.reserve(50);
  uint64_t expected = 0;
  while (expected < count && std::chrono::steady_clock::now() < deadline)
  {
    auto record = queue->pop();
    if (record)
    {
      CHECK(record->size() == 37);
      if (record->size() != 37)
        break;
      uint64_t sequence;
      std::memcpy(&sequence, record->data(), sizeof(sequence));
      CHECK(sequence == expected);
      for (size_t i = sizeof(sequence); i < record->size(); ++i)
        CHECK((*record)[i] == expected % 251);
      if (retained.size() < 50)
        retained.push_back(std::move(record));
      ++expected;
    }
    else
      std::this_thread::yield();
  }
  writer.join();
  CHECK(expected == count);
  CHECK(queue->size() == 0);
  CHECK(queue->pop() == nullptr);
  queue.reset();
  CHECK(retained.size() == 50);
  for (size_t i = 0; i < retained.size(); ++i)
  {
    uint64_t sequence;
    std::memcpy(&sequence, retained[i]->data(), sizeof(sequence));
    CHECK(sequence == i);
    for (size_t j = sizeof(sequence); j < retained[i]->size(); ++j)
      CHECK((*retained[i])[j] == i % 251);
  }
}

TEST_CASE("SPSC export: framing, producer isolation, drops and shutdown")
{
  using Sink = ccf::tracing::FluentdSink;
  producer = std::this_thread::get_id();
  bool encoded = false;
  const auto before_unconfigured = allocations;
  ccf::tracing::emit(
    "ccf.request", "probe", request_trace::EncodingProbe{encoded});
  request_trace::single(request_trace::EncodingProbe{encoded});
  const auto after_unconfigured = allocations;
  CHECK(after_unconfigured == before_unconfigured);
  CHECK_FALSE(encoded);
  CHECK_FALSE(Sink::enqueue({}));
  CHECK_FALSE(Sink::wait_for_connection(std::chrono::milliseconds(0)));
  CHECK_THROWS_AS(
    Sink::configure(Sink::Endpoint{"127.0.0.1", "0"}), std::invalid_argument);
  CHECK_THROWS_AS(
    Sink::configure(Sink::Endpoint{"127.0.0.1", "65536"}),
    std::invalid_argument);
  CHECK_THROWS_AS(
    Sink::configure(Sink::Endpoint{"127.0.0.1", "42extra"}),
    std::invalid_argument);
  auto invalid = Sink::Endpoint{"127.0.0.1", "24224"};
  invalid.queue_capacity = 0;
  CHECK_THROWS_AS(Sink::configure(invalid), std::invalid_argument);
  const int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  REQUIRE(listener >= 0);
  sockaddr_in address = {};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  REQUIRE(bind(listener, (sockaddr*)&address, sizeof(address)) == 0);
  socklen_t size = sizeof(address);
  REQUIRE(getsockname(listener, (sockaddr*)&address, &size) == 0);
  Sink::Endpoint endpoint{"127.0.0.1", std::to_string(ntohs(address.sin_port))};
  endpoint.queue_capacity = 3;
  Sink::configure(endpoint, 2);
  Sink::bind_producer(0);
  const auto waiting = std::chrono::steady_clock::now();
  CHECK_FALSE(Sink::wait_for_connection(std::chrono::milliseconds(150)));
  CHECK(std::chrono::steady_clock::now() - waiting < std::chrono::seconds(1));
  CHECK(calls == 0);
  REQUIRE(listen(listener, 1) == 0);
  REQUIRE(Sink::wait_for_connection(std::chrono::seconds(2)));
  CHECK(calls == 0);
  CHECK(Sink::dropped_count() == 0);
  int peer = accept(listener, nullptr, nullptr);
  REQUIRE(peer >= 0);
  // Fail the first buffer reserve, then process identity initialization.
  for (size_t failure = 1; failure <= 2; ++failure)
  {
    const auto before = Sink::dropped_count();
    allocation_failure = allocations + failure;
    CHECK_NOTHROW(ccf::tracing::emit("ccf.request", "status", 200));
    allocation_failure = 0;
    CHECK(Sink::dropped_count() == before + 1);
  }
  ccf::tracing::emit(
    "ccf.request", "path", "/app/log", "status", 200, "cached", false);
  const auto typed_frame =
    nlohmann::json::from_msgpack(ccf::tracing::event_buffer());
  CHECK(
    typed_frame[2]["msg"] ==
    nlohmann::json{{"path", "/app/log"}, {"status", 200}, {"cached", false}});
  std::vector<uint8_t> bytes;
  std::array<uint8_t, 256> chunk;
  nlohmann::json frame;
  while (frame.is_null())
  {
    const auto n = recv(peer, chunk.data(), chunk.size(), 0);
    REQUIRE(n > 0);
    bytes.insert(bytes.end(), chunk.begin(), chunk.begin() + n);
    auto decoded = nlohmann::json::from_msgpack(bytes, true, false);
    if (!decoded.is_discarded())
      frame = std::move(decoded);
  }
  CHECK(frame[0] == "ccf.request");
  CHECK(frame[1].is_binary());
  CHECK(frame[1].get_binary().subtype() == 0);
  CHECK(frame[1].get_binary().size() == 8);
  CHECK(
    frame[2]["msg"] ==
    nlohmann::json{{"path", "/app/log"}, {"status", 200}, {"cached", false}});
  CHECK(frame[2]["h_ts"] == 2);
  CHECK(frame[2]["process_id"].is_string());
  CHECK_FALSE(wrong_thread);

  const auto check_event =
    [&](auto emit, const nlohmann::ordered_json& expected) {
      emit();
      const auto& buffer = ccf::tracing::event_buffer();
      const auto event = nlohmann::ordered_json::from_msgpack(buffer);
      CHECK(
        nlohmann::ordered_json::to_msgpack(event[2]["msg"]) ==
        nlohmann::ordered_json::to_msgpack(expected));
      std::vector<uint8_t> actual(buffer.size());
      REQUIRE(
        recv(peer, actual.data(), actual.size(), MSG_WAITALL) ==
        static_cast<ssize_t>(actual.size()));
      CHECK(actual == buffer);
    };
  check_event([] { request_trace::empty(); }, {{"function", "empty"}});
  check_event(
    request_trace::empty_from_other_translation_unit, {{"function", "empty"}});
  check_event(
    [] { request_trace::single(request_trace::Nested{7, false}); },
    {{"function", "single"}, {"value", {{"number", 7}, {"flag", false}}}});
  check_event(
    request_trace::single_from_other_translation_unit,
    {{"function", "single"}, {"value", {{"number", 7}, {"flag", false}}}});
  int evaluations = 0;
  check_event(
    [&] { request_trace::request("/app/log", ++evaluations, false); },
    {{"function", "request"},
     {"path", "/app/log"},
     {"status", 1},
     {"cached", false}});
  CHECK(evaluations == 1);

  const std::string large_value(
    ccf::tracing::event_buffer().capacity() + 1, 'x');
  const auto before_encoding_failure = Sink::dropped_count();
  allocation_failure = allocations + 1;
  CHECK_NOTHROW(request_trace::single(large_value));
  allocation_failure = 0;
  CHECK(Sink::dropped_count() == before_encoding_failure + 1);
  check_event([] { request_trace::empty(); }, {{"function", "empty"}});

  const std::string oversized_value(
    ccf::tracing::SPSCQueue::MAX_RECORD_SIZE, 'x');
  const auto before_oversized = Sink::dropped_count();
  request_trace::single(oversized_value);
  CHECK(Sink::dropped_count() == before_oversized + 1);
  check_event([] { request_trace::empty(); }, {{"function", "empty"}});

  std::thread second([&] {
    Sink::bind_producer(1);
    CHECK(Sink::enqueue(bytes));
  });
  second.join();
  std::vector<uint8_t> received(bytes.size());
  REQUIRE(
    recv(peer, received.data(), received.size(), MSG_WAITALL) ==
    static_cast<ssize_t>(received.size()));
  CHECK(received == bytes);

  const auto drops_before_disconnect = Sink::dropped_count();
  fail_at = calls + 2;
  REQUIRE(Sink::enqueue(bytes));
  REQUIRE(recv(peer, chunk.data(), chunk.size(), MSG_WAITALL) == 7);
  CHECK(recv(peer, chunk.data(), chunk.size(), 0) == 0);
  close(peer);
  const auto drop_deadline =
    std::chrono::steady_clock::now() + std::chrono::seconds(1);
  while (Sink::dropped_count() == drops_before_disconnect &&
         std::chrono::steady_clock::now() < drop_deadline)
    std::this_thread::yield();
  CHECK(Sink::dropped_count() == drops_before_disconnect + 1);
  REQUIRE(Sink::wait_for_connection(std::chrono::seconds(2)));
  REQUIRE(Sink::enqueue(bytes));
  peer = accept(listener, nullptr, nullptr);
  REQUIRE(peer >= 0);
  REQUIRE(
    recv(peer, received.data(), received.size(), MSG_WAITALL) ==
    static_cast<ssize_t>(received.size()));
  CHECK(received == bytes);

  const auto drops_before_allocation_failures = Sink::dropped_count();
  for (size_t failure = 1; failure <= 2; ++failure)
  {
    allocation_failure = allocations + failure;
    const auto pushed = Sink::enqueue(bytes);
    allocation_failure = 0;
    CHECK_FALSE(pushed);
  }
  CHECK(Sink::dropped_count() == drops_before_allocation_failures + 2);

  const auto drops_before_emission_failures = Sink::dropped_count();
  for (size_t failure = 1; failure <= 2; ++failure)
  {
    allocation_failure = allocations + failure;
    CHECK_NOTHROW(request_trace::empty());
    allocation_failure = 0;
  }
  CHECK(Sink::dropped_count() == drops_before_emission_failures + 2);
  check_event([] { request_trace::empty(); }, {{"function", "empty"}});

  auto logger = std::make_unique<DropLogger>();
  auto* logs = logger.get();
  ccf::logger::config::loggers().push_back(std::move(logger));
  stalled = true;
  std::array<uint8_t, 128> payload = {};
  const auto previous = calls.load();
  REQUIRE(Sink::enqueue(payload));
  while (calls == previous)
    std::this_thread::yield();
  REQUIRE(Sink::enqueue(payload));
  REQUIRE(Sink::enqueue(payload));
  REQUIRE(Sink::enqueue(payload));
  const auto full_before = allocations;
  const auto full = Sink::enqueue(payload);
  const auto full_after = allocations;
  CHECK_FALSE(full);
  CHECK(full_before == full_after);
  std::vector<uint8_t> oversize(ccf::tracing::SPSCQueue::MAX_RECORD_SIZE + 1);
  forbid_allocation = true;
  bool allocation_failed = false;
  try
  {
    for (size_t i = 0; i < Sink::DROP_REPORT_INTERVAL * 2; ++i)
      Sink::enqueue(oversize);
    for (size_t i = 0; i < 32; ++i)
      Sink::enqueue(payload);
  }
  catch (...)
  {
    allocation_failed = true;
  }
  forbid_allocation = false;
  CHECK_FALSE(allocation_failed);
  CHECK(Sink::dropped_count() >= Sink::DROP_REPORT_INTERVAL * 2);
  const auto report_deadline =
    std::chrono::steady_clock::now() + std::chrono::seconds(1);
  while (logs->reports < 2 &&
         std::chrono::steady_clock::now() < report_deadline)
    std::this_thread::yield();
  CHECK(logs->reports == 2);
  const auto drops_before_unbound = Sink::dropped_count();
  bool unbound_pushed = true;
  size_t unbound_allocations = 0;
  std::thread unbound([&] {
    const auto before = allocations;
    unbound_pushed = Sink::enqueue(payload);
    unbound_allocations = allocations - before;
  });
  unbound.join();
  CHECK_FALSE(unbound_pushed);
  CHECK(unbound_allocations == 0);
  CHECK(Sink::dropped_count() == drops_before_unbound + 1);
  const auto drops_before_shutdown = Sink::dropped_count();
  const auto start = std::chrono::steady_clock::now();
  Sink::shutdown();
  CHECK_FALSE(Sink::wait_for_connection(std::chrono::seconds(1)));
  CHECK(std::chrono::steady_clock::now() - start < std::chrono::seconds(3));
  CHECK(Sink::dropped_count() == drops_before_shutdown + 4);
  // Use the empty queue so a full queue cannot mask shutdown rejection.
  Sink::bind_producer(1);
  const auto allocations_before_shutdown_enqueue = allocations;
  const auto shutdown_pushed = Sink::enqueue(payload);
  const auto allocations_after_shutdown_enqueue = allocations;
  CHECK_FALSE(shutdown_pushed);
  CHECK(
    allocations_after_shutdown_enqueue == allocations_before_shutdown_enqueue);
  CHECK(Sink::dropped_count() == drops_before_shutdown + 5);
  CHECK(logs->reports == 2);
  CHECK_FALSE(wrong_thread);
  close(peer);
  close(listener);
}
