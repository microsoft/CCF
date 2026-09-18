// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "common/configuration.h"
#include "tracing/test/events.h"

#include <arpa/inet.h>
#include <doctest/doctest.h>
#include <future>

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

TEST_CASE("Fluentd configuration round trips")
{
  ccf::CCFConfig::Observability config;
  CHECK(nlohmann::json(config) == nlohmann::json::object());
  config.fluentd = {"::1", "24224"};
  CHECK(config.fluentd->queue_capacity == 4096);
  config.fluentd->queue_capacity = 3;
  CHECK(nlohmann::json(config).get<ccf::CCFConfig::Observability>() == config);
  auto json = nlohmann::json(config);
  json["fluentd"]["queue_capacity"] = -1;
  CHECK_THROWS_AS(
    ccf::tracing::FluentdSink::validate(
      json.get<ccf::CCFConfig::Observability>().fluentd.value()),
    std::invalid_argument);
}

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
  CHECK_THROWS_AS(Queue(Queue::MAX_CAPACITY + 1), std::invalid_argument);
  Queue queue(3);
  auto ignore = [](auto) {};
  CHECK(queue.size() == 0);
  CHECK(queue.read(1, ignore) == 0);
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
    size_t expected = 0;
    CHECK(queue.read(3, [&](auto bytes) {
      CHECK(queue.size() == 3 - expected);
      CHECK(bytes.size() == payload.size());
      for (auto byte : bytes)
        CHECK(byte == expected);
      ++expected;
    }) == 3);
    CHECK(expected == 3);
    CHECK(queue.size() == 0);
    CHECK(queue.read(1, ignore) == 0);
  }
  for (size_t failure = 1; failure <= 2; ++failure)
  {
    allocation_failure = allocations + failure;
    const auto pushed = queue.push(payload);
    allocation_failure = 0;
    CHECK_FALSE(pushed);
    CHECK(queue.read(1, ignore) == 0);
    REQUIRE(queue.push(payload));
    CHECK(queue.read(1, ignore) == 1);
  }
  std::vector<uint8_t> large(Queue::MAX_RECORD_SIZE + 1);
  const auto before = allocations;
  const auto oversized = queue.push(large);
  const auto after = allocations;
  CHECK_FALSE(oversized);
  CHECK(before == after);
  large.pop_back();
  REQUIRE(queue.push(large));
  CHECK(queue.read(1, [&](auto bytes) {
    CHECK(bytes.size() == Queue::MAX_RECORD_SIZE);
  }) == 1);
}

TEST_CASE("Direct map encoding does not allocate into a reserved buffer")
{
  std::vector<uint8_t> bytes;
  bytes.reserve(2048);
  const auto before = allocations;
  ccf::msgpack::write_map(
    bytes,
    "signed",
    -1,
    "unsigned",
    uint64_t(42),
    "bool",
    true,
    "nested",
    request_trace::Nested{7, false},
    "args",
    ccf::msgpack::map("idx", 3),
    "literal",
    "value");
  const auto after = allocations;
  CHECK(after == before);
  CHECK(nlohmann::json::from_msgpack(bytes)["nested"]["number"] == 7);
}

TEST_CASE("SPSC callback retains ownership until it returns")
{
  ccf::tracing::SPSCQueue queue(1);
  std::array<uint8_t, 1> payload = {42};
  REQUIRE(queue.push(payload));
  std::promise<void> entered;
  std::promise<void> release;
  auto released = release.get_future();
  std::thread consumer([&] {
    CHECK(queue.read(1, [&](auto bytes) {
      CHECK(queue.size() == 1);
      entered.set_value();
      released.wait();
      CHECK(bytes[0] == 42);
      CHECK(queue.size() == 1);
    }) == 1);
    CHECK(queue.size() == 0);
  });
  entered.get_future().wait();
  payload[0] = 17;
  const auto before = allocations;
  const auto pushed = queue.push(payload);
  const auto after = allocations;
  CHECK_FALSE(pushed);
  CHECK(before == after);
  release.set_value();
  consumer.join();
  REQUIRE(queue.push(payload));
  CHECK(queue.read(1, [](auto bytes) { CHECK(bytes[0] == 17); }) == 1);
}

TEST_CASE("SPSC read reuses callbacks without copying or consuming them")
{
  ccf::tracing::SPSCQueue queue(2);
  const auto fill = [&] {
    REQUIRE(queue.push({}));
    REQUIRE(queue.push({}));
  };
  auto callback = [count = size_t{0}](auto) mutable { return ++count; };
  fill();
  CHECK(queue.read(2, callback) == 2);
  CHECK(callback(std::span<const uint8_t>{}) == 3);
  fill();
  CHECK(queue.read(2, callback) == 2);
  CHECK(callback(std::span<const uint8_t>{}) == 6);

  struct LvalueCallback
  {
    size_t& calls;

    explicit LvalueCallback(size_t& calls_) : calls(calls_) {}
    LvalueCallback(const LvalueCallback&) = delete;
    LvalueCallback(LvalueCallback&&) = default;

    void operator()(std::span<const uint8_t> /*bytes*/) &
    {
      ++calls;
    }

    void operator()(std::span<const uint8_t> /*bytes*/) && = delete;
  };
  size_t callback_calls = 0;
  LvalueCallback lvalue_callback(callback_calls);
  fill();
  CHECK(queue.read(2, lvalue_callback) == 2);
  CHECK(callback_calls == 2);
  fill();
  CHECK(queue.read(2, LvalueCallback{callback_calls}) == 2);
  CHECK(callback_calls == 4);
}

TEST_CASE("SPSC default capacity counts records, including empty records")
{
  ccf::tracing::SPSCQueue queue;
  for (size_t i = 0; i < 4096; ++i)
    REQUIRE(queue.push({}));
  CHECK_FALSE(queue.push({}));
  CHECK(queue.read(4096, [](auto bytes) { CHECK(bytes.empty()); }) == 4096);
  CHECK(queue.read(1, [](auto) {}) == 0);
}

TEST_CASE("SPSC records are published in order concurrently")
{
  ccf::tracing::SPSCQueue queue(3);
  constexpr uint64_t count = 10000;
  std::thread writer([&] {
    std::array<uint8_t, 37> payload;
    for (uint64_t i = 0; i < count; ++i)
    {
      payload.fill(i % 251);
      std::memcpy(payload.data(), &i, sizeof(i));
      while (!queue.push(payload))
        std::this_thread::yield();
    }
  });
  uint64_t expected = 0;
  while (expected < count)
  {
    CHECK(queue.size() <= 3);
    queue.read(64, [&](auto bytes) {
      const auto pending = queue.size();
      CHECK(pending >= 1);
      CHECK(pending <= 3);
      REQUIRE(bytes.size() == 37);
      uint64_t sequence;
      std::memcpy(&sequence, bytes.data(), sizeof(sequence));
      CHECK(sequence == expected);
      for (size_t i = sizeof(sequence); i < bytes.size(); ++i)
        CHECK(bytes[i] == expected % 251);
      ++expected;
    });
    std::this_thread::yield();
  }
  writer.join();
  CHECK(queue.size() == 0);
}

TEST_CASE("SPSC export: framing, producer isolation, drops and shutdown")
{
  using Sink = ccf::tracing::FluentdSink;
  producer = std::this_thread::get_id();
  bool encoded = false;
  ccf::tracing::emit(
    "ccf.request", "probe", request_trace::EncodingProbe{encoded});
  request_trace::single(request_trace::EncodingProbe{encoded});
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
  CHECK(frame[2]["h_ts"] == 0);
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

  fail_at = calls + 2;
  REQUIRE(Sink::enqueue(bytes));
  REQUIRE(recv(peer, chunk.data(), chunk.size(), MSG_WAITALL) == 7);
  CHECK(recv(peer, chunk.data(), chunk.size(), 0) == 0);
  close(peer);
  CHECK(Sink::dropped_count() == 1);
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
  CHECK(Sink::dropped_count() == drops_before_shutdown + 3);
  // Use the empty queue so a full queue cannot mask shutdown rejection.
  Sink::bind_producer(1);
  const auto allocations_before_shutdown_enqueue = allocations;
  const auto shutdown_pushed = Sink::enqueue(payload);
  const auto allocations_after_shutdown_enqueue = allocations;
  CHECK_FALSE(shutdown_pushed);
  CHECK(
    allocations_after_shutdown_enqueue == allocations_before_shutdown_enqueue);
  CHECK(Sink::dropped_count() == drops_before_shutdown + 4);
  CHECK(logs->reports == 2);
  CHECK_FALSE(wrong_thread);
  close(peer);
  close(listener);
}
