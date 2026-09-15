// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "common/configuration.h"
#include "tracing/trace.h"

#include <arpa/inet.h>
#include <doctest/doctest.h>
#include <future>
TEST_CASE("Fluentd configuration round trips")
{
  ccf::CCFConfig::Observability config;
  CHECK(nlohmann::json(config) == nlohmann::json::object());
  config.fluentd = {"::1", "24224"};
  CHECK(nlohmann::json(config).get<ccf::CCFConfig::Observability>() == config);
}

namespace
{
  thread_local bool forbid_allocation = false;
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
  if (forbid_allocation)
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

TEST_CASE("SPSC export: framing, allocation-free enqueue, drops and shutdown")
{
  using Sink = ccf::tracing::FluentdSink;
  producer = std::this_thread::get_id();
  bool encoded = false;
  ccf::tracing::emit("ccf.request", 0, [&](auto&) { encoded = true; });
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
  invalid.ring_buffer_size = "3KB";
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
  endpoint.ring_buffer_size = "1KB";
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
  ccf::tracing::emit_fields(
    "ccf.request",
    ccf::msgpack::Field{"path", std::string_view("/app/log")},
    ccf::msgpack::Field{"status", 200},
    ccf::msgpack::Field{"cached", false});
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

  auto logger = std::make_unique<DropLogger>();
  auto* logs = logger.get();
  ccf::logger::config::loggers().push_back(std::move(logger));
  stalled = true;
  std::array<uint8_t, 128> payload = {};
  const auto previous = calls.load();
  REQUIRE(Sink::enqueue(payload));
  while (calls == previous)
    std::this_thread::yield();
  std::array<uint8_t, 1024> oversize = {};
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
  const auto start = std::chrono::steady_clock::now();
  Sink::shutdown();
  CHECK_FALSE(Sink::wait_for_connection(std::chrono::seconds(1)));
  CHECK(std::chrono::steady_clock::now() - start < std::chrono::seconds(3));
  CHECK(logs->reports == 2);
  CHECK_FALSE(wrong_thread);
  close(peer);
  close(listener);
}
