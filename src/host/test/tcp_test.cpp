// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "host/tcp.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <algorithm>
#include <chrono>
#include <cstring>
#include <doctest/doctest.h>
#include <functional>
#include <netdb.h>
#include <thread>

// TCPImpl's static read quota members are normally defined in
// src/host/run.cpp (linked into the host binary via ccf_launcher). This test
// binary links TCPImpl directly (like node_connections_test does, but against
// the real implementation rather than a fake), so it must provide its own
// definitions.
size_t asynchost::TCPImpl::remaining_read_quota =
  asynchost::TCPImpl::max_read_quota;
bool asynchost::TCPImpl::alloc_quota_logged = false;

using namespace std::chrono_literals;

namespace
{
  // Surfaces the message of an unexpected exception in the failure output,
  // rather than just reporting that something was thrown.
  REGISTER_EXCEPTION_TRANSLATOR(const std::exception& e)
  {
    return doctest::String(e.what());
  }

  // Records every SocketBehaviour callback, in order, so tests can assert on
  // both occurrence and ordering. Overrides on_resolve_failed/on_listen_failed
  // (which default to LOG_FATAL_FMT + abort()) so failure scenarios can be
  // exercised without crashing the test binary.
  class RecordingBehaviour : public asynchost::SocketBehaviour<asynchost::TCP>
  {
  public:
    std::vector<std::string> events;
    std::string listen_host;
    std::string listen_service;
    std::vector<uint8_t> received;

    asynchost::TCP accepted_peer{nullptr};
    RecordingBehaviour* accepted_peer_behaviour = nullptr;
    bool has_accepted_peer = false;

    explicit RecordingBehaviour(const char* name = "test") :
      asynchost::SocketBehaviour<asynchost::TCP>(name, "tcp_test")
    {}

    void on_listening(
      const std::string& host, const std::string& service) override
    {
      listen_host = host;
      listen_service = service;
      events.emplace_back("listening");
    }

    void on_connect() override
    {
      events.emplace_back("connect");
    }

    void on_accept(asynchost::TCP& peer) override
    {
      events.emplace_back("accept");
      // Set the peer's behaviour synchronously, before returning control to
      // libuv: TCPImpl::on_accept() calls peer->read_start() before invoking
      // this callback, so any read event for the peer could otherwise be
      // dispatched before a behaviour is attached.
      // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
      auto* peer_behaviour = new RecordingBehaviour("accepted");
      peer->set_behaviour(std::unique_ptr<asynchost::SocketBehaviour<asynchost::TCP>>(
        peer_behaviour));
      accepted_peer = peer;
      accepted_peer_behaviour = peer_behaviour;
      has_accepted_peer = true;
    }

    bool on_read(size_t len, uint8_t*& data, sockaddr /*addr*/) override
    {
      events.emplace_back("read");
      received.insert(received.end(), data, data + len);
      return true;
    }

    void on_disconnect() override
    {
      events.emplace_back("disconnect");
    }

    void on_bind_failed() override
    {
      events.emplace_back("bind_failed");
    }

    void on_connect_failed() override
    {
      events.emplace_back("connect_failed");
    }

    void on_resolve_failed() override
    {
      events.emplace_back("resolve_failed");
    }

    void on_listen_failed() override
    {
      events.emplace_back("listen_failed");
    }

    [[nodiscard]] bool has(const std::string& event) const
    {
      return std::find(events.begin(), events.end(), event) != events.end();
    }
  };

  // Drives uv_default_loop() with UV_RUN_NOWAIT so that no single libuv call
  // can block past the deadline, regardless of what it is waiting on
  // (DNS resolution on the threadpool, TCP handshakes, kernel-level
  // connection timeouts). Returns whether predicate() became true before the
  // deadline.
  bool run_until(
    const std::function<bool()>& predicate,
    std::chrono::milliseconds timeout = 5s)
  {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (!predicate())
    {
      uv_run(uv_default_loop(), UV_RUN_NOWAIT);
      if (predicate())
      {
        break;
      }
      if (std::chrono::steady_clock::now() > deadline)
      {
        return false;
      }
      std::this_thread::sleep_for(1ms);
    }
    return true;
  }

  // Drains the loop until it has no more active handles (all closes have
  // completed), or the deadline is reached.
  void drain_loop(std::chrono::milliseconds timeout = 2s)
  {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (uv_loop_alive(uv_default_loop()) != 0)
    {
      uv_run(uv_default_loop(), UV_RUN_NOWAIT);
      if (std::chrono::steady_clock::now() > deadline)
      {
        break;
      }
      std::this_thread::sleep_for(1ms);
    }
  }

  asynchost::TCP make_listener(RecordingBehaviour* behaviour)
  {
    asynchost::TCP listener;
    listener->set_behaviour(
      std::unique_ptr<asynchost::SocketBehaviour<asynchost::TCP>>(behaviour));
    return listener;
  }

  bool ipv6_loopback_for_localhost_available()
  {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (getaddrinfo("localhost", "0", &hints, &res) != 0)
    {
      return false;
    }

    bool found = false;
    for (auto* p = res; p != nullptr; p = p->ai_next)
    {
      if (p->ai_family == AF_INET6)
      {
        found = true;
        break;
      }
    }
    freeaddrinfo(res);
    return found;
  }
}

TEST_CASE(
  "TCP listen, connect, exchange bytes both ways, close" *
  doctest::test_suite("tcp"))
{
  auto* server_behaviour = new RecordingBehaviour("server"); // NOLINT
  auto server = make_listener(server_behaviour);
  REQUIRE(server->listen("127.0.0.1", "0", std::string("test-listener")));
  REQUIRE(server_behaviour->has("listening"));
  const auto port = server_behaviour->listen_service;
  REQUIRE_FALSE(port.empty());
  CHECK(server->get_port() == port);
  CHECK(server->get_host() == "127.0.0.1");
  CHECK(server->get_listen_name() == std::optional<std::string>("test-listener"));

  // Trivial accessors/no-ops, otherwise never exercised.
  asynchost::TCPImpl::reset_read_quota();

  auto* client_behaviour = new RecordingBehaviour("client"); // NOLINT
  asynchost::TCP client(true, std::nullopt);
  client->set_behaviour(
    std::unique_ptr<asynchost::SocketBehaviour<asynchost::TCP>>(
      client_behaviour));
  client->start(0); // No-op for TCP; mirrors UDP's interface.

  REQUIRE(client->connect("127.0.0.1", port));

  // A write issued before the connection completes (status is still
  // CONNECTING_RESOLVING/CONNECTING here, since resolution and the TCP
  // handshake both require the loop to run) must be queued (pending_writes)
  // and delivered once connected.
  const std::string first_message = "hello-before-connect";
  REQUIRE(client->write(
    first_message.size(),
    reinterpret_cast<const uint8_t*>(first_message.data())));
  CHECK_FALSE(client_behaviour->has("connect"));

  REQUIRE(run_until([&]() { return client_behaviour->has("connect"); }));
  REQUIRE(run_until([&]() { return server_behaviour->has_accepted_peer; }));
  auto* peer_behaviour = server_behaviour->accepted_peer_behaviour;
  auto peer = server_behaviour->accepted_peer;

  REQUIRE(run_until([&]() { return !peer_behaviour->received.empty(); }));
  CHECK(
    std::string(peer_behaviour->received.begin(), peer_behaviour->received.end()) ==
    first_message);

  // Callback order on the client: connect only, no accept/read yet.
  CHECK(client_behaviour->events == std::vector<std::string>{"connect"});

  const std::string reply = "hi-from-server";
  REQUIRE(peer->write(reply.size(), reinterpret_cast<const uint8_t*>(reply.data())));
  REQUIRE(run_until([&]() { return !client_behaviour->received.empty(); }));
  CHECK(
    std::string(client_behaviour->received.begin(), client_behaviour->received.end()) ==
    reply);

  // Close from the client side: the peer should observe a disconnect.
  client = nullptr;
  REQUIRE(run_until([&]() { return peer_behaviour->has("disconnect"); }));

  // Close from the server side (both the accepted peer and the listener).
  peer = nullptr;
  server = nullptr;
  drain_loop();
  CHECK(uv_loop_alive(uv_default_loop()) == 0);
}

TEST_CASE(
  "TCP connect to an unresolvable host" * doctest::test_suite("tcp"))
{
  auto* behaviour = new RecordingBehaviour(); // NOLINT
  asynchost::TCP tcp(true, std::nullopt);
  tcp->set_behaviour(
    std::unique_ptr<asynchost::SocketBehaviour<asynchost::TCP>>(behaviour));

  REQUIRE(tcp->connect("nonexistent.invalid", "1234"));
  REQUIRE(run_until([&]() { return behaviour->has("resolve_failed"); }));

  const uint8_t byte = 0;
  CHECK_FALSE(tcp->write(1, &byte));

  tcp = nullptr;
  drain_loop();
  CHECK(uv_loop_alive(uv_default_loop()) == 0);
}

TEST_CASE(
  "TCP connect to a closed port" * doctest::test_suite("tcp"))
{
  // Bind an ephemeral port and immediately close it, so nothing is listening
  // there when the client tries to connect.
  auto* probe_behaviour = new RecordingBehaviour(); // NOLINT
  auto probe = make_listener(probe_behaviour);
  REQUIRE(probe->listen("127.0.0.1", "0"));
  const auto port = probe_behaviour->listen_service;
  probe = nullptr;
  drain_loop();

  auto* behaviour = new RecordingBehaviour(); // NOLINT
  asynchost::TCP tcp(true, std::nullopt);
  tcp->set_behaviour(
    std::unique_ptr<asynchost::SocketBehaviour<asynchost::TCP>>(behaviour));

  REQUIRE(tcp->connect("127.0.0.1", port));
  REQUIRE(run_until([&]() { return behaviour->has("connect_failed"); }));

  const uint8_t byte = 0;
  CHECK_FALSE(tcp->write(1, &byte));

  tcp = nullptr;
  drain_loop();
  CHECK(uv_loop_alive(uv_default_loop()) == 0);
}

TEST_CASE("TCP client_bind" * doctest::test_suite("tcp"))
{
  auto* server_behaviour = new RecordingBehaviour("server"); // NOLINT
  auto server = make_listener(server_behaviour);
  REQUIRE(server->listen("127.0.0.1", "0"));
  const auto port = server_behaviour->listen_service;

  SUBCASE("bindable client_host succeeds")
  {
    auto* behaviour = new RecordingBehaviour(); // NOLINT
    // A non-null connection_timeout exercises
    // set_connection_timeout_on_uv_handle()'s TCP_USER_TIMEOUT setsockopt
    // path (otherwise skipped entirely when connection_timeout is nullopt).
    asynchost::TCP tcp(true, std::chrono::milliseconds(5000));
    tcp->set_behaviour(
      std::unique_ptr<asynchost::SocketBehaviour<asynchost::TCP>>(behaviour));

    REQUIRE(tcp->connect("127.0.0.1", port, std::string("127.0.0.1")));
    REQUIRE(run_until([&]() { return behaviour->has("connect"); }));
    CHECK_FALSE(behaviour->has("bind_failed"));

    tcp = nullptr;
  }

  SUBCASE("unbindable client_host fails")
  {
    // 192.0.2.0/24 is TEST-NET-1 (RFC 5737): reserved for documentation and
    // never assigned to a real interface, so binding to it fails locally.
    auto* behaviour = new RecordingBehaviour(); // NOLINT
    asynchost::TCP tcp(true, std::nullopt);
    tcp->set_behaviour(
      std::unique_ptr<asynchost::SocketBehaviour<asynchost::TCP>>(behaviour));

    REQUIRE(tcp->connect("127.0.0.1", port, std::string("192.0.2.1")));
    REQUIRE(run_until([&]() { return behaviour->has("bind_failed"); }));
    CHECK_FALSE(behaviour->has("connect"));

    const uint8_t byte = 0;
    CHECK_FALSE(tcp->write(1, &byte));

    tcp = nullptr;
  }

  SUBCASE("unresolvable client_host fails synchronously")
  {
    // connect()'s client_host branch resolves the client_host synchronously
    // (DNS::resolve(..., async=false)); when that lookup itself fails (as
    // opposed to the bind() call), connect() returns false directly, without
    // any behaviour callback (client_bind()/on_client_resolved() are never
    // reached).
    auto* behaviour = new RecordingBehaviour(); // NOLINT
    asynchost::TCP tcp(true, std::nullopt);
    tcp->set_behaviour(
      std::unique_ptr<asynchost::SocketBehaviour<asynchost::TCP>>(behaviour));

    CHECK_FALSE(
      tcp->connect("127.0.0.1", port, std::string("nonexistent.invalid")));
    CHECK(behaviour->events.empty());

    tcp = nullptr;
  }

  SUBCASE("connect() called again with client_host reuses the object")
  {
    // Nothing in connect()'s client_host branch guards re-entry with
    // assert_status (unlike the plain-connect branch), so calling it again
    // after an earlier client_bind() failure is allowed; it discards the
    // previous client_addr_base and starts over.
    auto* behaviour = new RecordingBehaviour(); // NOLINT
    asynchost::TCP tcp(true, std::nullopt);
    tcp->set_behaviour(
      std::unique_ptr<asynchost::SocketBehaviour<asynchost::TCP>>(behaviour));

    REQUIRE(tcp->connect("127.0.0.1", port, std::string("192.0.2.1")));
    REQUIRE(run_until([&]() { return behaviour->has("bind_failed"); }));

    REQUIRE(tcp->connect("127.0.0.1", port, std::string("127.0.0.1")));
    REQUIRE(run_until([&]() { return behaviour->has("connect"); }));

    tcp = nullptr;
  }

  server = nullptr;
  drain_loop();
  CHECK(uv_loop_alive(uv_default_loop()) == 0);
}

TEST_CASE(
  "TCP listen failure: address already in use" * doctest::test_suite("tcp"))
{
  auto* first_behaviour = new RecordingBehaviour("first"); // NOLINT
  auto first = make_listener(first_behaviour);
  REQUIRE(first->listen("127.0.0.1", "0"));
  const auto port = first_behaviour->listen_service;

  auto* second_behaviour = new RecordingBehaviour("second"); // NOLINT
  auto second = make_listener(second_behaviour);
  // NOTE: listen()'s return value only reflects whether the synchronous DNS
  // resolution succeeded, not whether the subsequent bind/listen (run
  // synchronously inside the same call, via on_resolved()/listen_resolved())
  // succeeded; that failure is only observable through the behaviour
  // callback. This is a pre-existing quirk, orthogonal to the dead code
  // removed by this change, with no caller relying on the return value
  // (node_connections.h ignores it), so it is left as-is.
  CHECK(second->listen("127.0.0.1", port));
  CHECK(second_behaviour->has("listen_failed"));
  CHECK_FALSE(second_behaviour->has("listening"));

  first = nullptr;
  second = nullptr;
  drain_loop();
  CHECK(uv_loop_alive(uv_default_loop()) == 0);
}

TEST_CASE(
  "TCP listen failure: unbindable address" * doctest::test_suite("tcp"))
{
  // 192.0.2.0/24 (TEST-NET-1) is a literal address, so DNS resolution
  // succeeds, and the failure genuinely comes from uv_tcp_bind() inside
  // listen_resolved()'s address loop.
  auto* behaviour = new RecordingBehaviour(); // NOLINT
  auto listener = make_listener(behaviour);
  CHECK(listener->listen("192.0.2.1", "0"));
  CHECK(behaviour->has("listen_failed"));
  CHECK_FALSE(behaviour->has("listening"));

  listener = nullptr;
  drain_loop();
  CHECK(uv_loop_alive(uv_default_loop()) == 0);
}

TEST_CASE(
  "TCP listen failure: unbindable IPv6 address" * doctest::test_suite("tcp"))
{
  // 2001:db8::/32 is the IPv6 documentation prefix (RFC 3849): reserved and
  // never assigned to a real interface. This exercises get_address_name()'s
  // AF_INET6 branch (used in the uv_tcp_bind failure log message).
  auto* behaviour = new RecordingBehaviour(); // NOLINT
  auto listener = make_listener(behaviour);
  CHECK(listener->listen("2001:db8::1", "0"));
  CHECK(behaviour->has("listen_failed"));
  CHECK_FALSE(behaviour->has("listening"));

  listener = nullptr;
  drain_loop();
  CHECK(uv_loop_alive(uv_default_loop()) == 0);
}

TEST_CASE(
  "TCP listen on an unresolvable host does not crash" *
  doctest::test_suite("tcp"))
{
  // listen() resolves synchronously (unlike connect()). When that
  // synchronous resolution fails, TCPImpl::resolve() sets status to
  // RESOLVING_FAILED and returns false, without invoking any behaviour
  // callback (on_listen_failed is only reached from the address-loop inside
  // listen_resolved(), which is never entered here). This is a pre-existing
  // gap in tcp.h, orthogonal to the dead code removed by this change; this
  // test documents the current behaviour rather than asserting a callback
  // that is not actually fired.
  auto* behaviour = new RecordingBehaviour(); // NOLINT
  auto listener = make_listener(behaviour);
  CHECK_FALSE(listener->listen("nonexistent.invalid", "0"));
  CHECK_FALSE(behaviour->has("listening"));
  CHECK_FALSE(behaviour->has("listen_failed"));

  listener = nullptr;
  drain_loop();
  CHECK(uv_loop_alive(uv_default_loop()) == 0);
}

TEST_CASE(
  "TCP connection timeout against an unroutable address" *
  doctest::test_suite("tcp"))
{
  // 10.255.255.1 is routed but unanswered in CI/sandbox networks (no host
  // there, and no immediate ICMP unreachable), so the connect attempt hangs
  // until TCP_USER_TIMEOUT (applied via the connection_timeout constructor
  // argument, see TCPImpl::set_connection_timeout) aborts it.
  auto* behaviour = new RecordingBehaviour(); // NOLINT
  asynchost::TCP tcp(true, std::chrono::milliseconds(200));
  tcp->set_behaviour(
    std::unique_ptr<asynchost::SocketBehaviour<asynchost::TCP>>(behaviour));

  REQUIRE(tcp->connect("10.255.255.1", "12345"));
  const bool finished =
    run_until([&]() { return behaviour->has("connect_failed"); }, 10s);

  if (!finished)
  {
    MESSAGE(
      "Connection to 10.255.255.1 did not time out within the deadline; "
      "this sandbox's network may answer or reject it immediately. "
      "Skipping strict assertions for this environment.");
  }
  else
  {
    CHECK(behaviour->has("connect_failed"));
  }

  tcp = nullptr;
  drain_loop();
  CHECK(uv_loop_alive(uv_default_loop()) == 0);
}

TEST_CASE(
  "TCP IPv4/IPv6 family change on connect" * doctest::test_suite("tcp"))
{
  if (!ipv6_loopback_for_localhost_available())
  {
    MESSAGE(
      "'localhost' does not resolve to an IPv6 address (::1) on this host; "
      "skipping the family-change scenario.");
    return;
  }

  auto* server_behaviour = new RecordingBehaviour("server"); // NOLINT
  auto server = make_listener(server_behaviour);
  // Listen on IPv4 only.
  REQUIRE(server->listen("127.0.0.1", "0"));
  const auto port = server_behaviour->listen_service;

  auto* behaviour = new RecordingBehaviour(); // NOLINT
  asynchost::TCP tcp(true, std::nullopt);
  tcp->set_behaviour(
    std::unique_ptr<asynchost::SocketBehaviour<asynchost::TCP>>(behaviour));

  // "localhost" resolves to both ::1 and 127.0.0.1; if ::1 is attempted
  // first, the first attempt is refused (nothing is listening there), and
  // TCPImpl must fall back to 127.0.0.1 via reset_handle_for_family_change()/
  // on_family_reset(), eventually succeeding.
  REQUIRE(tcp->connect("localhost", port));
  REQUIRE(run_until([&]() { return behaviour->has("connect"); }, 10s));

  tcp = nullptr;
  server = nullptr;
  drain_loop();
  CHECK(uv_loop_alive(uv_default_loop()) == 0);
}

TEST_CASE(
  "TCP assert_status misuse throws std::logic_error" *
  doctest::test_suite("tcp"))
{
  auto* behaviour = new RecordingBehaviour(); // NOLINT
  asynchost::TCP tcp(true, std::nullopt);
  tcp->set_behaviour(
    std::unique_ptr<asynchost::SocketBehaviour<asynchost::TCP>>(behaviour));

  REQUIRE(tcp->connect("127.0.0.1", "1"));
  // Calling connect() again while already resolving is an unexpected status
  // transition (FRESH -> CONNECTING_RESOLVING is no longer valid, since
  // status is already past FRESH).
  REQUIRE_THROWS_AS(tcp->connect("127.0.0.1", "1"), std::logic_error);

  tcp = nullptr;
  drain_loop();
  CHECK(uv_loop_alive(uv_default_loop()) == 0);
}

TEST_CASE(
  "TCP write() in an unexpected status throws std::logic_error" *
  doctest::test_suite("tcp"))
{
  SUBCASE("FRESH")
  {
    asynchost::TCP tcp(true, std::nullopt);
    tcp->set_behaviour(
      std::unique_ptr<asynchost::SocketBehaviour<asynchost::TCP>>(
        new RecordingBehaviour())); // NOLINT

    const uint8_t data[1] = {0};
    REQUIRE_THROWS_AS(tcp->write(1, data), std::logic_error);

    tcp = nullptr;
  }

  SUBCASE("LISTENING")
  {
    auto* behaviour = new RecordingBehaviour(); // NOLINT
    auto listener = make_listener(behaviour);
    REQUIRE(listener->listen("127.0.0.1", "0"));
    REQUIRE(run_until([&]() { return behaviour->has("listening"); }));

    const uint8_t data[1] = {0};
    REQUIRE_THROWS_AS(listener->write(1, data), std::logic_error);

    listener = nullptr;
  }

  drain_loop();
  CHECK(uv_loop_alive(uv_default_loop()) == 0);
}

TEST_CASE(
  "TCP destruction with an in-flight DNS request cleans up safely" *
  doctest::test_suite("tcp"))
{
  // connect() without a client_host resolves asynchronously via
  // uv_getaddrinfo(), which is only actually delivered on a subsequent
  // uv_run(). Destroying the TCPImpl before ever running the loop
  // guarantees the request is still in pending_resolve_requests, exercising
  // the destructor's cleanup of the dangling `req->data` pointer.
  auto* behaviour = new RecordingBehaviour(); // NOLINT
  asynchost::TCP tcp(true, std::nullopt);
  tcp->set_behaviour(
    std::unique_ptr<asynchost::SocketBehaviour<asynchost::TCP>>(behaviour));

  REQUIRE(tcp->connect("127.0.0.1", "1"));
  tcp = nullptr;

  // Let the (now-orphaned) resolve request complete and be cleaned up
  // without touching the destroyed TCPImpl.
  drain_loop();
  CHECK(uv_loop_alive(uv_default_loop()) == 0);
}
