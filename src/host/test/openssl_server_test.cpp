// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

// Unit tests for the OpenSSL-native RPC transport and SessionWriter bridge.

#include "ccf/crypto/ec_key_pair.h"
#include "ccf/ds/x509_time_fmt.h"
#include "crypto/certs.h"
#include "host/datagram_server.h"
#include "host/tls/openssl_server.h"
#include "host/tls/openssl_session_manager.h"
#include "tasks/task_system.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <deque>
#include <doctest/doctest.h>
#include <future>
#include <mutex>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <random>
#include <set>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

using namespace asynchost;

// Set by the build when the toolchain's OpenSSL is new enough (3.5+) to
// negotiate the hybrid post-quantum groups the server offers.
#ifndef TEST_HYBRID_TLS_GROUPS
#  define TEST_HYBRID_TLS_GROUPS 0
#endif

namespace
{
  // The host process ignores SIGPIPE (see src/host/run.cpp), so writes to a
  // socket the peer has already closed return EPIPE rather than killing it.
  // Tests must do the same to reproduce production behaviour.
  [[maybe_unused]] const bool ignore_sigpipe = []() {
    return signal(SIGPIPE, SIG_IGN) != SIG_ERR;
  }();

  struct TaskWorkers
  {
    TaskWorkers()
    {
      ccf::tasks::set_task_threads(4);
    }

    ~TaskWorkers()
    {
      ccf::tasks::set_task_threads(0);
    }
  } task_workers;

  std::pair<std::string, std::string> make_server_cert()
  {
    using namespace std::literals;
    auto kp = ccf::crypto::make_ec_key_pair();
    const auto valid_from =
      ccf::ds::to_x509_time_string(std::chrono::system_clock::now() - 24h);
    auto cert = ccf::crypto::create_self_signed_cert(
      kp, "CN=localhost", {}, valid_from, /*validity_days*/ 365);
    return {cert.str(), kp->private_key_pem().str()};
  }

  struct TestCA
  {
    ccf::crypto::ECKeyPairPtr kp;
    ccf::crypto::Pem cert;
  };

  TestCA make_ca()
  {
    using namespace std::literals;
    auto kp = ccf::crypto::make_ec_key_pair();
    const auto valid_from =
      ccf::ds::to_x509_time_string(std::chrono::system_clock::now() - 24h);
    return {
      kp,
      ccf::crypto::create_self_signed_cert(
        kp, "CN=issuer", {}, valid_from, /*validity_days*/ 365)};
  }

  std::pair<std::string, std::string> make_endorsed_server_cert(
    const TestCA& ca)
  {
    using namespace std::literals;
    auto kp = ccf::crypto::make_ec_key_pair();
    const auto valid_from =
      ccf::ds::to_x509_time_string(std::chrono::system_clock::now() - 24h);
    auto cert = ccf::crypto::create_endorsed_cert(
      kp,
      "CN=localhost",
      {},
      valid_from,
      /*validity_days*/ 365,
      ca.kp->private_key_pem(),
      ca.cert);
    return {cert.str(), kp->private_key_pem().str()};
  }

  // Blocking TLS client: connects, sends `req` in full, reads exactly
  // `expected_resp` bytes. Verification is disabled for the self-signed test
  // certificate.
  std::vector<uint8_t> tls_client_exchange(
    uint16_t port,
    const std::vector<uint8_t>& req,
    size_t expected_resp,
    const std::string& client_cert = {},
    const std::string& client_key = {})
  {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(fd >= 0);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    REQUIRE(inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) == 1);
    REQUIRE(
      ::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);

    SSL_CTX* cctx = SSL_CTX_new(TLS_client_method());
    REQUIRE(cctx != nullptr);
    if (!client_cert.empty())
    {
      BIO* cb = BIO_new_mem_buf(
        client_cert.data(), static_cast<int>(client_cert.size()));
      X509* xc = PEM_read_bio_X509(cb, nullptr, nullptr, nullptr);
      BIO_free(cb);
      REQUIRE(xc != nullptr);
      REQUIRE(SSL_CTX_use_certificate(cctx, xc) == 1);
      X509_free(xc);
      BIO* kb =
        BIO_new_mem_buf(client_key.data(), static_cast<int>(client_key.size()));
      EVP_PKEY* pk = PEM_read_bio_PrivateKey(kb, nullptr, nullptr, nullptr);
      BIO_free(kb);
      REQUIRE(pk != nullptr);
      REQUIRE(SSL_CTX_use_PrivateKey(cctx, pk) == 1);
      EVP_PKEY_free(pk);
    }
    SSL* ssl = SSL_new(cctx);
    REQUIRE(ssl != nullptr);
    REQUIRE(SSL_set_fd(ssl, fd) == 1);
    SSL_set_connect_state(ssl);
    REQUIRE(SSL_connect(ssl) == 1);

    size_t off = 0;
    while (off < req.size())
    {
      const int n =
        SSL_write(ssl, req.data() + off, static_cast<int>(req.size() - off));
      REQUIRE(n > 0);
      off += static_cast<size_t>(n);
    }

    std::vector<uint8_t> resp;
    resp.reserve(expected_resp);
    while (resp.size() < expected_resp)
    {
      uint8_t buf[16384];
      const int n = SSL_read(ssl, buf, static_cast<int>(sizeof(buf)));
      if (n <= 0)
      {
        break;
      }
      resp.insert(resp.end(), buf, buf + static_cast<size_t>(n));
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(cctx);
    ::close(fd);
    return resp;
  }

  std::vector<uint8_t> random_bytes(size_t n)
  {
    std::vector<uint8_t> v(n);
    std::mt19937 rng(12345);
    for (auto& b : v)
    {
      b = static_cast<uint8_t>(rng());
    }
    return v;
  }

  std::string negotiated_group_name(SSL* ssl)
  {
    const auto group_id = SSL_get_negotiated_group(ssl);
    if (group_id == NID_undef)
    {
      return {};
    }

    const auto* group_name = SSL_group_to_name(ssl, group_id);
    if (group_name != nullptr)
    {
      return group_name;
    }

    return std::to_string(group_id);
  }

  struct HandshakeResult
  {
    bool succeeded = false;
    std::string group;
    std::string cipher;
  };

  // Handshakes against the server, optionally restricting what the client
  // offers, and reports what was negotiated. Used to assert the server's
  // configured cipher/group policy from the wire rather than by inspecting
  // the SSL_CTX.
  HandshakeResult handshake_and_inspect(
    uint16_t port,
    const std::string& client_groups = {},
    const std::string& client_ciphersuites = {})
  {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(fd >= 0);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    REQUIRE(inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) == 1);
    REQUIRE(
      ::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);

    SSL_CTX* cctx = SSL_CTX_new(TLS_client_method());
    REQUIRE(cctx != nullptr);
    if (!client_groups.empty())
    {
      REQUIRE(SSL_CTX_set1_groups_list(cctx, client_groups.c_str()) == 1);
    }
    if (!client_ciphersuites.empty())
    {
      REQUIRE(SSL_CTX_set_ciphersuites(cctx, client_ciphersuites.c_str()) == 1);
    }

    SSL* ssl = SSL_new(cctx);
    REQUIRE(ssl != nullptr);
    REQUIRE(SSL_set_fd(ssl, fd) == 1);
    SSL_set_connect_state(ssl);

    HandshakeResult result;
    result.succeeded = SSL_connect(ssl) == 1;
    if (result.succeeded)
    {
      result.group = negotiated_group_name(ssl);
      const auto* cipher = SSL_get_current_cipher(ssl);
      if (cipher != nullptr)
      {
        result.cipher = SSL_CIPHER_get_name(cipher);
      }
      SSL_shutdown(ssl);
    }

    SSL_free(ssl);
    SSL_CTX_free(cctx);
    ::close(fd);
    return result;
  }

  // Handshakes with a client that verifies the server certificate against
  // `ca`. Returns whether the handshake completed.
  bool verifying_client_handshake(uint16_t port, const ccf::crypto::Pem& ca)
  {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(fd >= 0);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    REQUIRE(inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) == 1);
    REQUIRE(
      ::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);

    SSL_CTX* cctx = SSL_CTX_new(TLS_client_method());
    REQUIRE(cctx != nullptr);
    {
      const auto ca_pem = ca.str();
      BIO* cb = BIO_new_mem_buf(ca_pem.data(), static_cast<int>(ca_pem.size()));
      X509* root = PEM_read_bio_X509(cb, nullptr, nullptr, nullptr);
      BIO_free(cb);
      REQUIRE(root != nullptr);
      REQUIRE(X509_STORE_add_cert(SSL_CTX_get_cert_store(cctx), root) == 1);
      X509_free(root);
    }
    SSL_CTX_set_verify(cctx, SSL_VERIFY_PEER, nullptr);

    SSL* ssl = SSL_new(cctx);
    REQUIRE(ssl != nullptr);
    REQUIRE(SSL_set_fd(ssl, fd) == 1);
    SSL_set_connect_state(ssl);

    const bool ok = SSL_connect(ssl) == 1;
    if (ok)
    {
      REQUIRE(SSL_get_verify_result(ssl) == X509_V_OK);
      SSL_shutdown(ssl);
    }

    SSL_free(ssl);
    SSL_CTX_free(cctx);
    ::close(fd);
    return ok;
  }

  // Echoes received plaintext back to the same connection via send().
  struct UVLoopRunner
  {
    std::thread thread;

    void start()
    {
      thread = std::thread([]() { uv_run(uv_default_loop(), UV_RUN_DEFAULT); });
    }

    ~UVLoopRunner()
    {
      if (thread.joinable())
      {
        thread.join();
      }
    }
  };

  struct EchoServer
  {
    std::shared_ptr<OpenSSLServer> server;
    UVLoopRunner loop;

    EchoServer(
      const std::string& cert,
      const std::string& key,
      const std::string& host = "127.0.0.1")
    {
      server = std::make_shared<OpenSSLServer>(
        OpenSSLServer::Config{.host = host, .cert_pem = cert, .key_pem = key},
        [this](
          uint64_t id,
          std::vector<uint8_t> d,
          const std::vector<uint8_t>&,
          bool) { server->send(id, d.data(), d.size()); });
      server->start();
      loop.start();
    }

    ~EchoServer()
    {
      server->stop(OpenSSLServer::LoopState::Running);
    }

    uint16_t port() const
    {
      return server->port();
    }
  };

  // A minimal ccf::Session that echoes received bytes back through its writer,
  // exercising the real Session / SessionWriter path over TLS.
  struct EchoSession : public ccf::Session
  {
    ::tcp::ConnID id;
    ccf::SessionWriter& writer;

    EchoSession(::tcp::ConnID id_, ccf::SessionWriter& w) : id(id_), writer(w)
    {}

    void handle_incoming_data(std::vector<uint8_t>&& data) override
    {
      writer.write_outbound(id, std::move(data));
    }

    void send_data(std::vector<uint8_t>&& /*data*/) override {}

    void close_session() override
    {
      writer.close_socket(id);
    }
  };

  // Writes a (large) response then immediately closes - reproduces the close-
  // truncation bug: without graceful close, the buffered response is discarded.
  struct LargeThenCloseSession : public ccf::Session
  {
    ::tcp::ConnID id;
    ccf::SessionWriter& writer;
    std::vector<uint8_t> payload;

    LargeThenCloseSession(
      ::tcp::ConnID id_, ccf::SessionWriter& w, std::vector<uint8_t> p) :
      id(id_),
      writer(w),
      payload(std::move(p))
    {}

    void handle_incoming_data(std::vector<uint8_t>&& /*data*/) override
    {
      writer.write_outbound(id, std::vector<uint8_t>(payload));
      writer.close_socket(id);
    }

    void send_data(std::vector<uint8_t>&& /*data*/) override {}
    void close_session() override {}
  };
}

// Admission control must run at accept time, not when the first request
// arrives. A client which completes the TCP and TLS handshakes and then sends
// nothing still holds a file descriptor and TLS state on the node, so it has
// to be counted - and the count has to be released exactly once when the
// connection goes away, whether or not it ever produced a session.
TEST_CASE("Connections are admitted at accept time and released once")
{
  auto [cert, key] = make_server_cert();

  std::mutex m;
  std::condition_variable cv;
  std::vector<::tcp::ConnID> admitted;
  std::vector<::tcp::ConnID> closed;
  size_t data_callbacks = 0;
  // Refuse everything after the first two connections, as a hard cap would.
  constexpr size_t cap = 2;

  auto server = std::make_shared<OpenSSLServer>(
    OpenSSLServer::Config{
      .host = "127.0.0.1", .cert_pem = cert, .key_pem = key},
    [&](
      ::tcp::ConnID, std::vector<uint8_t>, const std::vector<uint8_t>&, bool) {
      std::lock_guard<std::mutex> guard(m);
      ++data_callbacks;
      cv.notify_all();
    },
    [&](::tcp::ConnID id) {
      std::lock_guard<std::mutex> guard(m);
      closed.push_back(id);
      cv.notify_all();
    },
    [&](::tcp::ConnID id) -> std::optional<bool> {
      std::lock_guard<std::mutex> guard(m);
      if (admitted.size() >= cap)
      {
        return std::nullopt;
      }
      admitted.push_back(id);
      cv.notify_all();
      return false;
    });
  UVLoopRunner loop;
  server->start();
  const auto port = server->port();
  loop.start();

  const auto connect_tls = [port](int& fd, SSL_CTX*& ctx, SSL*& ssl) {
    fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    REQUIRE(fd >= 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    REQUIRE(inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) == 1);
    REQUIRE(
      ::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);
    ctx = SSL_CTX_new(TLS_client_method());
    REQUIRE(ctx != nullptr);
    ssl = SSL_new(ctx);
    REQUIRE(ssl != nullptr);
    REQUIRE(SSL_set_fd(ssl, fd) == 1);
    SSL_set_connect_state(ssl);
  };

  // Two silent clients: they complete the TLS handshake and then send nothing
  // at all, so on_data is never invoked for them.
  int fds[cap] = {-1, -1};
  SSL_CTX* ctxs[cap] = {nullptr, nullptr};
  SSL* ssls[cap] = {nullptr, nullptr};
  for (size_t i = 0; i < cap; ++i)
  {
    connect_tls(fds[i], ctxs[i], ssls[i]);
    REQUIRE(SSL_connect(ssls[i]) == 1);
  }

  {
    std::unique_lock<std::mutex> lock(m);
    REQUIRE(cv.wait_for(lock, std::chrono::seconds(10), [&]() {
      return admitted.size() == cap;
    }));
    // Nothing was sent, so nothing reached the session layer - which is
    // precisely why counting there would have missed these connections.
    REQUIRE(data_callbacks == 0);
    REQUIRE(closed.empty());
  }

  // A third connection is refused at accept. It is closed without a TLS
  // handshake, and must not be reported through on_close since it was never
  // admitted.
  {
    int fd = -1;
    SSL_CTX* ctx = nullptr;
    SSL* ssl = nullptr;
    connect_tls(fd, ctx, ssl);
    REQUIRE(SSL_connect(ssl) != 1);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    ::close(fd);
  }

  // Now drop the two admitted connections; each must be released exactly once.
  for (size_t i = 0; i < cap; ++i)
  {
    SSL_free(ssls[i]);
    SSL_CTX_free(ctxs[i]);
    ::close(fds[i]);
  }

  {
    std::unique_lock<std::mutex> lock(m);
    REQUIRE(cv.wait_for(
      lock, std::chrono::seconds(10), [&]() { return closed.size() >= cap; }));
    REQUIRE(closed.size() == cap);
    REQUIRE(
      std::set<::tcp::ConnID>(closed.begin(), closed.end()) ==
      std::set<::tcp::ConnID>(admitted.begin(), admitted.end()));
  }

  server->stop(OpenSSLServer::LoopState::Running);
}

// Node startup can fail after the interfaces are listening but before the
// event loop is ever entered, so stopping without a running loop has to be
// safe. The servers do not drive the loop themselves: they hand their handles
// to uv_close and return. Each handle owns itself, so the servers can then be
// destroyed immediately, and the loop reclaims the handles whenever it next
// runs - or never, for a process on its way out.
TEST_CASE("Transports stop and are destroyed before the libuv loop ever runs")
{
  auto [cert, key] = make_server_cert();
  {
    auto tcp_server = std::make_shared<OpenSSLServer>(
      OpenSSLServer::Config{
        .host = "127.0.0.1", .cert_pem = cert, .key_pem = key},
      [](
        ::tcp::ConnID,
        std::vector<uint8_t>,
        const std::vector<uint8_t>&,
        bool) {});
    tcp_server->start();
    tcp_server->stop();

    DatagramServer udp_server(
      "127.0.0.1",
      0,
      [](const uint8_t*, size_t, const sockaddr_storage&, socklen_t) {});
    udp_server.start();
    udp_server.stop();

    // Both servers go out of scope here, while their handles are still
    // registered with the loop and awaiting their close callbacks.
  }

  // Which the loop can now run without touching the destroyed servers. This
  // mirrors the drain run.cpp performs after its event loop exits.
  constexpr size_t max_iterations = 100;
  size_t iterations = 0;
  while (uv_loop_alive(uv_default_loop()) != 0 && iterations < max_iterations)
  {
    uv_run(uv_default_loop(), UV_RUN_NOWAIT);
    ++iterations;
  }
  REQUIRE(uv_loop_alive(uv_default_loop()) == 0);
}

TEST_CASE("Transport shutdown drains TLS tasks with no background workers")
{
  struct RestoreWorkers
  {
    ~RestoreWorkers()
    {
      ccf::tasks::set_task_threads(4);
    }
  } restore_workers;
  ccf::tasks::set_task_threads(0);

  auto [cert, key] = make_server_cert();
  auto server = std::make_shared<OpenSSLServer>(
    OpenSSLServer::Config{
      .host = "127.0.0.1", .cert_pem = cert, .key_pem = key},
    [](::tcp::ConnID, std::vector<uint8_t>, const std::vector<uint8_t>&, bool) {
    });
  UVLoopRunner loop;
  server->start();
  loop.start();

  const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  REQUIRE(fd >= 0);
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(server->port());
  REQUIRE(inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) == 1);
  REQUIRE(::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);
  const uint8_t byte = 0;
  REQUIRE(::send(fd, &byte, sizeof(byte), MSG_NOSIGNAL) == sizeof(byte));

  const auto deadline =
    std::chrono::steady_clock::now() + std::chrono::seconds(5);
  while (ccf::tasks::get_main_job_board().get_summary().pending_tasks == 0 &&
         std::chrono::steady_clock::now() < deadline)
  {
    std::this_thread::yield();
  }
  REQUIRE(ccf::tasks::get_main_job_board().get_summary().pending_tasks > 0);

  server->stop(OpenSSLServer::LoopState::Running);
  ::close(fd);
}

// Shutdown must not declare itself complete on a transient lull in the
// pending-close count. Connections close one at a time, and libuv runs close
// callbacks at the end of each loop iteration, so a connection which tears
// down promptly can look like the last one while others are still open.
// Reporting "stopped" there lets the caller destroy the server while the loop
// is still going to use its handles.
//
// The stagger is produced by holding some connections' workers inside on_data
// while one connection is left idle and therefore closes immediately.
TEST_CASE("Shutdown with staggered connection closes releases every uv handle")
{
  auto [cert, key] = make_server_cert();

  constexpr size_t num_conns = 3;
  constexpr size_t num_blocked = 2;

  std::mutex m;
  std::condition_variable cv;
  std::map<::tcp::ConnID, bool> block_decision;
  size_t arrived = 0;
  bool release = false;

  auto server = std::make_shared<OpenSSLServer>(
    OpenSSLServer::Config{
      .host = "127.0.0.1",
      .cert_pem = cert,
      .key_pem = key,
      // Configure an idle timeout, so the timer handle is in play as well.
      .idle_timeout = std::chrono::milliseconds(60000)},
    [&](
      ::tcp::ConnID id,
      std::vector<uint8_t>,
      const std::vector<uint8_t>&,
      bool) {
      bool should_block = false;
      {
        std::unique_lock<std::mutex> lock(m);
        auto it = block_decision.find(id);
        if (it == block_decision.end())
        {
          it = block_decision.emplace(id, block_decision.size() < num_blocked)
                 .first;
          ++arrived;
          cv.notify_all();
        }
        should_block = it->second;
        if (should_block)
        {
          cv.wait(lock, [&]() { return release; });
        }
      }
    });
  UVLoopRunner loop;
  server->start();
  const auto port = server->port();
  loop.start();

  std::vector<std::thread> clients;
  clients.reserve(num_conns);
  for (size_t i = 0; i < num_conns; ++i)
  {
    clients.emplace_back([port, &m, &cv, &release]() {
      const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
      REQUIRE(fd >= 0);
      sockaddr_in addr{};
      addr.sin_family = AF_INET;
      addr.sin_port = htons(port);
      REQUIRE(inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) == 1);
      REQUIRE(
        ::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);

      SSL_CTX* cctx = SSL_CTX_new(TLS_client_method());
      REQUIRE(cctx != nullptr);
      SSL* ssl = SSL_new(cctx);
      REQUIRE(ssl != nullptr);
      REQUIRE(SSL_set_fd(ssl, fd) == 1);
      SSL_set_connect_state(ssl);
      REQUIRE(SSL_connect(ssl) == 1);
      const uint8_t byte = 'x';
      REQUIRE(SSL_write(ssl, &byte, 1) == 1);

      // Hold the connection open until the blocked workers are released, so
      // that shutdown genuinely has several live connections to tear down.
      {
        std::unique_lock<std::mutex> lock(m);
        cv.wait(lock, [&]() { return release; });
      }
      SSL_free(ssl);
      SSL_CTX_free(cctx);
      ::close(fd);
    });
  }

  {
    std::unique_lock<std::mutex> lock(m);
    REQUIRE(cv.wait_for(
      lock, std::chrono::seconds(10), [&]() { return arrived == num_conns; }));
  }

  // Release the held workers only after shutdown has had time to close the
  // one connection which is not blocked, which is the window in which the
  // pending-close count transiently reaches zero.
  std::thread releaser([&]() {
    std::this_thread::sleep_for(std::chrono::milliseconds(250));
    std::lock_guard<std::mutex> guard(m);
    release = true;
    cv.notify_all();
  });

  server->stop(OpenSSLServer::LoopState::Running);

  releaser.join();
  for (auto& t : clients)
  {
    t.join();
  }

  // stop() has returned, so nothing refers to the handles any more and the
  // server can be destroyed even though the loop has not yet reclaimed them.
  server.reset();

  // The loop then finishes of its own accord, which it can only do once every
  // handle has been closed - so if any had been missed, or if a close callback
  // touched the destroyed server, this would hang or crash rather than pass.
  loop.thread.join();
  REQUIRE(uv_loop_alive(uv_default_loop()) == 0);
}

// Shutdown must not be hostage to a peer which has stopped reading. A
// connection with output it cannot flush is closed after a single further
// pass, rather than being re-dispatched until the socket becomes writable -
// which, for a client advertising a zero window, is never.
TEST_CASE("Shutdown completes while a connection cannot flush its output")
{
  auto [cert, key] = make_server_cert();

  // Far larger than any socket buffer, so the write is guaranteed to stall
  // with most of the payload still queued.
  constexpr size_t payload_size = 32 * 1024 * 1024;
  const std::vector<uint8_t> payload(payload_size, 'z');

  std::shared_ptr<OpenSSLServer> server;
  server = std::make_shared<OpenSSLServer>(
    OpenSSLServer::Config{
      .host = "127.0.0.1", .cert_pem = cert, .key_pem = key},
    [&](
      ::tcp::ConnID id,
      std::vector<uint8_t>,
      const std::vector<uint8_t>&,
      bool) { server->send(id, std::vector<uint8_t>(payload)); });
  UVLoopRunner loop;
  server->start();
  const auto port = server->port();
  loop.start();

  const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  REQUIRE(fd >= 0);
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  REQUIRE(inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) == 1);
  REQUIRE(::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);

  SSL_CTX* cctx = SSL_CTX_new(TLS_client_method());
  REQUIRE(cctx != nullptr);
  SSL* ssl = SSL_new(cctx);
  REQUIRE(ssl != nullptr);
  REQUIRE(SSL_set_fd(ssl, fd) == 1);
  SSL_set_connect_state(ssl);
  REQUIRE(SSL_connect(ssl) == 1);

  const uint8_t request = 'x';
  REQUIRE(SSL_write(ssl, &request, 1) == 1);

  // Read just enough to know the response has started, then stop reading. The
  // server's remaining output has nowhere to go from here on.
  std::vector<uint8_t> chunk(1024);
  REQUIRE(SSL_read(ssl, chunk.data(), static_cast<int>(chunk.size())) > 0);

  auto stopped = std::async(std::launch::async, [&]() {
    server->stop(OpenSSLServer::LoopState::Running);
  });
  const bool completed =
    stopped.wait_for(std::chrono::seconds(10)) == std::future_status::ready;

  // Unblock the server if it did not stop, so that the failure is reported
  // rather than hanging the test binary.
  SSL_free(ssl);
  SSL_CTX_free(cctx);
  ::close(fd);

  stopped.get();
  REQUIRE(completed);

  server.reset();
  loop.thread.join();
  REQUIRE(uv_loop_alive(uv_default_loop()) == 0);
}

TEST_CASE("TCP connections use the legacy latency and keepalive options")
{
  const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  REQUIRE(fd >= 0);
  REQUIRE_FALSE(asynchost::details::configure_tcp_connection(fd).has_value());

  const auto get_option = [fd](int level, int option) {
    int value = 0;
    socklen_t value_size = sizeof(value);
    REQUIRE(getsockopt(fd, level, option, &value, &value_size) == 0);
    REQUIRE(value_size == sizeof(value));
    return value;
  };

  REQUIRE(get_option(IPPROTO_TCP, TCP_NODELAY) == 1);
  REQUIRE(get_option(SOL_SOCKET, SO_KEEPALIVE) == 1);
  REQUIRE(get_option(IPPROTO_TCP, TCP_KEEPIDLE) == 30);
  REQUIRE(get_option(IPPROTO_TCP, TCP_KEEPINTVL) == 1);
  REQUIRE(get_option(IPPROTO_TCP, TCP_KEEPCNT) == 10);
  REQUIRE((fcntl(fd, F_GETFD) & FD_CLOEXEC) != 0);

  ::close(fd);

  const auto error = asynchost::details::configure_tcp_connection(-1);
  REQUIRE(error.has_value());
  REQUIRE(std::string(error->option) == "TCP_NODELAY");
  REQUIRE(error->error == EBADF);
}

TEST_CASE("TLS handshake and small round-trip")
{
  auto [cert, key] = make_server_cert();
  EchoServer s(cert, key);
  REQUIRE(s.port() != 0);

  const std::vector<uint8_t> msg = {'h', 'e', 'l', 'l', 'o'};
  REQUIRE(tls_client_exchange(s.port(), msg, msg.size()) == msg);
}

TEST_CASE("TLS processing runs off the libuv thread")
{
  auto [cert, key] = make_server_cert();
  std::mutex callback_mutex;
  std::thread::id callback_thread;
  OpenSSLServer* server_ptr = nullptr;
  auto server = std::make_shared<OpenSSLServer>(
    OpenSSLServer::Config{
      .host = "127.0.0.1", .cert_pem = cert, .key_pem = key},
    [&](
      ::tcp::ConnID id,
      std::vector<uint8_t> data,
      const std::vector<uint8_t>&,
      bool) {
      {
        std::lock_guard<std::mutex> guard(callback_mutex);
        callback_thread = std::this_thread::get_id();
      }
      server_ptr->send(id, data.data(), data.size());
    });
  UVLoopRunner loop;
  server_ptr = server.get();
  server->start();
  loop.start();

  const std::vector<uint8_t> msg = {'w', 'o', 'r', 'k', 'e', 'r'};
  REQUIRE(tls_client_exchange(server->port(), msg, msg.size()) == msg);
  {
    std::lock_guard<std::mutex> guard(callback_mutex);
    REQUIRE(callback_thread != std::thread::id{});
    REQUIRE(callback_thread != loop.thread.get_id());
  }

  server->stop(OpenSSLServer::LoopState::Running);
}

TEST_CASE("Large transfer exercises the backpressure path")
{
  auto [cert, key] = make_server_cert();
  EchoServer s(cert, key);

  // 4 MiB forces the socket send buffer to fill, so SSL_write returns
  // WANT_WRITE and the server must buffer + re-arm UV_WRITABLE.
  const auto payload = random_bytes(4 * 1024 * 1024);
  const auto resp = tls_client_exchange(s.port(), payload, payload.size());

  REQUIRE(resp.size() == payload.size());
  REQUIRE(resp == payload);
}

// A read pass stops after max_read_per_event (64KiB), so a client which sends
// far more than that in one go and then goes silent must still have all of it
// delivered - either because the socket is still readable, or because the
// server noticed OpenSSL's own buffered data (SSL_has_pending) and scheduled
// another pass.
//
// NB: with OpenSSL's default TLS settings (read_ahead off, one record per
// socket read) the second case is hard to provoke deliberately, so this test
// does not by itself prove the SSL_has_pending() continuation is load-bearing.
// It covers the multi-pass read path, which is the part that regresses easily.
TEST_CASE("A single large write past the per-pass read cap is fully delivered")
{
  auto [cert, key] = make_server_cert();

  std::mutex m;
  std::condition_variable cv;
  size_t received = 0;

  auto server = std::make_shared<OpenSSLServer>(
    OpenSSLServer::Config{
      .host = "127.0.0.1", .cert_pem = cert, .key_pem = key},
    [&](
      ::tcp::ConnID,
      std::vector<uint8_t> data,
      const std::vector<uint8_t>&,
      bool) {
      std::lock_guard<std::mutex> guard(m);
      received += data.size();
      cv.notify_all();
    });
  UVLoopRunner loop;
  server->start();
  loop.start();

  // Comfortably more than the 64KiB per-pass cap, written in one go and
  // followed by no further traffic at all.
  const size_t payload_size = 512 * 1024;
  const auto payload = random_bytes(payload_size);

  std::thread client([&]() {
    const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    REQUIRE(fd >= 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(server->port());
    REQUIRE(inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) == 1);
    REQUIRE(
      ::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);

    SSL_CTX* cctx = SSL_CTX_new(TLS_client_method());
    REQUIRE(cctx != nullptr);
    SSL* ssl = SSL_new(cctx);
    REQUIRE(ssl != nullptr);
    REQUIRE(SSL_set_fd(ssl, fd) == 1);
    SSL_set_connect_state(ssl);
    REQUIRE(SSL_connect(ssl) == 1);

    size_t off = 0;
    while (off < payload.size())
    {
      const int n = SSL_write(
        ssl, payload.data() + off, static_cast<int>(payload.size() - off));
      REQUIRE(n > 0);
      off += static_cast<size_t>(n);
    }

    // Deliberately send nothing more, and hold the connection open, so the
    // only way the server can see the rest is by noticing its own buffered
    // data rather than waiting for readability.
    {
      std::unique_lock<std::mutex> lock(m);
      cv.wait_for(lock, std::chrono::seconds(10), [&]() {
        return received >= payload_size;
      });
    }

    SSL_free(ssl);
    SSL_CTX_free(cctx);
    ::close(fd);
  });

  {
    std::unique_lock<std::mutex> lock(m);
    REQUIRE(cv.wait_for(lock, std::chrono::seconds(10), [&]() {
      return received >= payload_size;
    }));
    REQUIRE(received == payload_size);
  }

  client.join();
  server->stop(OpenSSLServer::LoopState::Running);
}

TEST_CASE("Concurrent connections")
{
  auto [cert, key] = make_server_cert();
  EchoServer s(cert, key);
  const uint16_t port = s.port();

  constexpr int num_clients = 16;
  std::vector<std::thread> clients;
  std::atomic<int> ok{0};
  clients.reserve(num_clients);
  for (int i = 0; i < num_clients; ++i)
  {
    clients.emplace_back([port, i, &ok]() {
      const std::vector<uint8_t> msg(64, static_cast<uint8_t>('A' + (i % 26)));
      const auto resp = tls_client_exchange(port, msg, msg.size());
      if (resp == msg)
      {
        ok.fetch_add(1);
      }
    });
  }
  for (auto& t : clients)
  {
    t.join();
  }

  REQUIRE(ok.load() == num_clients);
}

// Models the production dispatch path: the libuv thread hands the request to a
// worker thread, which replies via send() - exercising cross-thread send +
// uv_async_t loop wakeup.
TEST_CASE("Reply from a worker thread")
{
  auto [cert, key] = make_server_cert();

  OpenSSLServer* sp = nullptr;
  std::mutex m;
  std::condition_variable cv;
  std::deque<std::pair<uint64_t, std::vector<uint8_t>>> q;
  std::atomic<bool> stop{false};

  std::thread worker([&]() {
    for (;;)
    {
      std::unique_lock<std::mutex> l(m);
      cv.wait(l, [&]() { return stop.load() || !q.empty(); });
      if (stop.load() && q.empty())
      {
        return;
      }
      auto item = std::move(q.front());
      q.pop_front();
      l.unlock();
      sp->send(item.first, item.second.data(), item.second.size());
    }
  });

  auto server = std::make_shared<OpenSSLServer>(
    OpenSSLServer::Config{
      .host = "127.0.0.1", .cert_pem = cert, .key_pem = key},
    [&](
      uint64_t id, std::vector<uint8_t> d, const std::vector<uint8_t>&, bool) {
      {
        std::lock_guard<std::mutex> l(m);
        q.emplace_back(id, std::move(d));
      }
      cv.notify_one();
    });
  UVLoopRunner loop;
  sp = server.get();
  server->start();
  loop.start();

  const std::vector<uint8_t> msg = {'w', 'o', 'r', 'k', 'e', 'r'};
  REQUIRE(tls_client_exchange(server->port(), msg, msg.size()) == msg);

  server->stop(OpenSSLServer::LoopState::Running);
  {
    std::lock_guard<std::mutex> l(m);
    stop.store(true);
  }
  cv.notify_one();
  worker.join();
}

TEST_CASE("Datagram server round-trip on the libuv reactor")
{
  DatagramServer* server_ptr = nullptr;
  DatagramServer server(
    "127.0.0.1",
    0,
    [&](
      const uint8_t* data,
      size_t len,
      const sockaddr_storage& peer,
      socklen_t peerlen) {
      REQUIRE(server_ptr->send_to(peer, peerlen, data, len));
    });
  UVLoopRunner loop;
  server_ptr = &server;
  server.start();
  loop.start();

  const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
  REQUIRE(fd >= 0);
  timeval timeout{1, 0};
  REQUIRE(
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = htons(server.port());
  REQUIRE(inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) == 1);

  const std::vector<uint8_t> message = {'u', 'd', 'p'};
  REQUIRE(
    ::sendto(
      fd,
      message.data(),
      message.size(),
      0,
      reinterpret_cast<sockaddr*>(&address),
      sizeof(address)) == static_cast<ssize_t>(message.size()));
  std::vector<uint8_t> response(message.size());
  REQUIRE(::recv(fd, response.data(), response.size(), 0) == 3);
  REQUIRE(response == message);
  ::close(fd);

  server.stop(DatagramServer::LoopState::Running);
}

// The datagram handler runs inline on the libuv thread and, in the real
// manager, takes the same lock that shutdown needs. Shutting down while
// datagrams are still arriving must therefore not deadlock: shutdown waits on
// the loop, and the loop must never end up waiting on shutdown.
TEST_CASE("Datagram server stops cleanly while datagrams are still arriving")
{
  std::atomic<size_t> handled{0};
  std::mutex handler_mutex;

  DatagramServer* server_ptr = nullptr;
  DatagramServer server(
    "127.0.0.1",
    0,
    [&](
      const uint8_t* data,
      size_t len,
      const sockaddr_storage& peer,
      socklen_t peerlen) {
      // Stands in for RPCConnectionManager's interfaces_mutex, which the
      // datagram path takes on the loop thread while stop() may be running on
      // another thread.
      std::lock_guard<std::mutex> guard(handler_mutex);
      handled.fetch_add(1);
      (void)server_ptr->send_to(peer, peerlen, data, len);
    });
  UVLoopRunner loop;
  server_ptr = &server;
  server.start();
  const auto port = server.port();
  loop.start();

  std::atomic<bool> sending{true};
  std::thread flooder([port, &sending]() {
    const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    REQUIRE(fd >= 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    REQUIRE(inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) == 1);
    const std::vector<uint8_t> message = {'u', 'd', 'p'};
    while (sending.load())
    {
      (void)::sendto(
        fd,
        message.data(),
        message.size(),
        0,
        reinterpret_cast<sockaddr*>(&address),
        sizeof(address));
    }
    ::close(fd);
  });

  const auto deadline =
    std::chrono::steady_clock::now() + std::chrono::seconds(10);
  while (handled.load() == 0 && std::chrono::steady_clock::now() < deadline)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  REQUIRE(handled.load() > 0);

  // Stops while the flood is still in flight. If this deadlocks, the test
  // hangs rather than failing, which is the intended signal.
  server.stop(DatagramServer::LoopState::Running);

  sending.store(false);
  flooder.join();

  REQUIRE(uv_loop_alive(uv_default_loop()) == 0);
}

TEST_CASE("Session bridge: round-trip via ccf::Session + SessionWriter")
{
  auto [cert, key] = make_server_cert();
  OpenSSLSessionManager mgr(
    {.host = "127.0.0.1", .cert_pem = cert, .key_pem = key},
    [](::tcp::ConnID id, ccf::SessionWriter& w, std::vector<uint8_t>, bool) {
      return std::make_shared<EchoSession>(id, w);
    });
  UVLoopRunner loop;
  mgr.start();
  loop.start();
  REQUIRE(mgr.port() != 0);

  const std::vector<uint8_t> msg = {'b', 'r', 'i', 'd', 'g', 'e'};
  REQUIRE(tls_client_exchange(mgr.port(), msg, msg.size()) == msg);

  mgr.stop(OpenSSLServer::LoopState::Running);
}

TEST_CASE("Session bridge: large transfer via ccf::Session + SessionWriter")
{
  auto [cert, key] = make_server_cert();
  OpenSSLSessionManager mgr(
    {.host = "127.0.0.1", .cert_pem = cert, .key_pem = key},
    [](::tcp::ConnID id, ccf::SessionWriter& w, std::vector<uint8_t>, bool) {
      return std::make_shared<EchoSession>(id, w);
    });
  UVLoopRunner loop;
  mgr.start();
  loop.start();

  const auto payload = random_bytes(2 * 1024 * 1024);
  const auto resp = tls_client_exchange(mgr.port(), payload, payload.size());
  REQUIRE(resp == payload);

  mgr.stop(OpenSSLServer::LoopState::Running);
}

// The server must request the client certificate during the handshake so it is
// available for application-level caller authentication (user/member cert
// auth). Verifies the cert presented by the client reaches the session factory.
TEST_CASE("Peer certificate is captured for inbound connections")
{
  auto [cert, key] = make_server_cert();
  auto [client_cert, client_key] = make_server_cert();

  std::mutex m;
  std::vector<uint8_t> captured;
  std::atomic<bool> got{false};

  OpenSSLSessionManager mgr(
    {.host = "127.0.0.1", .cert_pem = cert, .key_pem = key},
    [&](
      ::tcp::ConnID id, ccf::SessionWriter& w, std::vector<uint8_t> pc, bool) {
      {
        std::lock_guard<std::mutex> l(m);
        captured = std::move(pc);
      }
      got.store(true);
      return std::make_shared<EchoSession>(id, w);
    });
  UVLoopRunner loop;
  mgr.start();
  loop.start();

  const std::vector<uint8_t> msg = {'m', 't', 'l', 's'};
  REQUIRE(
    tls_client_exchange(mgr.port(), msg, msg.size(), client_cert, client_key) ==
    msg);

  REQUIRE(got.load());
  std::lock_guard<std::mutex> l(m);
  REQUIRE(!captured.empty());

  mgr.stop(OpenSSLServer::LoopState::Running);
}

// The server deliberately does not enforce client certificate validity: it
// requests one and hands whatever arrives to the application, which decides.
// A client presenting no certificate at all must therefore still connect.
TEST_CASE("Client certificate is requested but not enforced")
{
  auto [cert, key] = make_server_cert();

  std::mutex m;
  std::vector<uint8_t> captured;
  std::atomic<bool> got{false};

  OpenSSLSessionManager mgr(
    {.host = "127.0.0.1", .cert_pem = cert, .key_pem = key},
    [&](
      ::tcp::ConnID id, ccf::SessionWriter& w, std::vector<uint8_t> pc, bool) {
      {
        std::lock_guard<std::mutex> l(m);
        captured = std::move(pc);
      }
      got.store(true);
      return std::make_shared<EchoSession>(id, w);
    });
  UVLoopRunner loop;
  mgr.start();
  loop.start();

  const std::vector<uint8_t> msg = {'n', 'o', 'c', 'e', 'r', 't'};
  REQUIRE(tls_client_exchange(mgr.port(), msg, msg.size()) == msg);

  REQUIRE(got.load());
  std::lock_guard<std::mutex> l(m);
  REQUIRE(captured.empty());

  mgr.stop(OpenSSLServer::LoopState::Running);
}

// The server certificate must be verifiable by a client that trusts the CA
// which endorsed it, and rejected by one that does not.
TEST_CASE("Server certificate is verified by the client")
{
  auto ca = make_ca();

  SUBCASE("a client trusting the endorsing CA completes the handshake")
  {
    auto [cert, key] = make_endorsed_server_cert(ca);
    EchoServer s(cert, key);
    REQUIRE(verifying_client_handshake(s.port(), ca.cert));
  }

  SUBCASE("a client trusting a different CA rejects the server")
  {
    auto [cert, key] = make_endorsed_server_cert(ca);
    EchoServer s(cert, key);
    REQUIRE_FALSE(verifying_client_handshake(s.port(), make_ca().cert));
  }

  SUBCASE("a verifying client rejects a self-signed server certificate")
  {
    auto [cert, key] = make_server_cert();
    EchoServer s(cert, key);
    REQUIRE_FALSE(verifying_client_handshake(s.port(), ca.cert));
  }
}

namespace
{
  // Connect to host:port (resolved via getaddrinfo, any family), TLS
  // round-trip.
  std::vector<uint8_t> tls_echo_roundtrip(
    const std::string& host, uint16_t port, const std::vector<uint8_t>& msg)
  {
    addrinfo hints{};
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    REQUIRE(
      getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) ==
      0);
    int fd = -1;
    for (addrinfo* ai = res; ai != nullptr; ai = ai->ai_next)
    {
      fd = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
      if (fd < 0)
      {
        continue;
      }
      if (::connect(fd, ai->ai_addr, ai->ai_addrlen) == 0)
      {
        break;
      }
      ::close(fd);
      fd = -1;
    }
    freeaddrinfo(res);
    REQUIRE(fd >= 0);

    SSL_CTX* cctx = SSL_CTX_new(TLS_client_method());
    REQUIRE(cctx != nullptr);
    SSL* ssl = SSL_new(cctx);
    REQUIRE(SSL_set_fd(ssl, fd) == 1);
    SSL_set_connect_state(ssl);
    REQUIRE(SSL_connect(ssl) == 1);

    size_t off = 0;
    while (off < msg.size())
    {
      const int n =
        SSL_write(ssl, msg.data() + off, static_cast<int>(msg.size() - off));
      REQUIRE(n > 0);
      off += static_cast<size_t>(n);
    }

    std::vector<uint8_t> resp(msg.size());
    size_t roff = 0;
    while (roff < resp.size())
    {
      const int n =
        SSL_read(ssl, resp.data() + roff, static_cast<int>(resp.size() - roff));
      if (n <= 0)
      {
        break;
      }
      roff += static_cast<size_t>(n);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(cctx);
    ::close(fd);
    return resp;
  }
}

TEST_CASE("Listener binds a hostname (localhost)")
{
  auto [cert, key] = make_server_cert();
  EchoServer s(cert, key, "localhost");
  REQUIRE(s.port() != 0);

  const std::vector<uint8_t> msg = {'l', 'o', 'c', 'a', 'l'};
  REQUIRE(tls_echo_roundtrip("localhost", s.port(), msg) == msg);
}

TEST_CASE("Listener binds IPv6 loopback when available")
{
  auto [cert, key] = make_server_cert();
  std::unique_ptr<EchoServer> s;
  try
  {
    s = std::make_unique<EchoServer>(cert, key, "::1");
  }
  catch (const std::exception&)
  {
    MESSAGE("IPv6 loopback unavailable in this environment - skipping");
    return;
  }

  const std::vector<uint8_t> msg = {'v', '6'};
  REQUIRE(tls_echo_roundtrip("::1", s->port(), msg) == msg);
}

TEST_CASE("Graceful close flushes buffered response without truncation")
{
  auto [cert, key] = make_server_cert();
  const auto payload = random_bytes(4 * 1024 * 1024);

  OpenSSLSessionManager mgr(
    {.host = "127.0.0.1", .cert_pem = cert, .key_pem = key},
    [&payload](
      ::tcp::ConnID id, ccf::SessionWriter& w, std::vector<uint8_t>, bool) {
      return std::make_shared<LargeThenCloseSession>(id, w, payload);
    });
  UVLoopRunner loop;
  mgr.start();
  loop.start();

  const std::vector<uint8_t> req = {'g', 'o'};
  const auto resp = tls_client_exchange(mgr.port(), req, payload.size());
  REQUIRE(resp.size() == payload.size());
  REQUIRE(resp == payload);

  mgr.stop(OpenSSLServer::LoopState::Running);
}

// Multiple sequential requests on a single kept-alive TLS connection - the node
// must not drop the connection between requests (regression for the e2e
// "Server disconnected" after a few requests on an idle keep-alive connection).
TEST_CASE("Persistent connection survives many sequential round-trips")
{
  auto [cert, key] = make_server_cert();
  EchoServer s(cert, key);
  REQUIRE(s.port() != 0);

  const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  REQUIRE(fd >= 0);
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(s.port());
  REQUIRE(inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) == 1);
  REQUIRE(::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);

  SSL_CTX* cctx = SSL_CTX_new(TLS_client_method());
  SSL* ssl = SSL_new(cctx);
  REQUIRE(SSL_set_fd(ssl, fd) == 1);
  SSL_set_connect_state(ssl);
  REQUIRE(SSL_connect(ssl) == 1);

  for (int i = 0; i < 10; ++i)
  {
    const std::vector<uint8_t> msg = {
      'r', static_cast<uint8_t>('0' + (i % 10))};
    REQUIRE(SSL_write(ssl, msg.data(), static_cast<int>(msg.size())) == 2);

    std::vector<uint8_t> resp(msg.size());
    size_t off = 0;
    while (off < resp.size())
    {
      const int n =
        SSL_read(ssl, resp.data() + off, static_cast<int>(resp.size() - off));
      REQUIRE(n > 0);
      off += static_cast<size_t>(n);
    }
    REQUIRE(resp == msg);

    // Idle a moment between requests, as the e2e client does (sleep(0.5)).
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }

  SSL_shutdown(ssl);
  SSL_free(ssl);
  SSL_CTX_free(cctx);
  ::close(fd);
}

// The server's cipher, ciphersuite and group policy is defined in
// build_server_ctx(). These assert it from the wire.

TEST_CASE("Server restricts TLS 1.3 ciphersuites to the configured list")
{
  auto [cert, key] = make_server_cert();
  EchoServer s(cert, key);

  SUBCASE("a configured ciphersuite is accepted")
  {
    const auto r =
      handshake_and_inspect(s.port(), {}, "TLS_AES_256_GCM_SHA384");
    REQUIRE(r.succeeded);
    REQUIRE(r.cipher == "TLS_AES_256_GCM_SHA384");
  }

  SUBCASE("the other configured ciphersuite is accepted")
  {
    const auto r =
      handshake_and_inspect(s.port(), {}, "TLS_AES_128_GCM_SHA256");
    REQUIRE(r.succeeded);
    REQUIRE(r.cipher == "TLS_AES_128_GCM_SHA256");
  }

  SUBCASE("an unconfigured ciphersuite is refused")
  {
    // ChaCha20-Poly1305 is a valid TLS 1.3 ciphersuite that CCF does not offer.
    const auto r =
      handshake_and_inspect(s.port(), {}, "TLS_CHACHA20_POLY1305_SHA256");
    REQUIRE_FALSE(r.succeeded);
  }
}

TEST_CASE("Server restricts key exchange groups to the configured list")
{
  auto [cert, key] = make_server_cert();
  EchoServer s(cert, key);

  SUBCASE("an approved classical group is accepted")
  {
    const auto r = handshake_and_inspect(s.port(), "P-256");
    REQUIRE(r.succeeded);
    REQUIRE(r.group == "secp256r1");
  }

  SUBCASE("the client order decides among approved groups")
  {
    // In TLS 1.3 OpenSSL selects the first client-offered group the server
    // also supports, so the server order is only a filter.
    REQUIRE(
      handshake_and_inspect(s.port(), "P-521:P-256").group == "secp521r1");
    REQUIRE(
      handshake_and_inspect(s.port(), "P-256:P-521").group == "secp256r1");
  }

  SUBCASE("a group the server does not offer is refused")
  {
    const auto r = handshake_and_inspect(s.port(), "X448");
    REQUIRE_FALSE(r.succeeded);
  }

  SUBCASE("an unoffered group falls back to the first shared approved one")
  {
    const auto r = handshake_and_inspect(s.port(), "X448:P-384");
    REQUIRE(r.succeeded);
    REQUIRE(r.group == "secp384r1");
  }
}

TEST_CASE(
  "Server prefers the strongest hybrid post-quantum group" *
  doctest::skip(TEST_HYBRID_TLS_GROUPS == 0))
{
  auto [cert, key] = make_server_cert();
  EchoServer s(cert, key);

  SUBCASE("a client offering all configured groups gets the strongest hybrid")
  {
    const auto r = handshake_and_inspect(
      s.port(),
      "SecP384r1MLKEM1024:SecP256r1MLKEM768:X25519MLKEM768:P-521:P-384:P-256");
    REQUIRE(r.succeeded);
    REQUIRE(r.group == "SecP384r1MLKEM1024");
  }

  SUBCASE("each configured hybrid group can be negotiated")
  {
    for (const auto* group :
         {"SecP384r1MLKEM1024", "SecP256r1MLKEM768", "X25519MLKEM768"})
    {
      const auto r = handshake_and_inspect(s.port(), group);
      REQUIRE(r.succeeded);
      REQUIRE(r.group == group);
    }
  }
}

// A client which sends faster than the node can execute must not be able to
// make it queue unbounded work. Reads pause once the node-wide budget is
// exhausted and resume once it is released, without dropping or truncating
// anything.
TEST_CASE("Reads pause while the node-wide inbound budget is exhausted")
{
  auto [cert, key] = make_server_cert();

  constexpr size_t limit = 64 * 1024;
  constexpr size_t to_send = 4 * 1024 * 1024;
  auto admission = std::make_shared<InboundAdmission>(limit);

  std::atomic<size_t> received{0};

  // Stands in for the bridge, which charges the budget as it hands data to a
  // session and releases it once the session reports the data processed. This
  // session never reports, so the budget stays charged until the test frees it.
  auto server = std::make_shared<OpenSSLServer>(
    OpenSSLServer::Config{
      .host = "127.0.0.1",
      .cert_pem = cert,
      .key_pem = key,
      .inbound_admission = admission},
    [&](
      ::tcp::ConnID,
      std::vector<uint8_t> d,
      const std::vector<uint8_t>&,
      bool) {
      received += d.size();
      admission->queued(d.size());
    });

  UVLoopRunner loop;
  server->start();
  const auto port = server->port();
  loop.start();

  // The client has to run on its own thread: once the server stops reading,
  // the socket buffers fill and SSL_write blocks. It must also stay connected
  // until the server has read everything - closing a socket which still has
  // unread data resets the connection and discards it.
  std::atomic<bool> client_may_close{false};
  std::thread client([port, &client_may_close]() {
    const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    REQUIRE(fd >= 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    REQUIRE(inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) == 1);
    REQUIRE(
      ::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);

    SSL_CTX* cctx = SSL_CTX_new(TLS_client_method());
    REQUIRE(cctx != nullptr);
    SSL* ssl = SSL_new(cctx);
    REQUIRE(ssl != nullptr);
    REQUIRE(SSL_set_fd(ssl, fd) == 1);
    SSL_set_connect_state(ssl);
    REQUIRE(SSL_connect(ssl) == 1);

    const std::vector<uint8_t> chunk(16 * 1024, 'x');
    size_t sent = 0;
    while (sent < to_send)
    {
      const int n =
        SSL_write(ssl, chunk.data(), static_cast<int>(chunk.size()));
      if (n <= 0)
      {
        break;
      }
      sent += static_cast<size_t>(n);
    }

    while (!client_may_close.load())
    {
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    SSL_free(ssl);
    SSL_CTX_free(cctx);
    ::close(fd);
  });

  // Wait for the gate to engage.
  const auto deadline =
    std::chrono::steady_clock::now() + std::chrono::seconds(10);
  while (!admission->saturated() && std::chrono::steady_clock::now() < deadline)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  REQUIRE(admission->saturated());

  // Give the server every chance to keep reading if the gate does not hold.
  std::this_thread::sleep_for(std::chrono::milliseconds(500));

  // A pass which was already in flight when the gate engaged may read up to
  // its per-pass cap, and the kernel and OpenSSL hold buffers of their own, so
  // some overshoot is expected. What must not happen is the whole 4MiB
  // arriving: without the gate this reaches to_send almost immediately.
  const size_t stalled_at = received.load();
  REQUIRE(stalled_at < to_send);
  REQUIRE(stalled_at <= limit + (1024 * 1024));

  // Releasing the budget must wake the transport and let the rest through -
  // the gate pauses reads, it does not drop or truncate anything.
  admission->consumed(admission->bytes_pending());
  REQUIRE_FALSE(admission->saturated());

  const auto resume_deadline =
    std::chrono::steady_clock::now() + std::chrono::seconds(20);
  while (received.load() < to_send &&
         std::chrono::steady_clock::now() < resume_deadline)
  {
    // The test is standing in for the bridge, so it also has to keep releasing
    // as the server reads more.
    admission->consumed(admission->bytes_pending());
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  REQUIRE(received.load() == to_send);

  client_may_close.store(true);
  client.join();
  server->stop(OpenSSLServer::LoopState::Running);
  server.reset();
  loop.thread.join();
}

// A session which never reports the data it was given - a custom protocol, or
// one whose queued work is cancelled as it is destroyed - must not be able to
// strand part of the node-wide budget. The bridge releases whatever is still
// outstanding when the connection is torn down.
TEST_CASE("Inbound budget is released when a connection closes unreported")
{
  auto [cert, key] = make_server_cert();

  constexpr size_t limit = 1024 * 1024;
  auto admission = std::make_shared<InboundAdmission>(limit);

  OpenSSLSessionManager bridge(
    OpenSSLServer::Config{
      .host = "127.0.0.1",
      .cert_pem = cert,
      .key_pem = key,
      .inbound_admission = admission},
    [&](::tcp::ConnID id, ccf::SessionWriter& w, std::vector<uint8_t>, bool)
      -> std::shared_ptr<ccf::Session> {
      // EchoSession is a plain ccf::Session, so it never calls
      // inbound_consumed - exactly the case this test is about.
      return std::make_shared<EchoSession>(id, w);
    });

  UVLoopRunner loop;
  bridge.start();
  const auto port = bridge.port();
  loop.start();

  {
    const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    REQUIRE(fd >= 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    REQUIRE(inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) == 1);
    REQUIRE(
      ::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);

    SSL_CTX* cctx = SSL_CTX_new(TLS_client_method());
    REQUIRE(cctx != nullptr);
    SSL* ssl = SSL_new(cctx);
    REQUIRE(ssl != nullptr);
    REQUIRE(SSL_set_fd(ssl, fd) == 1);
    SSL_set_connect_state(ssl);
    REQUIRE(SSL_connect(ssl) == 1);

    const std::vector<uint8_t> payload(32 * 1024, 'y');
    REQUIRE(
      SSL_write(ssl, payload.data(), static_cast<int>(payload.size())) ==
      static_cast<int>(payload.size()));

    // Wait for the bytes to be charged to the budget.
    const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (admission->bytes_pending() < payload.size() &&
           std::chrono::steady_clock::now() < deadline)
    {
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    REQUIRE(admission->bytes_pending() >= payload.size());

    SSL_free(ssl);
    SSL_CTX_free(cctx);
    ::close(fd);
  }

  // Closing the connection must hand the whole charge back, or a node would
  // leak budget on every connection which used a non-reporting session and
  // would eventually stop reading altogether.
  const auto deadline =
    std::chrono::steady_clock::now() + std::chrono::seconds(10);
  while (admission->bytes_pending() != 0 &&
         std::chrono::steady_clock::now() < deadline)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  REQUIRE(admission->bytes_pending() == 0);

  bridge.stop(OpenSSLServer::LoopState::Running);
  loop.thread.join();
}
