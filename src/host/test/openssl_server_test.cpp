// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

// Unit tests for the OpenSSL-native RPC transport and SessionWriter bridge.

#include "ccf/crypto/ec_key_pair.h"
#include "ccf/ds/x509_time_fmt.h"
#include "crypto/certs.h"
#include "host/tls/openssl_server.h"
#include "host/tls/openssl_session_manager.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <deque>
#include <doctest/doctest.h>
#include <mutex>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <random>
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
  struct EchoServer
  {
    std::unique_ptr<OpenSSLServer> server;

    EchoServer(
      const std::string& cert,
      const std::string& key,
      const std::string& host = "127.0.0.1")
    {
      server = std::make_unique<OpenSSLServer>(
        cert,
        key,
        host,
        static_cast<uint16_t>(0),
        [this](uint64_t id, std::vector<uint8_t> d) {
          server->send(id, d.data(), d.size());
        });
      server->start();
    }

    ~EchoServer()
    {
      server->stop();
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

    void handle_incoming_data(
      std::span<const uint8_t> data, sockaddr /*addr*/ = {}) override
    {
      writer.write_outbound(id, data);
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

    void handle_incoming_data(
      std::span<const uint8_t> /*data*/, sockaddr /*addr*/ = {}) override
    {
      writer.write_outbound(id, payload);
      writer.close_socket(id);
    }

    void send_data(std::vector<uint8_t>&& /*data*/) override {}
    void close_session() override {}
  };
}

TEST_CASE("TLS handshake and small round-trip")
{
  auto [cert, key] = make_server_cert();
  EchoServer s(cert, key);
  REQUIRE(s.port() != 0);

  const std::vector<uint8_t> msg = {'h', 'e', 'l', 'l', 'o'};
  REQUIRE(tls_client_exchange(s.port(), msg, msg.size()) == msg);
}

TEST_CASE("Large transfer exercises the backpressure path")
{
  auto [cert, key] = make_server_cert();
  EchoServer s(cert, key);

  // 4 MiB forces the socket send buffer to fill, so SSL_write returns
  // WANT_WRITE and the server must buffer + re-arm EPOLLOUT.
  const auto payload = random_bytes(4 * 1024 * 1024);
  const auto resp = tls_client_exchange(s.port(), payload, payload.size());

  REQUIRE(resp.size() == payload.size());
  REQUIRE(resp == payload);
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

// Models the production dispatch path: the epoll thread hands the request to a
// worker thread, which replies via send() - exercising cross-thread send +
// eventfd loop wakeup.
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

  OpenSSLServer server(
    cert,
    key,
    "127.0.0.1",
    static_cast<uint16_t>(0),
    [&](uint64_t id, std::vector<uint8_t> d) {
      {
        std::lock_guard<std::mutex> l(m);
        q.emplace_back(id, std::move(d));
      }
      cv.notify_one();
    });
  sp = &server;
  server.start();

  const std::vector<uint8_t> msg = {'w', 'o', 'r', 'k', 'e', 'r'};
  REQUIRE(tls_client_exchange(server.port(), msg, msg.size()) == msg);

  server.stop();
  {
    std::lock_guard<std::mutex> l(m);
    stop.store(true);
  }
  cv.notify_one();
  worker.join();
}

TEST_CASE("Session bridge: round-trip via ccf::Session + SessionWriter")
{
  auto [cert, key] = make_server_cert();
  OpenSSLSessionManager mgr(
    cert,
    key,
    "127.0.0.1",
    static_cast<uint16_t>(0),
    [](::tcp::ConnID id, ccf::SessionWriter& w, std::vector<uint8_t>) {
      return std::make_shared<EchoSession>(id, w);
    });
  mgr.start();
  REQUIRE(mgr.port() != 0);

  const std::vector<uint8_t> msg = {'b', 'r', 'i', 'd', 'g', 'e'};
  REQUIRE(tls_client_exchange(mgr.port(), msg, msg.size()) == msg);

  mgr.stop();
}

TEST_CASE("Session bridge: large transfer via ccf::Session + SessionWriter")
{
  auto [cert, key] = make_server_cert();
  OpenSSLSessionManager mgr(
    cert,
    key,
    "127.0.0.1",
    static_cast<uint16_t>(0),
    [](::tcp::ConnID id, ccf::SessionWriter& w, std::vector<uint8_t>) {
      return std::make_shared<EchoSession>(id, w);
    });
  mgr.start();

  const auto payload = random_bytes(2 * 1024 * 1024);
  const auto resp = tls_client_exchange(mgr.port(), payload, payload.size());
  REQUIRE(resp == payload);

  mgr.stop();
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
    cert,
    key,
    "127.0.0.1",
    static_cast<uint16_t>(0),
    [&](::tcp::ConnID id, ccf::SessionWriter& w, std::vector<uint8_t> pc) {
      {
        std::lock_guard<std::mutex> l(m);
        captured = std::move(pc);
      }
      got.store(true);
      return std::make_shared<EchoSession>(id, w);
    });
  mgr.start();

  const std::vector<uint8_t> msg = {'m', 't', 'l', 's'};
  REQUIRE(
    tls_client_exchange(mgr.port(), msg, msg.size(), client_cert, client_key) ==
    msg);

  REQUIRE(got.load());
  std::lock_guard<std::mutex> l(m);
  REQUIRE(!captured.empty());

  mgr.stop();
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
    cert,
    key,
    "127.0.0.1",
    static_cast<uint16_t>(0),
    [&](::tcp::ConnID id, ccf::SessionWriter& w, std::vector<uint8_t> pc) {
      {
        std::lock_guard<std::mutex> l(m);
        captured = std::move(pc);
      }
      got.store(true);
      return std::make_shared<EchoSession>(id, w);
    });
  mgr.start();

  const std::vector<uint8_t> msg = {'n', 'o', 'c', 'e', 'r', 't'};
  REQUIRE(tls_client_exchange(mgr.port(), msg, msg.size()) == msg);

  REQUIRE(got.load());
  std::lock_guard<std::mutex> l(m);
  REQUIRE(captured.empty());

  mgr.stop();
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
    cert,
    key,
    "127.0.0.1",
    static_cast<uint16_t>(0),
    [&payload](::tcp::ConnID id, ccf::SessionWriter& w, std::vector<uint8_t>) {
      return std::make_shared<LargeThenCloseSession>(id, w, payload);
    });
  mgr.start();

  const std::vector<uint8_t> req = {'g', 'o'};
  const auto resp = tls_client_exchange(mgr.port(), req, payload.size());
  REQUIRE(resp.size() == payload.size());
  REQUIRE(resp == payload);

  mgr.stop();
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
