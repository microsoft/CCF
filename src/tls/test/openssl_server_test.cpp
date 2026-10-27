// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

// Unit tests for the OpenSSL-native RPC transport and SessionWriter bridge.

#include "ccf/crypto/ec_key_pair.h"
#include "ccf/crypto/rsa_key_pair.h"
#include "ccf/ds/x509_time_fmt.h"
#include "crypto/certs.h"
#include "http/http_parser.h"
#include "http/http_proc.h"
#include "node/rpc/openssl_session_manager.h"
#include "tasks/task_system.h"
#include "tls/datagram_server.h"
#include "tls/openssl_client.h"
#include "tls/openssl_server.h"

#define DOCTEST_CONFIG_IMPLEMENT
#include <arpa/inet.h>
#include <array>
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
#include <openssl/crypto.h>
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

using namespace ccf::tls;
using ccf::OpenSSLSessionManager;

namespace
{
  struct NotificationGate
  {
    ccf::ds::Mutex mutex;
    ccf::ds::ConditionVariable cv;
    size_t calls CCF_GUARDED_BY(mutex) = 0;
    bool released CCF_GUARDED_BY(mutex) = false;

    size_t call_count() CCF_EXCLUDES(mutex)
    {
      ccf::ds::MutexGuard lock(mutex);
      return calls;
    }

    bool wait_for_calls(size_t count) CCF_EXCLUDES(mutex)
    {
      ccf::ds::MutexGuard lock(mutex);
      return cv.wait_for(
        lock, std::chrono::seconds(5), [&]() CCF_REQUIRES(mutex) {
          return calls >= count;
        });
    }

    void release() CCF_EXCLUDES(mutex)
    {
      ccf::ds::MutexGuard lock(mutex);
      released = true;
      cv.notify_all();
    }
  };

  // Installed only while the test owns all threads using the gate.
  std::atomic<NotificationGate*> notification_gate = nullptr;
  std::atomic<NotificationGate*> handshake_gate = nullptr;
  std::atomic<bool> suppress_connect_poll = false;
  std::atomic<size_t> suppressed_connect_polls = 0;
  std::atomic<size_t> socket_calls = 0;

  struct ResolutionGate
  {
    std::mutex mutex;
    std::condition_variable cv;
    std::atomic<bool> submitted = false;
    bool completed = false;
    uv_getaddrinfo_t* request = nullptr;
    uv_getaddrinfo_cb callback = nullptr;
    int status = 0;
    addrinfo* result = nullptr;
  };

  std::atomic<ResolutionGate*> resolution_gate = nullptr;
}

extern "C" int __real_SSL_do_handshake(SSL* ssl);

extern "C" int __wrap_SSL_do_handshake(SSL* ssl)
{
  const int result = __real_SSL_do_handshake(ssl);
  if (result == 1 && SSL_is_server(ssl) == 0)
  {
    if (auto* gate = handshake_gate.load())
    {
      ccf::ds::MutexGuard guard(gate->mutex);
      ++gate->calls;
      gate->cv.notify_all();
      gate->cv.wait(
        guard, [&]() CCF_REQUIRES(gate->mutex) { return gate->released; });
    }
  }
  return result;
}

extern "C" int __real_socket(int domain, int type, int protocol);

extern "C" int __wrap_socket(int domain, int type, int protocol)
{
  ++socket_calls;
  return __real_socket(domain, type, protocol);
}

extern "C" int __real_uv_getaddrinfo(
  uv_loop_t*,
  uv_getaddrinfo_t*,
  uv_getaddrinfo_cb,
  const char*,
  const char*,
  const addrinfo*);

extern "C" int __wrap_uv_getaddrinfo(
  uv_loop_t* loop,
  uv_getaddrinfo_t* request,
  uv_getaddrinfo_cb callback,
  const char* node,
  const char* service,
  const addrinfo* hints)
{
  auto* gate = resolution_gate.load();
  if (gate == nullptr || gate->submitted.exchange(true))
  {
    return __real_uv_getaddrinfo(loop, request, callback, node, service, hints);
  }
  gate->request = request;
  gate->callback = callback;
  return __real_uv_getaddrinfo(
    loop,
    request,
    [](uv_getaddrinfo_t*, int status, addrinfo* result) {
      auto* gate = resolution_gate.load();
      std::lock_guard<std::mutex> guard(gate->mutex);
      gate->status = status;
      gate->result = result;
      gate->completed = true;
      gate->cv.notify_all();
    },
    node,
    service,
    hints);
}

extern "C" int __real_uv_poll_start(uv_poll_t*, int, uv_poll_cb);

extern "C" int __wrap_uv_poll_start(
  uv_poll_t* poll, int events, uv_poll_cb callback)
{
  if (events == UV_WRITABLE && suppress_connect_poll.exchange(false))
  {
    ++suppressed_connect_polls;
    return 0;
  }
  return __real_uv_poll_start(poll, events, callback);
}

extern "C" int __real_uv_async_send(uv_async_t* handle);

extern "C" int __wrap_uv_async_send(uv_async_t* handle)
{
  if (auto* gate = notification_gate.load())
  {
    ccf::ds::MutexGuard lock(gate->mutex);
    const auto call = ++gate->calls;
    gate->cv.notify_all();
    if (call == 1)
    {
      gate->cv.wait(
        lock, [&]() CCF_REQUIRES(gate->mutex) { return gate->released; });
    }
  }
  return __real_uv_async_send(handle);
}

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

  // Sends `request` over TLS, then parses the response stream until
  // `expected_count` complete HTTP responses have been read. Used to assert
  // that multiple responses coalesced into a single write are all delivered
  // intact, which needs an HTTP parser rather than a raw byte comparison.
  struct ParsedResponse
  {
    ccf::http_status status;
    std::string body;
  };

  std::vector<ParsedResponse> tls_collect_http_responses(
    uint16_t port, const std::vector<uint8_t>& request, size_t expected_count)
  {
    struct Collector : public ::http::ResponseProcessor
    {
      std::vector<ParsedResponse> responses;

      void handle_response(
        ccf::http_status status,
        ccf::http::HeaderMap&& /*headers*/,
        std::vector<uint8_t>&& body) override
      {
        responses.push_back(
          ParsedResponse{status, std::string(body.begin(), body.end())});
      }
    };

    Collector collector;
    ::http::ResponseParser parser(collector);

    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(fd >= 0);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    REQUIRE(inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) == 1);
    REQUIRE(
      ::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);

    // Bound the read loop below: if the server fails to deliver every
    // response, the test must fail on the count assertion rather than block
    // here until the whole suite times out.
    timeval recv_timeout{};
    recv_timeout.tv_sec = 10;
    REQUIRE(
      ::setsockopt(
        fd, SOL_SOCKET, SO_RCVTIMEO, &recv_timeout, sizeof(recv_timeout)) == 0);

    SSL_CTX* cctx = SSL_CTX_new(TLS_client_method());
    REQUIRE(cctx != nullptr);
    SSL* ssl = SSL_new(cctx);
    REQUIRE(ssl != nullptr);
    REQUIRE(SSL_set_fd(ssl, fd) == 1);
    SSL_set_connect_state(ssl);
    REQUIRE(SSL_connect(ssl) == 1);

    size_t off = 0;
    while (off < request.size())
    {
      const int n = SSL_write(
        ssl, request.data() + off, static_cast<int>(request.size() - off));
      REQUIRE(n > 0);
      off += static_cast<size_t>(n);
    }

    while (collector.responses.size() < expected_count)
    {
      uint8_t buf[16384];
      const int n = SSL_read(ssl, buf, static_cast<int>(sizeof(buf)));
      if (n <= 0)
      {
        break;
      }
      parser.execute(buf, static_cast<size_t>(n));
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(cctx);
    ::close(fd);
    return collector.responses;
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
      result.group = ccf::tls::details::get_negotiated_group(ssl);
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

  bool supports_hybrid_groups()
  {
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    REQUIRE(ctx != nullptr);
    const bool supported =
      SSL_CTX_set1_groups_list(
        ctx, "SecP384r1MLKEM1024:SecP256r1MLKEM768:X25519MLKEM768") == 1;
    SSL_CTX_free(ctx);
    return supported;
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

namespace
{
  struct EnginePair
  {
    std::mutex mutex;
    std::condition_variable cv;
    std::vector<uint8_t> received;
    std::vector<uint8_t> accepted_data;
    size_t client_closed = 0;
    size_t server_closed = 0;
    size_t client_handshakes = 0;
    size_t server_handshakes = 0;
    bool reject_client = false;
    bool reject_server = false;
    bool admitted = false;
    bool reply = true;
    std::string peer_source;
    unsigned int client_user_timeout = 0;
    unsigned int server_user_timeout = 0;
    std::function<void(::tcp::ConnID)> after_client_handshake;
    UVLoopRunner loop;
    std::shared_ptr<OpenSSLServer> server;
    std::shared_ptr<OpenSSLClient> client;
    std::shared_ptr<SSL_CTX> client_ctx;

    EnginePair(
      std::optional<std::chrono::milliseconds> server_timeout = std::nullopt)
    {
      auto [cert, key] = make_server_cert();
      client_ctx = {SSL_CTX_new(TLS_client_method()), SSL_CTX_free};
      REQUIRE(client_ctx != nullptr);
      ccf::crypto::OpenSSL::Unique_BIO bio(
        cert.data(), static_cast<int>(cert.size()));
      ccf::crypto::OpenSSL::Unique_X509 root(bio, true);
      REQUIRE(root != nullptr);
      REQUIRE(
        X509_STORE_add_cert(SSL_CTX_get_cert_store(client_ctx.get()), root) ==
        1);
      SSL_CTX_set_verify(client_ctx.get(), SSL_VERIFY_PEER, nullptr);

      OpenSSLServer::Config config{
        .host = "127.0.0.1", .cert_pem = cert, .key_pem = key};
      config.tcp_user_timeout = server_timeout;
      config.on_handshake = [this](::tcp::ConnID id, SSL* ssl, bool outgoing) {
        std::lock_guard<std::mutex> guard(mutex);
        CHECK_FALSE(outgoing);
        ++server_handshakes;
        sockaddr_in peer{};
        socklen_t size = sizeof(peer);
        CHECK(
          getpeername(
            SSL_get_fd(ssl), reinterpret_cast<sockaddr*>(&peer), &size) == 0);
        std::array<char, INET_ADDRSTRLEN> address{};
        REQUIRE(
          inet_ntop(AF_INET, &peer.sin_addr, address.data(), address.size()) !=
          nullptr);
        peer_source = address.data();
        size = sizeof(server_user_timeout);
        CHECK(
          getsockopt(
            SSL_get_fd(ssl),
            IPPROTO_TCP,
            TCP_USER_TIMEOUT,
            &server_user_timeout,
            &size) == 0);
        const std::vector<uint8_t> greeting{'h', 'i'};
        if (reply)
        {
          server->send(id, greeting.data(), greeting.size());
        }
        cv.notify_all();
        return !reject_server;
      };
      server = std::make_shared<OpenSSLServer>(
        config,
        [this](
          ::tcp::ConnID id,
          std::vector<uint8_t> data,
          const std::vector<uint8_t>&,
          bool) {
          {
            std::lock_guard<std::mutex> guard(mutex);
            accepted_data.insert(accepted_data.end(), data.begin(), data.end());
          }
          if (reply)
          {
            server->send(id, std::move(data));
          }
          cv.notify_all();
        },
        [this](::tcp::ConnID) {
          std::lock_guard<std::mutex> guard(mutex);
          ++server_closed;
          cv.notify_all();
        });
      OpenSSLClient::Config client_config;
      client_config.on_handshake =
        [this](::tcp::ConnID id, SSL* ssl, bool outgoing) {
          std::lock_guard<std::mutex> guard(mutex);
          CHECK(outgoing);
          CHECK(SSL_get_verify_result(ssl) == X509_V_OK);
          CHECK(SSL_get0_peer_certificate(ssl) != nullptr);
          socklen_t size = sizeof(client_user_timeout);
          CHECK(
            getsockopt(
              SSL_get_fd(ssl),
              IPPROTO_TCP,
              TCP_USER_TIMEOUT,
              &client_user_timeout,
              &size) == 0);
          ++client_handshakes;
          admitted = !reject_client;
          if (admitted && after_client_handshake)
          {
            after_client_handshake(id);
          }
          cv.notify_all();
          return admitted;
        };
      client = std::make_shared<OpenSSLClient>(
        client_config,
        [this](
          ::tcp::ConnID,
          std::vector<uint8_t> data,
          const std::vector<uint8_t>& peer_cert,
          bool) {
          std::lock_guard<std::mutex> guard(mutex);
          CHECK(admitted);
          CHECK_FALSE(peer_cert.empty());
          received.insert(received.end(), data.begin(), data.end());
          cv.notify_all();
        },
        [this](::tcp::ConnID) {
          std::lock_guard<std::mutex> guard(mutex);
          ++client_closed;
          cv.notify_all();
        });
      server->start();
      client->start();
    }

    OpenSSLClient::ConnectConfig config()
    {
      return {
        .host = "localhost",
        .port = server->port(),
        .source_host = "127.0.0.2",
        .tls_context = client_ctx,
        .timeout = std::chrono::milliseconds(500),
        .tcp_user_timeout = std::chrono::milliseconds(1234)};
    }

    template <typename Predicate>
    bool wait(Predicate predicate)
    {
      std::unique_lock<std::mutex> lock(mutex);
      return cv.wait_for(lock, std::chrono::seconds(5), predicate);
    }

    ~EnginePair()
    {
      const auto state = loop.thread.joinable() ?
        OpenSSLServer::LoopState::Running :
        OpenSSLServer::LoopState::NotRunning;
      client->stop(state);
      server->stop(state);
    }
  };
}

TEST_CASE(
  "Outbound engine exchanges real bidirectional TLS application traffic")
{
  EnginePair pair;
  const auto id = pair.client->connect(pair.config());
  std::vector<uint8_t> payload(512 * 1024, 42);
  pair.client->send(id, payload.data(), payload.size());
  pair.loop.start();
  REQUIRE(
    pair.wait([&]() { return pair.received.size() == payload.size() + 2; }));
  {
    std::lock_guard<std::mutex> guard(pair.mutex);
    CHECK(pair.client_handshakes == 1);
    CHECK(pair.server_handshakes == 1);
    CHECK(pair.peer_source == "127.0.0.2");
    CHECK(pair.client_user_timeout == 1234);
    CHECK(pair.server_user_timeout == 0);
    CHECK(pair.accepted_data == payload);
    CHECK(
      std::vector<uint8_t>(pair.received.begin() + 2, pair.received.end()) ==
      payload);
  }
  pair.client->close_connection(id);
  REQUIRE(pair.wait([&]() { return pair.client_closed == 1; }));
}

TEST_CASE("Outbound client startup allocates no listener or socket")
{
  uv_loop_t loop{};
  REQUIRE(uv_loop_init(&loop) == 0);
  const auto before = socket_calls.load();
  {
    auto client = std::make_shared<OpenSSLClient>(
      OpenSSLClient::Config{.loop = &loop},
      [](
        ::tcp::ConnID,
        std::vector<uint8_t>,
        const std::vector<uint8_t>&,
        bool) {});
    client->start();
    client->start();
    CHECK(socket_calls == before);
    std::vector<uv_handle_type> handles;
    uv_walk(
      &loop,
      [](uv_handle_t* handle, void* arg) {
        static_cast<std::vector<uv_handle_type>*>(arg)->push_back(handle->type);
      },
      &handles);
    CHECK(handles == std::vector<uv_handle_type>{UV_ASYNC});
    client->stop();
    client->stop();
  }
  uv_run(&loop, UV_RUN_DEFAULT);
  CHECK(uv_loop_close(&loop) == 0);
}

TEST_CASE("Shared engine supports caller TLS policy without a negotiated group")
{
  using namespace std::chrono_literals;
  auto ca = make_ca();
  auto key = ccf::crypto::make_rsa_key_pair();
  const auto valid_from =
    ccf::ds::to_x509_time_string(std::chrono::system_clock::now() - 24h);
  const auto cert = ccf::crypto::create_endorsed_cert(
    key->public_key_pem(),
    "CN=localhost",
    {},
    valid_from,
    ccf::crypto::compute_cert_valid_to_string(valid_from, 365),
    ca.kp->private_key_pem(),
    ca.cert);
  const auto key_pem = key->private_key_pem();
  std::shared_ptr<SSL_CTX> server_ctx(
    SSL_CTX_new(TLS_server_method()), SSL_CTX_free);
  std::shared_ptr<SSL_CTX> client_ctx(
    SSL_CTX_new(TLS_client_method()), SSL_CTX_free);
  REQUIRE(server_ctx != nullptr);
  REQUIRE(client_ctx != nullptr);
  ccf::crypto::OpenSSL::Unique_BIO cert_bio(cert);
  ccf::crypto::OpenSSL::Unique_X509 x509(cert_bio, true);
  REQUIRE(x509 != nullptr);
  ccf::crypto::OpenSSL::Unique_BIO key_bio(key_pem);
  ccf::crypto::OpenSSL::Unique_PKEY pkey(
    PEM_read_bio_PrivateKey(key_bio, nullptr, nullptr, nullptr), EVP_PKEY_free);
  REQUIRE(SSL_CTX_use_certificate(server_ctx.get(), x509) == 1);
  REQUIRE(SSL_CTX_use_PrivateKey(server_ctx.get(), pkey) == 1);
  for (auto* context : {server_ctx.get(), client_ctx.get()})
  {
    REQUIRE(SSL_CTX_set_min_proto_version(context, TLS1_2_VERSION) == 1);
    REQUIRE(SSL_CTX_set_max_proto_version(context, TLS1_2_VERSION) == 1);
    REQUIRE(SSL_CTX_set_cipher_list(context, "AES128-GCM-SHA256") == 1);
  }

  std::mutex mutex;
  std::condition_variable cv;
  size_t handshakes = 0;
  std::vector<uint8_t> received;
  const auto on_handshake = [&](::tcp::ConnID, SSL* ssl, bool) {
    std::lock_guard<std::mutex> guard(mutex);
    CHECK(SSL_version(ssl) == TLS1_2_VERSION);
    CHECK(SSL_get0_group_name(ssl) == nullptr);
    ++handshakes;
    cv.notify_all();
    return true;
  };
  UVLoopRunner loop;
  std::shared_ptr<OpenSSLConnectionEngine> server;
  server = std::make_shared<OpenSSLConnectionEngine>(
    OpenSSLConnectionEngine::Config{.on_handshake = on_handshake},
    [&](
      ::tcp::ConnID id,
      std::vector<uint8_t> data,
      const std::vector<uint8_t>&,
      bool) { server->send(id, std::move(data)); });
  auto client = std::make_shared<OpenSSLConnectionEngine>(
    OpenSSLConnectionEngine::Config{.on_handshake = on_handshake},
    [&](
      ::tcp::ConnID,
      std::vector<uint8_t> data,
      const std::vector<uint8_t>&,
      bool) {
      std::lock_guard<std::mutex> guard(mutex);
      received.insert(received.end(), data.begin(), data.end());
      cv.notify_all();
    });

  struct StopEngines
  {
    std::shared_ptr<OpenSSLConnectionEngine> server;
    std::shared_ptr<OpenSSLConnectionEngine> client;
    UVLoopRunner& loop;

    ~StopEngines()
    {
      const auto state = loop.thread.joinable() ?
        OpenSSLConnectionEngine::LoopState::Running :
        OpenSSLConnectionEngine::LoopState::NotRunning;
      client->stop(state);
      server->stop(state);
    }
  } cleanup{server, client, loop};

  int sockets[2] = {-1, -1};
  REQUIRE(
    socketpair(
      AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sockets) == 0);
  server->start();
  client->start();
  REQUIRE(
    server->adopt({.id = 1, .fd = sockets[0], .tls_context = server_ctx}));
  REQUIRE(client->adopt(
    {.id = 1,
     .fd = sockets[1],
     .tls_context = client_ctx,
     .outgoing = true,
     .handshake_timeout = 5s}));
  const std::vector<uint8_t> payload{1, 2, 3};
  client->send(1, payload.data(), payload.size());
  loop.start();
  std::unique_lock<std::mutex> guard(mutex);
  REQUIRE(cv.wait_for(
    guard, 5s, [&]() { return received == payload && handshakes == 2; }));
}

TEST_CASE("Outbound handshake admission gates reads and queued writes")
{
  EnginePair pair;
  SUBCASE("Initiator rejects")
  {
    pair.reject_client = true;
  }
  SUBCASE("Acceptor rejects")
  {
    pair.reject_server = true;
  }
  const auto id = pair.client->connect(pair.config());
  pair.client->send(id, std::vector<uint8_t>{1, 2, 3});
  pair.loop.start();
  REQUIRE(pair.wait(
    [&]() { return pair.client_closed == 1 && pair.server_closed == 1; }));
  std::lock_guard<std::mutex> guard(pair.mutex);
  CHECK(pair.received.empty());
  CHECK(pair.accepted_data.empty());
  CHECK(pair.client_handshakes == 1);
  // If the client rejects, its close_notify can race the server's Finished.
  CHECK(pair.server_handshakes <= 1);
}

TEST_CASE("Outbound admission callback send-and-close flushes application data")
{
  EnginePair pair;
  pair.reply = false;
  const std::vector<uint8_t> payload(256 * 1024, 73);
  pair.after_client_handshake = [&](::tcp::ConnID id) {
    pair.client->send(id, payload.data(), payload.size());
    pair.client->close_connection(id);
  };
  pair.client->connect(pair.config());
  pair.loop.start();
  REQUIRE(pair.wait([&]() {
    return pair.client_closed == 1 &&
      pair.accepted_data.size() == payload.size();
  }));
  std::lock_guard<std::mutex> guard(pair.mutex);
  CHECK(pair.accepted_data == payload);
}

namespace
{
  TEST_CASE(
    "Cancellation during the final TLS drive suppresses application I/O")
  {
    using namespace std::chrono_literals;
    bool shutdown = false;
    SUBCASE("Explicit close") {}
    SUBCASE("Shutdown")
    {
      shutdown = true;
    }
    auto [cert, key] = make_server_cert();
    std::shared_ptr<SSL_CTX> server_context(
      SSL_CTX_new(TLS_server_method()), SSL_CTX_free);
    std::shared_ptr<SSL_CTX> client_context(
      SSL_CTX_new(TLS_client_method()), SSL_CTX_free);
    REQUIRE(server_context != nullptr);
    REQUIRE(client_context != nullptr);
    ccf::crypto::OpenSSL::Unique_BIO cert_bio(
      cert.data(), static_cast<int>(cert.size()));
    ccf::crypto::OpenSSL::Unique_X509 x509(cert_bio, true);
    ccf::crypto::OpenSSL::Unique_BIO key_bio(
      key.data(), static_cast<int>(key.size()));
    ccf::crypto::OpenSSL::Unique_PKEY pkey(
      PEM_read_bio_PrivateKey(key_bio, nullptr, nullptr, nullptr),
      EVP_PKEY_free);
    REQUIRE(SSL_CTX_use_certificate(server_context.get(), x509) == 1);
    REQUIRE(SSL_CTX_use_PrivateKey(server_context.get(), pkey) == 1);
    REQUIRE(SSL_CTX_set_num_tickets(server_context.get(), 0) == 1);

    int sockets[2] = {-1, -1};
    REQUIRE(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) == 0);
    REQUIRE(fcntl(sockets[0], F_SETFL, O_NONBLOCK) == 0);
    const int send_buffer = 4096;
    REQUIRE(
      setsockopt(
        sockets[0], SOL_SOCKET, SO_SNDBUF, &send_buffer, sizeof(send_buffer)) ==
      0);
    timeval receive_timeout{.tv_sec = 5, .tv_usec = 0};
    REQUIRE(
      setsockopt(
        sockets[1],
        SOL_SOCKET,
        SO_RCVTIMEO,
        &receive_timeout,
        sizeof(receive_timeout)) == 0);

    std::mutex mutex;
    std::condition_variable cv;
    bool peer_ready = false;
    bool peer_read = false;
    size_t admission_calls = 0;
    size_t received = 0;
    size_t closes = 0;
    bool cancellation_processed = false;
    bool stop_barrier_posted = false;
    std::function<void()> acknowledge_shutdown = [&]() {
      std::lock_guard<std::mutex> guard(mutex);
      cancellation_processed = true;
      cv.notify_all();
    };
    constexpr ::tcp::ConnID connection_id = 1;
    constexpr ::tcp::ConnID barrier_id = 2;
    NotificationGate gate;
    handshake_gate = &gate;
    UVLoopRunner loop;
    auto client = std::make_shared<OpenSSLConnectionEngine>(
      OpenSSLConnectionEngine::Config{
        .on_handshake =
          [&](::tcp::ConnID, SSL*, bool) {
            std::lock_guard<std::mutex> guard(mutex);
            ++admission_calls;
            return true;
          },
        .on_stop =
          [&]() {
            if (!shutdown || stop_barrier_posted)
            {
              return;
            }
            stop_barrier_posted = true;
            auto timer = std::make_unique<uv_timer_t>();
            const int rc = uv_timer_init(uv_default_loop(), timer.get());
            CHECK(rc == 0);
            if (rc != 0)
            {
              return;
            }
            timer->data = &acknowledge_shutdown;
            // on_stop precedes connection cancellation. A subsequent loop
            // callback acknowledges the whole teardown pass, not just on_stop.
            const int start_rc = uv_timer_start(
              timer.get(),
              [](uv_timer_t* handle) {
                (*static_cast<std::function<void()>*>(handle->data))();
                ccf::tls::details::close_handle(handle);
              },
              0,
              0);
            CHECK(start_rc == 0);
            auto* handle = timer.release();
            if (start_rc != 0)
            {
              ccf::tls::details::close_handle(handle);
            }
          },
        .on_unconnected =
          [&](::tcp::ConnID id, std::vector<uint8_t>, bool) {
            std::lock_guard<std::mutex> guard(mutex);
            CHECK(id == barrier_id);
            cancellation_processed = true;
            cv.notify_all();
          }},
      [&](
        ::tcp::ConnID,
        std::vector<uint8_t> data,
        const std::vector<uint8_t>&,
        bool) {
        std::lock_guard<std::mutex> guard(mutex);
        received += data.size();
      },
      [&](::tcp::ConnID id) {
        std::lock_guard<std::mutex> guard(mutex);
        CHECK(id == connection_id);
        ++closes;
        cv.notify_all();
      });
    auto peer = std::async(std::launch::async, [&]() {
      std::unique_ptr<SSL, decltype(&SSL_free)> ssl(
        SSL_new(server_context.get()), SSL_free);
      CHECK(ssl != nullptr);
      CHECK(SSL_set_fd(ssl.get(), sockets[1]) == 1);
      CHECK(SSL_accept(ssl.get()) == 1);
      CHECK(SSL_write(ssl.get(), "hello", 5) == 5);
      {
        std::unique_lock<std::mutex> guard(mutex);
        peer_ready = true;
        cv.notify_all();
        cv.wait(guard, [&]() { return peer_read; });
      }
      size_t bytes = 0;
      std::array<uint8_t, 16384> buffer{};
      for (;;)
      {
        const auto n = SSL_read(ssl.get(), buffer.data(), buffer.size());
        if (n <= 0)
        {
          break;
        }
        bytes += static_cast<size_t>(n);
      }
      ccf::tls::details::close_socket(sockets[1]);
      return bytes;
    });
    std::future<void> stopping;

    struct Cleanup
    {
      NotificationGate& gate;
      std::mutex& mutex;
      std::condition_variable& cv;
      bool& peer_read;
      std::shared_ptr<OpenSSLConnectionEngine> client;
      UVLoopRunner& loop;

      ~Cleanup()
      {
        gate.release();
        {
          std::lock_guard<std::mutex> guard(mutex);
          peer_read = true;
          cv.notify_all();
        }
        client->stop(
          loop.thread.joinable() ?
            OpenSSLConnectionEngine::LoopState::Running :
            OpenSSLConnectionEngine::LoopState::NotRunning);
        handshake_gate = nullptr;
      }
    } cleanup{gate, mutex, cv, peer_read, client, loop};

    client->start();
    REQUIRE(client->adopt(
      {.id = connection_id,
       .fd = sockets[0],
       .tls_context = client_context,
       .outgoing = true,
       .handshake_timeout = 5s,
       .pending_commands = {
         {connection_id,
          std::vector<uint8_t>(size_t{4} * 1024 * 1024, 42),
          false}}}));
    loop.start();
    REQUIRE(gate.wait_for_calls(1));
    {
      std::unique_lock<std::mutex> guard(mutex);
      REQUIRE(cv.wait_for(guard, 5s, [&]() { return peer_ready; }));
    }
    if (shutdown)
    {
      stopping = std::async(std::launch::async, [&]() {
        client->stop(OpenSSLConnectionEngine::LoopState::Running);
      });
    }
    else
    {
      client->close_connection(connection_id);
      // FIFO processing acknowledges cancellation while the worker is gated.
      client->close_connection(barrier_id);
    }
    {
      std::unique_lock<std::mutex> guard(mutex);
      REQUIRE(cv.wait_for(guard, 5s, [&]() { return cancellation_processed; }));
    }
    gate.release();
    {
      std::unique_lock<std::mutex> guard(mutex);
      CHECK(cv.wait_for(guard, 1s, [&]() { return closes == 1; }));
      CHECK(admission_calls == 0);
      CHECK(received == 0);
      peer_read = true;
      cv.notify_all();
    }
    CHECK(peer.get() == 0);
    if (stopping.valid())
    {
      stopping.get();
    }
    client->stop(OpenSSLConnectionEngine::LoopState::Running);
    CHECK(closes == 1);
  }

}

TEST_CASE("Outbound stalled TLS establishment times out, cancels and stops")
{
  EnginePair pair;
  std::atomic<size_t> hello_bytes = 0;
  auto blackhole = std::make_shared<OpenSSLServer>(
    OpenSSLServer::Config{.host = "127.0.0.1", .plaintext = true},
    [&](
      ::tcp::ConnID,
      std::vector<uint8_t> data,
      const std::vector<uint8_t>&,
      bool) {
      hello_bytes += data.size();
      pair.cv.notify_all();
    });
  blackhole->start();
  auto config = pair.config();
  config.port = blackhole->port();
  config.timeout = std::chrono::milliseconds(200);
  const auto id = pair.client->connect(config);
  pair.client->send(id, std::vector<uint8_t>(1024 * 1024, 1));
  pair.loop.start();
  const bool sent_hello = pair.wait([&]() { return hello_bytes > 0; });
  CHECK(sent_hello);
  SUBCASE("Timeout")
  {
    CHECK(pair.wait([&]() { return pair.client_closed == 1; }));
  }
  SUBCASE("Cancel")
  {
    pair.client->close_connection(id);
    CHECK(pair.wait([&]() { return pair.client_closed == 1; }));
  }
  SUBCASE("Shutdown")
  {
    pair.client->stop(OpenSSLServer::LoopState::Running);
  }
  blackhole->stop(OpenSSLServer::LoopState::Running);
  CHECK(pair.client_closed == 1);
  CHECK(pair.client_handshakes == 0);
}

TEST_CASE(
  "Outbound context verification failures are not bypassed by admission")
{
  EnginePair pair;
  auto config = pair.config();
  config.tls_context = {SSL_CTX_new(TLS_client_method()), SSL_CTX_free};
  REQUIRE(config.tls_context != nullptr);
  SSL_CTX_set_verify(config.tls_context.get(), SSL_VERIFY_PEER, nullptr);
  pair.client->connect(config);
  pair.loop.start();
  REQUIRE(pair.wait([&]() { return pair.client_closed == 1; }));
  CHECK(pair.client_handshakes == 0);
}

TEST_CASE("Outbound cancellation cannot resurrect a resolving connection")
{
  EnginePair pair;
  const auto id = pair.client->connect(pair.config());
  pair.client->send(id, std::vector<uint8_t>{1});
  pair.client->close_connection(id);
  pair.loop.start();
  REQUIRE(pair.wait([&]() { return pair.client_closed == 1; }));
  pair.client->stop(OpenSSLServer::LoopState::Running);
  std::lock_guard<std::mutex> guard(pair.mutex);
  CHECK(pair.client_handshakes == 0);
  CHECK(pair.server_handshakes == 0);
}

TEST_CASE("Outbound resolution, source binding and TCP failures close once")
{
  EnginePair pair;
  auto unlistening = std::make_shared<OpenSSLServer>(
    OpenSSLServer::Config{.host = "127.0.0.1"},
    [](::tcp::ConnID, std::vector<uint8_t>, const std::vector<uint8_t>&, bool) {
    });
  auto config = pair.config();
  SUBCASE("Bad target")
  {
    config.host = "invalid host name";
  }
  SUBCASE("Bad source")
  {
    config.source_host = "invalid source name";
  }
  SUBCASE("Unbindable source")
  {
    config.source_host = "192.0.2.1";
  }
  SUBCASE("Connection refused")
  {
    config.host = "127.0.0.1";
    config.port = unlistening->port();
  }
  const auto id = pair.client->connect(config);
  pair.loop.start();
  REQUIRE(pair.wait([&]() { return pair.client_closed == 1; }));
  pair.client->close_connection(id);
  pair.client->stop(OpenSSLServer::LoopState::Running);
  CHECK(pair.client_closed == 1);
  CHECK(pair.client_handshakes == 0);
}

TEST_CASE("Outbound shutdown releases queued attempts without running the loop")
{
  {
    EnginePair pair;
    pair.client->connect(pair.config());
    pair.client->stop();
    CHECK(pair.client_closed == 1);
  }
  while (uv_loop_alive(uv_default_loop()) != 0)
  {
    uv_run(uv_default_loop(), UV_RUN_NOWAIT);
  }
}

TEST_CASE("Outbound late DNS completion is safe after timeout or destruction")
{
  ResolutionGate gate;
  resolution_gate = &gate;
  {
    EnginePair pair;
    auto config = pair.config();
    config.timeout = std::chrono::milliseconds(100);
    pair.client->connect(config);
    pair.loop.start();
    bool completed = false;
    {
      std::unique_lock<std::mutex> guard(gate.mutex);
      completed = gate.cv.wait_for(
        guard, std::chrono::seconds(5), [&]() { return gate.completed; });
    }
    CHECK(completed);
    SUBCASE("Resolution timeout")
    {
      CHECK(pair.wait([&]() { return pair.client_closed == 1; }));
    }
    SUBCASE("Shutdown during resolution") {}
    pair.client->stop(OpenSSLServer::LoopState::Running);
    CHECK(pair.client_closed == 1);
    CHECK(pair.client_handshakes == 0);
  }
  // The real resolver has finished, but the engine has not seen its callback.
  // Deliver it only after the engine is destroyed, as a stopped loop may do.
  resolution_gate = nullptr;
  REQUIRE(gate.completed);
  gate.callback(gate.request, gate.status, gate.result);
}

TEST_CASE("Outbound candidate timeout falls back without losing queued data")
{
  EnginePair pair;
  auto config = pair.config();
  // localhost resolves to IPv6 then IPv4. Do not bind to a v4 source so the
  // first candidate reaches polling, which is deliberately left unarmed.
  config.source_host.clear();
  suppressed_connect_polls = 0;
  suppress_connect_poll = true;
  const auto id = pair.client->connect(config);
  pair.client->send(id, std::vector<uint8_t>{42});
  pair.loop.start();
  const bool received = pair.wait([&]() { return pair.received.size() == 3; });
  suppress_connect_poll = false;
  REQUIRE(received);
  CHECK(suppressed_connect_polls == 1);
}

TEST_CASE("Outbound cancellation and shutdown during connect prevent retry")
{
  EnginePair pair;
  auto config = pair.config();
  config.source_host.clear();
  config.timeout = std::chrono::milliseconds(100);
  suppressed_connect_polls = 0;
  suppress_connect_poll = true;
  const auto id = pair.client->connect(config);
  pair.loop.start();
  const auto deadline =
    std::chrono::steady_clock::now() + std::chrono::seconds(5);
  while (suppressed_connect_polls == 0 &&
         std::chrono::steady_clock::now() < deadline)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  suppress_connect_poll = false;
  REQUIRE(suppressed_connect_polls == 1);
  SUBCASE("Cancel")
  {
    pair.client->close_connection(id);
    REQUIRE(pair.wait([&]() { return pair.client_closed == 1; }));
  }
  SUBCASE("Shutdown")
  {
    pair.client->stop(OpenSSLServer::LoopState::Running);
    CHECK(pair.client_closed == 1);
  }
  std::unique_lock<std::mutex> lock(pair.mutex);
  CHECK_FALSE(pair.cv.wait_for(lock, config.timeout * 3, [&]() {
    return pair.client_closed != 1 || pair.client_handshakes != 0;
  }));
}

TEST_CASE(
  "Outbound optional established TCP timeout applies to accepted sockets")
{
  EnginePair pair(std::chrono::milliseconds(2345));
  pair.client->connect(pair.config());
  pair.loop.start();
  REQUIRE(pair.wait([&]() { return pair.received.size() == 2; }));
  std::lock_guard<std::mutex> guard(pair.mutex);
  CHECK(pair.server_user_timeout == 2345);
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

TEST_CASE("Concurrent notifications retain the wake handle until they return")
{
  auto server = std::make_shared<OpenSSLServer>(
    OpenSSLServer::Config{.host = "127.0.0.1", .plaintext = true},
    [](::tcp::ConnID, std::vector<uint8_t>, const std::vector<uint8_t>&, bool) {
    });
  server->start();
  NotificationGate gate;
  notification_gate.store(&gate);

  // No connection is needed: send() queues its command before waking the loop.
  std::thread first([&]() { server->send(0, {}); });
  const bool first_entered = gate.wait_for_calls(1);
  std::thread second([&]() { server->send(0, {}); });
  const bool second_entered = gate.wait_for_calls(2);

  std::promise<void> stopping;
  std::promise<void> stopped;
  auto stopping_future = stopping.get_future();
  auto stopped_future = stopped.get_future();
  std::thread stopper([&]() {
    stopping.set_value();
    server->stop();
    stopped.set_value();
  });
  stopping_future.wait();
  const bool waited_for_notification =
    stopped_future.wait_for(std::chrono::milliseconds(100)) ==
    std::future_status::timeout;

  // Release before asserting so a failed regression cannot strand a thread.
  gate.release();
  first.join();
  second.join();
  stopper.join();
  const auto calls_before = gate.call_count();
  server->send(0, {});
  const auto calls_after = gate.call_count();
  notification_gate.store(nullptr);
  uv_run(uv_default_loop(), UV_RUN_DEFAULT);

  CHECK(first_entered);
  CHECK(second_entered);
  CHECK(waited_for_notification);
  CHECK(calls_before == 2);
  CHECK(calls_after == calls_before);
  CHECK(uv_loop_alive(uv_default_loop()) == 0);
}

TEST_CASE("Published shutdown skips notification lifecycle locking")
{
  auto server = std::make_shared<OpenSSLServer>(
    OpenSSLServer::Config{.host = "127.0.0.1", .plaintext = true},
    [](::tcp::ConnID, std::vector<uint8_t>, const std::vector<uint8_t>&, bool) {
    });
  UVLoopRunner loop;
  server->start();
  loop.start();
  NotificationGate gate;
  notification_gate.store(&gate);

  std::thread stopper(
    [&]() { server->stop(OpenSSLServer::LoopState::Running); });
  // stop() has published stopping but holds the exclusive lifecycle lock
  // until its notification returns.
  const bool stop_notifying = gate.wait_for_calls(1);
  auto producer = std::async(std::launch::async, [&]() {
    server->send(0, {});
    server->close_connection(0);
  });
  const bool skipped_lock =
    producer.wait_for(std::chrono::seconds(1)) == std::future_status::ready;
  const auto calls_while_stopping = gate.call_count();

  // Release before waiting or asserting, including when the producer blocks.
  gate.release();
  producer.get();
  stopper.join();
  loop.thread.join();
  notification_gate.store(nullptr);

  CHECK(stop_notifying);
  CHECK(skipped_lock);
  CHECK(calls_while_stopping == 1);
  CHECK(uv_loop_alive(uv_default_loop()) == 0);
}

TEST_CASE("Shutdown completes under concurrent notification load")
{
  auto server = std::make_shared<OpenSSLServer>(
    OpenSSLServer::Config{.host = "127.0.0.1", .plaintext = true},
    [](::tcp::ConnID, std::vector<uint8_t>, const std::vector<uint8_t>&, bool) {
    });
  UVLoopRunner loop;
  server->start();
  loop.start();
  std::atomic<bool> finish = false;
  std::atomic<size_t> notifications = 0;
  std::vector<std::thread> producers;
  for (size_t i = 0; i < 4; ++i)
  {
    producers.emplace_back([&]() {
      while (!finish.load())
      {
        server->send(0, {});
        ++notifications;
      }
    });
  }
  const auto deadline =
    std::chrono::steady_clock::now() + std::chrono::seconds(5);
  while (notifications.load() < 1000 &&
         std::chrono::steady_clock::now() < deadline)
  {
    std::this_thread::yield();
  }
  auto stopped = std::async(std::launch::async, [&]() {
    server->stop(OpenSSLServer::LoopState::Running);
  });
  const bool stopped_under_load =
    stopped.wait_for(std::chrono::seconds(5)) == std::future_status::ready;
  finish.store(true);
  for (auto& producer : producers)
  {
    producer.join();
  }
  stopped.get();
  loop.thread.join();
  CHECK(notifications.load() >= 1000);
  CHECK(stopped_under_load);
  CHECK(uv_loop_alive(uv_default_loop()) == 0);
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

// An interface binds before its certificate is necessarily known - a joining
// node only receives the service certificate once its join has been accepted.
// Until then it must refuse connections outright rather than accept them and
// drop them, so that a client fails to connect (and retries) rather than
// completing a TCP handshake and then failing mid-TLS.
TEST_CASE("A TLS interface without a certificate refuses connections")
{
  auto [cert, key] = make_server_cert();

  std::mutex m;
  std::condition_variable cv;
  size_t data_callbacks = 0;

  // No cert_pem/key_pem: the certificate arrives later, via set_server_cert.
  std::shared_ptr<OpenSSLServer> server;
  server = std::make_shared<OpenSSLServer>(
    OpenSSLServer::Config{.host = "127.0.0.1"},
    [&](
      ::tcp::ConnID id,
      std::vector<uint8_t> d,
      const std::vector<uint8_t>&,
      bool) {
      server->send(id, std::move(d));
      std::lock_guard<std::mutex> guard(m);
      ++data_callbacks;
      cv.notify_all();
    });
  UVLoopRunner loop;
  server->start();

  // The port is fixed by the bind, so it is reportable even before the
  // interface is serving.
  const auto port = server->port();
  REQUIRE(port != 0);
  loop.start();

  const auto try_connect = [port]() {
    const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    REQUIRE(fd >= 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    REQUIRE(inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) == 1);
    const int rc =
      ::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    const int err = errno;
    ::close(fd);
    return rc == 0 ? 0 : err;
  };

  // Bound but not listening, so the kernel answers the SYN with a reset.
  REQUIRE(try_connect() == ECONNREFUSED);

  // Supplying the certificate is what puts the interface into service.
  server->set_server_cert(cert, key);

  const auto deadline =
    std::chrono::steady_clock::now() + std::chrono::seconds(10);
  while (try_connect() != 0 && std::chrono::steady_clock::now() < deadline)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  REQUIRE(try_connect() == 0);

  // And the interface now serves a complete TLS session.
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

    const std::string request = "hello";
    REQUIRE(
      SSL_write(ssl, request.data(), static_cast<int>(request.size())) ==
      static_cast<int>(request.size()));

    std::vector<uint8_t> echoed(request.size());
    REQUIRE(
      SSL_read(ssl, echoed.data(), static_cast<int>(echoed.size())) ==
      static_cast<int>(request.size()));
    REQUIRE(std::string(echoed.begin(), echoed.end()) == request);

    SSL_free(ssl);
    SSL_CTX_free(cctx);
    ::close(fd);
  }

  {
    std::unique_lock<std::mutex> lock(m);
    REQUIRE(cv.wait_for(
      lock, std::chrono::seconds(10), [&]() { return data_callbacks > 0; }));
  }

  server->stop(OpenSSLServer::LoopState::Running);
  server.reset();
  loop.thread.join();
  REQUIRE(uv_loop_alive(uv_default_loop()) == 0);
}

// Idle connections are closed so that a client which connects, handshakes and
// then goes quiet cannot hold a file descriptor and TLS state indefinitely.
TEST_CASE("Idle connections are closed after the configured timeout")
{
  auto [cert, key] = make_server_cert();

  std::mutex m;
  std::condition_variable cv;
  std::set<::tcp::ConnID> opened;
  std::set<::tcp::ConnID> closed;

  // Shorter than the sweep interval, so the first sweep after the connection
  // goes quiet closes it.
  std::shared_ptr<OpenSSLServer> server;
  server = std::make_shared<OpenSSLServer>(
    OpenSSLServer::Config{
      .host = "127.0.0.1",
      .cert_pem = cert,
      .key_pem = key,
      .idle_timeout = std::chrono::milliseconds(100)},
    [&](
      ::tcp::ConnID id,
      std::vector<uint8_t> d,
      const std::vector<uint8_t>&,
      bool) {
      server->send(id, std::move(d));
      std::lock_guard<std::mutex> guard(m);
      opened.insert(id);
      cv.notify_all();
    },
    [&](::tcp::ConnID id) {
      std::lock_guard<std::mutex> guard(m);
      closed.insert(id);
      cv.notify_all();
    });
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
  uint8_t echoed = 0;
  REQUIRE(SSL_read(ssl, &echoed, 1) == 1);

  // The connection is established and served. Now go quiet, and the server
  // should close it of its own accord.
  {
    std::unique_lock<std::mutex> lock(m);
    REQUIRE(cv.wait_for(
      lock, std::chrono::seconds(10), [&]() { return !closed.empty(); }));
    REQUIRE(closed == opened);
  }

  // The client observes the close rather than the connection simply stalling.
  uint8_t after = 0;
  REQUIRE(SSL_read(ssl, &after, 1) <= 0);

  SSL_free(ssl);
  SSL_CTX_free(cctx);
  ::close(fd);

  server->stop(OpenSSLServer::LoopState::Running);
  server.reset();
  loop.thread.join();
  REQUIRE(uv_loop_alive(uv_default_loop()) == 0);
}

TEST_CASE("Idle expiry closes connections with blocked output")
{
  bool plaintext = false;
  SUBCASE("TLS") {}
  SUBCASE("Plaintext")
  {
    plaintext = true;
  }

  auto [cert, key] = make_server_cert();
  std::mutex mutex;
  std::condition_variable closed_cv;
  size_t close_count = 0;
  std::shared_ptr<OpenSSLServer> server;
  server = std::make_shared<OpenSSLServer>(
    OpenSSLServer::Config{
      .host = "127.0.0.1",
      .cert_pem = cert,
      .key_pem = key,
      .plaintext = plaintext,
      .idle_timeout = std::chrono::milliseconds(100)},
    [&](
      ::tcp::ConnID id,
      std::vector<uint8_t>,
      const std::vector<uint8_t>&,
      bool) { server->send(id, std::vector<uint8_t>(32 * 1024 * 1024, 'z')); },
    [&](::tcp::ConnID) {
      std::lock_guard<std::mutex> guard(mutex);
      ++close_count;
      closed_cv.notify_all();
    });
  UVLoopRunner loop;
  server->start();
  loop.start();

  struct StopOnExit
  {
    std::shared_ptr<OpenSSLServer> server;

    ~StopOnExit()
    {
      server->stop(OpenSSLServer::LoopState::Running);
    }
  } stop_on_exit{server};

  const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  REQUIRE(fd >= 0);

  struct CloseSocketOnExit
  {
    int fd;

    ~CloseSocketOnExit()
    {
      ::close(fd);
    }
  } close_socket_on_exit{fd};

  const int receive_buffer_size = 4096;
  REQUIRE(
    setsockopt(
      fd,
      SOL_SOCKET,
      SO_RCVBUF,
      &receive_buffer_size,
      sizeof(receive_buffer_size)) == 0);
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(server->port());
  REQUIRE(inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) == 1);
  REQUIRE(::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);

  ccf::crypto::OpenSSL::Unique_SSL_CTX cctx(TLS_client_method());
  ccf::crypto::OpenSSL::Unique_SSL ssl(cctx);
  if (!plaintext)
  {
    REQUIRE(SSL_set_fd(ssl, fd) == 1);
    REQUIRE(SSL_connect(ssl) == 1);
  }

  const uint8_t request = 'x';
  if (plaintext)
  {
    REQUIRE(::send(fd, &request, 1, MSG_NOSIGNAL) == 1);
  }
  else
  {
    REQUIRE(SSL_write(ssl, &request, 1) == 1);
  }
  uint8_t response = 0;
  REQUIRE(
    (plaintext ? ::recv(fd, &response, 1, 0) : SSL_read(ssl, &response, 1)) ==
    1);
  REQUIRE(response == 'z');

  // Leave the response backpressured and observe server-side eviction before
  // closing the client socket or requesting server shutdown.
  bool expired = false;
  {
    std::unique_lock<std::mutex> lock(mutex);
    expired = closed_cv.wait_for(
      lock, std::chrono::seconds(10), [&]() { return close_count != 0; });
  }

  server->stop(OpenSSLServer::LoopState::Running);
  server.reset();
  loop.thread.join();
  REQUIRE(expired);
  REQUIRE(close_count == 1);
  REQUIRE(uv_loop_alive(uv_default_loop()) == 0);
}

TEST_CASE("TCP connections use the legacy latency and keepalive options")
{
  const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  REQUIRE(fd >= 0);
  REQUIRE_FALSE(ccf::tls::details::configure_tcp_connection(fd).has_value());

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

  const int quickack_off = 0;
  REQUIRE(
    setsockopt(
      fd, IPPROTO_TCP, TCP_QUICKACK, &quickack_off, sizeof(quickack_off)) == 0);
  REQUIRE(get_option(IPPROTO_TCP, TCP_QUICKACK) == 0);
  REQUIRE_FALSE(ccf::tls::details::request_tcp_quickack(fd).has_value());
  REQUIRE(get_option(IPPROTO_TCP, TCP_QUICKACK) == 1);
  REQUIRE((fcntl(fd, F_GETFD) & FD_CLOEXEC) != 0);

  ::close(fd);

  const auto error = ccf::tls::details::configure_tcp_connection(-1);
  REQUIRE(error.has_value());
  REQUIRE(std::string(error->option) == "TCP_NODELAY");
  REQUIRE(error->error == EBADF);

  const auto quickack_error = ccf::tls::details::request_tcp_quickack(-1);
  REQUIRE(quickack_error.has_value());
  REQUIRE(std::string(quickack_error->option) == "TCP_QUICKACK");
  REQUIRE(quickack_error->error == EBADF);
}

TEST_CASE("TLS handshake and small round-trip")
{
  auto [cert, key] = make_server_cert();
  EchoServer s(cert, key);
  REQUIRE(s.port() != 0);

  const std::vector<uint8_t> msg = {'h', 'e', 'l', 'l', 'o'};
  REQUIRE(tls_client_exchange(s.port(), msg, msg.size()) == msg);
}

TEST_CASE("Coalesced pipelined HTTP responses are preserved")
{
  auto [cert, key] = make_server_cert();

  std::shared_ptr<OpenSSLServer> server;
  server = std::make_shared<OpenSSLServer>(
    OpenSSLServer::Config{
      .host = "127.0.0.1", .cert_pem = cert, .key_pem = key},
    [&](
      ::tcp::ConnID id,
      std::vector<uint8_t>,
      const std::vector<uint8_t>&,
      bool) {
      const std::string responses =
        "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\na"
        "HTTP/1.1 201 Created\r\nContent-Length: 1\r\n\r\nb";
      server->send(
        id, std::vector<uint8_t>(responses.begin(), responses.end()));
    });
  UVLoopRunner loop;
  server->start();
  loop.start();

  {
    const std::vector<uint8_t> request = {'x'};
    const auto responses =
      tls_collect_http_responses(server->port(), request, 2);

    REQUIRE(responses.size() == 2);
    REQUIRE(responses[0].status == HTTP_STATUS_OK);
    REQUIRE(responses[0].body == "a");
    REQUIRE(responses[1].status == HTTP_STATUS_CREATED);
    REQUIRE(responses[1].body == "b");
  }

  server->stop(OpenSSLServer::LoopState::Running);
}

TEST_CASE("Coalesced concurrent notifications deliver every queued response")
{
  auto [cert, key] = make_server_cert();
  constexpr size_t producers = 4;
  constexpr size_t responses_per_producer = 64;
  std::shared_ptr<OpenSSLServer> server;
  server = std::make_shared<OpenSSLServer>(
    OpenSSLServer::Config{
      .host = "127.0.0.1", .cert_pem = cert, .key_pem = key},
    [](::tcp::ConnID, std::vector<uint8_t>, const std::vector<uint8_t>&, bool) {
    },
    OpenSSLServer::OnClose{},
    [&](::tcp::ConnID id) -> std::optional<bool> {
      // on_accept runs on the loop. Join the producers here so all their
      // notifications coalesce before the loop can run the async callback.
      std::vector<std::thread> threads;
      for (size_t producer = 0; producer < producers; ++producer)
      {
        threads.emplace_back([&, producer]() {
          for (size_t i = 0; i < responses_per_producer; ++i)
          {
            const auto body =
              std::to_string(producer * responses_per_producer + i);
            const auto response = "HTTP/1.1 200 OK\r\nContent-Length: " +
              std::to_string(body.size()) + "\r\n\r\n" + body;
            server->send(
              id, std::vector<uint8_t>(response.begin(), response.end()));
          }
        });
      }
      for (auto& thread : threads)
      {
        thread.join();
      }
      return false;
    });
  UVLoopRunner loop;
  server->start();
  loop.start();

  struct StopOnExit
  {
    std::shared_ptr<OpenSSLServer> server;

    ~StopOnExit()
    {
      server->stop(OpenSSLServer::LoopState::Running);
    }
  } stop_on_exit{server};

  const auto responses = tls_collect_http_responses(
    server->port(), {}, producers * responses_per_producer);
  server->stop(OpenSSLServer::LoopState::Running);
  loop.thread.join();

  std::set<std::string> bodies;
  for (const auto& response : responses)
  {
    CHECK(response.status == HTTP_STATUS_OK);
    bodies.insert(response.body);
  }
  CHECK(responses.size() == producers * responses_per_producer);
  CHECK(bodies.size() == producers * responses_per_producer);
  for (size_t i = 0; i < producers * responses_per_producer; ++i)
  {
    CHECK(bodies.contains(std::to_string(i)));
  }
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

TEST_CASE("Datagram listeners bind exclusively and can rebind after stopping")
{
  std::string host = "127.0.0.1";
  SUBCASE("IPv4") {}
  SUBCASE("IPv6")
  {
    host = "::1";
  }
  const auto on_datagram =
    [](const uint8_t*, size_t, const sockaddr_storage&, socklen_t) {};
  uv_loop_t loop{};
  REQUIRE(uv_loop_init(&loop) == 0);
  {
    DatagramServer server(host, 0, on_datagram, &loop);
    server.start();
    const auto port = server.port();
    REQUIRE(port != 0);
    CHECK_THROWS_WITH_AS(
      DatagramServer(host, port, on_datagram, &loop),
      ("bind (udp) failed for " + host).c_str(),
      std::runtime_error);
    server.stop();

    DatagramServer rebound(host, port, on_datagram, &loop);
    CHECK(rebound.port() == port);
    rebound.start();
    rebound.stop();
  }
  CHECK(uv_run(&loop, UV_RUN_DEFAULT) == 0);
  CHECK(uv_loop_close(&loop) == 0);
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

TEST_CASE("Server presents configured intermediate certificate chain")
{
  using namespace std::literals;

  const auto root = make_ca();
  const auto valid_from =
    ccf::ds::to_x509_time_string(std::chrono::system_clock::now() - 24h);
  const auto valid_to =
    ccf::crypto::compute_cert_valid_to_string(valid_from, 365);

  const auto intermediate_kp = ccf::crypto::make_ec_key_pair();
  const auto intermediate_cert = ccf::crypto::create_endorsed_cert(
    intermediate_kp->public_key_pem(),
    "CN=intermediate",
    {},
    valid_from,
    valid_to,
    root.kp->private_key_pem(),
    root.cert,
    true);

  const auto leaf_kp = ccf::crypto::make_ec_key_pair();
  const auto leaf_cert = ccf::crypto::create_endorsed_cert(
    leaf_kp,
    "CN=localhost",
    {},
    valid_from,
    /*validity_days*/ 365,
    intermediate_kp->private_key_pem(),
    intermediate_cert);

  EchoServer s(
    leaf_cert.str() + "\n" + intermediate_cert.str(),
    leaf_kp->private_key_pem().str());

  REQUIRE(verifying_client_handshake(s.port(), root.cert));
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

TEST_CASE("Listener binds IPv6 loopback")
{
  auto [cert, key] = make_server_cert();
  EchoServer s(cert, key, "::1");

  const std::vector<uint8_t> msg = {'v', '6'};
  REQUIRE(tls_echo_roundtrip("::1", s.port(), msg) == msg);
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

TEST_CASE("Querying the negotiated group before a TLS handshake throws")
{
  ccf::crypto::OpenSSL::Unique_SSL_CTX ctx(TLS_client_method());
  ccf::crypto::OpenSSL::Unique_SSL ssl(ctx);
  REQUIRE_THROWS_WITH_AS(
    ccf::tls::details::get_negotiated_group(ssl),
    "Cannot query negotiated TLS group before handshake completion",
    std::logic_error);
}

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

TEST_CASE("Server prefers the strongest hybrid post-quantum group")
{
  if (!supports_hybrid_groups())
  {
    return;
  }

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

TEST_CASE("Budget resumption revisits idle connections on every interface")
{
  constexpr size_t interface_count = 2;
  constexpr size_t limit = 1;
  auto admission = std::make_shared<InboundAdmission>(limit);

  std::array<std::atomic<size_t>, interface_count> received{};
  std::array<std::atomic<bool>, interface_count> correct_payload{};
  std::atomic<size_t> accepted{0};
  std::atomic<bool> release_source{false};
  std::array<std::shared_ptr<OpenSSLServer>, interface_count> servers;
  std::array<int, interface_count> clients;
  clients.fill(-1);

  UVLoopRunner loop;
  for (size_t i = 0; i < interface_count; ++i)
  {
    servers[i] = std::make_shared<OpenSSLServer>(
      OpenSSLServer::Config{
        .host = "127.0.0.1", .plaintext = true, .inbound_admission = admission},
      [&, i](
        ::tcp::ConnID,
        std::vector<uint8_t> data,
        const std::vector<uint8_t>&,
        bool) {
        correct_payload[i] =
          data.size() == 1 && data[0] == static_cast<uint8_t>('a' + i);
        received[i] += data.size();
        if (i == 0)
        {
          admission->queued(data.size());
          while (!release_source.load())
          {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
          }
          admission->consumed(data.size());
        }
      },
      OpenSSLServer::OnClose{},
      [&](::tcp::ConnID) -> std::optional<bool> {
        ++accepted;
        return false;
      });
    servers[i]->start();
  }
  loop.start();

  int setup_error = 0;
  for (size_t i = 0; i < interface_count; ++i)
  {
    clients[i] = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (clients[i] < 0)
    {
      setup_error = errno;
      break;
    }
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(servers[i]->port());
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (
      ::connect(
        clients[i], reinterpret_cast<sockaddr*>(&address), sizeof(address)) !=
      0)
    {
      setup_error = errno;
      break;
    }
    const auto payload = static_cast<uint8_t>('a' + i);
    const auto sent =
      ::send(clients[i], &payload, sizeof(payload), MSG_NOSIGNAL);
    if (sent != 1)
    {
      setup_error = sent < 0 ? errno : EIO;
      break;
    }
    if (i == 0)
    {
      const auto saturated_deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(5);
      while (!admission->saturated() &&
             std::chrono::steady_clock::now() < saturated_deadline)
      {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
      }
      if (!admission->saturated())
      {
        setup_error = ETIMEDOUT;
        break;
      }
    }
  }

  const auto accepted_deadline =
    std::chrono::steady_clock::now() + std::chrono::seconds(5);
  while (setup_error == 0 && accepted.load() != interface_count &&
         std::chrono::steady_clock::now() < accepted_deadline)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }

  // No more data is sent on either interface. Let the masked readability pass
  // finish, leaving the second connection idle with data waiting to be read.
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  const std::array<size_t, interface_count> stalled_at = {
    received[0].load(), received[1].load()};

  // The first interface releases the budget from its worker. Only the shared
  // admission wake can revisit the otherwise idle second interface.
  release_source.store(true);
  const auto resumed_deadline =
    std::chrono::steady_clock::now() + std::chrono::seconds(5);
  while (setup_error == 0 && received[1].load() == 0 &&
         std::chrono::steady_clock::now() < resumed_deadline)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  const std::array<size_t, interface_count> resumed_at = {
    received[0].load(), received[1].load()};
  const std::array<bool, interface_count> valid_at_resume = {
    correct_payload[0].load(), correct_payload[1].load()};

  for (const auto fd : clients)
  {
    if (fd >= 0)
    {
      ::close(fd);
    }
  }
  for (auto& server : servers)
  {
    server->stop(OpenSSLServer::LoopState::Running);
  }
  loop.thread.join();

  INFO("Socket setup error: " << setup_error);
  CHECK(setup_error == 0);
  CHECK(accepted.load() == interface_count);
  CHECK(stalled_at[0] == 1);
  CHECK(stalled_at[1] == 0);
  for (size_t i = 0; i < interface_count; ++i)
  {
    CHECK(resumed_at[i] == 1);
    CHECK(valid_at_resume[i]);
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
  // the gate pauses reads, it does not drop or truncate anything. The gate
  // state is not checked immediately after the release: consumed() wakes the
  // loop thread synchronously, and with the client still holding megabytes
  // ready to send, the server can read and re-saturate a 64KiB budget before
  // this thread gets to look. Resumption is proven by the drain below.
  admission->consumed(admission->bytes_pending());

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

int main(int argc, char** argv)
{
  ccf::tasks::set_task_threads(4);

  doctest::Context context;
  context.applyCommandLine(argc, argv);
  const auto result = context.run();

  ccf::tasks::set_task_threads(0);
  OPENSSL_cleanup();
  return result;
}
