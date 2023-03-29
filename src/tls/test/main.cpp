// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ccf/crypto/key_pair.h"
#include "ccf/crypto/verifier.h"
#include "ccf/ds/logger.h"
#include "crypto/certs.h"
#include "tls/client.h"
#include "tls/msg_types.h"
#include "tls/server.h"
#include "tls/tls.h"

#include <chrono>
#include <exception>
#include <openssl/err.h>
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <iostream>
#include <memory>
#include <string>
#include <sys/socket.h>
#include <thread>

using namespace std;
using namespace crypto;
using namespace tls;

/// Server uses one pipe while client uses the other.
/// Writes always to one side, reads always from the other.
/// Use the send/recv template wrappers below as callbacks.
class TestPipe
{
  int pfd[2];

public:
  static const int SERVER = 0;
  static const int CLIENT = 1;

  TestPipe()
  {
    if (socketpair(PF_LOCAL, SOCK_STREAM, 0, pfd) == -1)
    {
      throw runtime_error(
        "Failed to create socketpair: " + string(strerror(errno)));
    }
  }
  ~TestPipe()
  {
    close(pfd[0]);
    close(pfd[1]);
  }

  size_t send(int id, const uint8_t* buf, size_t len)
  {
    int rc = write(pfd[id], buf, len);
    if (rc == -1)
      LOG_FAIL_FMT("Error while reading: {}", std::strerror(errno));
    return rc;
  }

  size_t recv(int id, uint8_t* buf, size_t len)
  {
    int rc = read(pfd[id], buf, len);
    if (rc == -1)
      LOG_FAIL_FMT("Error while reading: {}", std::strerror(errno));
    return rc;
  }
};

/// Callback wrapper around TestPipe->send().
template <int end>
int send(void* ctx, const uint8_t* buf, size_t len)
{
  auto pipe = reinterpret_cast<TestPipe*>(ctx);
  int rc = pipe->send(end, buf, len);
  REQUIRE(rc == len);
  return rc;
}

/// Callback wrapper around TestPipe->recv().
template <int end>
int recv(void* ctx, uint8_t* buf, size_t len)
{
  auto pipe = reinterpret_cast<TestPipe*>(ctx);
  int rc = pipe->recv(end, buf, len);
  REQUIRE(rc == len);
  return rc;
}

// OpenSSL callbacks that call onto the pipe's ones
template <int end>
long send(
  BIO* b,
  int oper,
  const char* argp,
  size_t len,
  int argi,
  long argl,
  int ret,
  size_t* processed)
{
  // Unused arguments
  (void)argi;
  (void)argl;
  (void)processed;

  if (ret && oper == (BIO_CB_WRITE | BIO_CB_RETURN))
  {
    // Flush the BIO so the "pipe doesn't clog", but we don't use the
    // data here, because 'argp' already has it.
    BIO_flush(b);
    size_t pending = BIO_pending(b);
    if (pending)
      BIO_reset(b);

    // Pipe object
    auto pipe = reinterpret_cast<TestPipe*>(BIO_get_callback_arg(b));
    size_t put = send<end>(pipe, (const uint8_t*)argp, len);
    REQUIRE(put == len);
  }

  // Unless we detected an error, the return value is always the same as the
  // original operation.
  return ret;
}

template <int end>
long recv(
  BIO* b,
  int oper,
  const char* argp,
  size_t len,
  int argi,
  long argl,
  int ret,
  size_t* processed)
{
  // Unused arguments
  (void)argi;
  (void)argl;

  if (ret && oper == (BIO_CB_READ | BIO_CB_RETURN))
  {
    // Pipe object
    auto pipe = reinterpret_cast<TestPipe*>(BIO_get_callback_arg(b));
    size_t got = recv<end>(pipe, (uint8_t*)argp, len);

    // Got nothing, return "WANTS READ"
    if (got <= 0)
      return ret;

    // Write to the actual BIO so SSL can use it
    BIO_write_ex(b, argp, got, processed);

    // If original return was -1 because it didn't find anything to read, return
    // 1 to say we actually read something
    if (got > 0 && ret < 0)
      return 1;
  }

  // Unless we detected an error, the return value is always the same as the
  // original operation.
  return ret;
}

/// Performs a TLS handshake, looping until there's nothing more to read/write.
/// Returns 0 on success, throws a runtime error with SSL error str on failure.
int handshake(Context* ctx, std::atomic<bool>& keep_going)
{
  while (keep_going)
  {
    int rc = ctx->handshake();

    switch (rc)
    {
      case 0:
        return 0;

      case TLS_ERR_WANT_READ:
      case TLS_ERR_WANT_WRITE:
        // Continue calling handshake until finished
        LOG_DEBUG_FMT("Handshake wants data");
        break;

      case TLS_ERR_NEED_CERT:
      {
        LOG_FAIL_FMT("Handshake error: {}", tls::error_string(rc));
        return 1;
      }

      case TLS_ERR_CONN_CLOSE_NOTIFY:
      {
        LOG_FAIL_FMT("Handshake error: {}", tls::error_string(rc));
        return 1;
      }

      case TLS_ERR_X509_VERIFY:
      {
        auto err = ctx->get_verify_error();
        LOG_FAIL_FMT("Handshake error: {} [{}]", err, tls::error_string(rc));
        return 1;
      }

      default:
      {
        LOG_FAIL_FMT("Handshake error: {}", tls::error_string(rc));
        return 1;
      }
    }
  }

  return 0;
}

struct NetworkCA
{
  shared_ptr<crypto::KeyPair> kp;
  crypto::Pem cert;
};

static crypto::Pem generate_self_signed_cert(
  const crypto::KeyPairPtr& kp, const std::string& name)
{
  using namespace std::literals;
  constexpr size_t certificate_validity_period_days = 365;
  auto valid_from =
    ds::to_x509_time_string(std::chrono::system_clock::now() - 24h);

  return crypto::create_self_signed_cert(
    kp, name, {}, valid_from, certificate_validity_period_days);
}

static crypto::Pem generate_endorsed_cert(
  const crypto::KeyPairPtr& kp,
  const std::string& name,
  const crypto::KeyPairPtr& issuer_kp,
  const crypto::Pem& issuer_cert)
{
  constexpr size_t certificate_validity_period_days = 365;

  using namespace std::literals;
  auto valid_from =
    ds::to_x509_time_string(std::chrono::system_clock::now() - 24h);

  return crypto::create_endorsed_cert(
    kp,
    name,
    {},
    valid_from,
    certificate_validity_period_days,
    issuer_kp->private_key_pem(),
    issuer_cert);
}

/// Get self-signed CA certificate.
NetworkCA get_ca()
{
  // Create a CA with a self-signed certificate
  auto kp = crypto::make_key_pair();
  auto crt = generate_self_signed_cert(kp, "CN=issuer");
  LOG_DEBUG_FMT("New self-signed CA certificate:\n{}", crt.str());
  return {kp, crt};
}

/// Creates a tls::Cert with a new CA using a new self-signed Pem certificate.
unique_ptr<tls::Cert> get_dummy_cert(
  NetworkCA& net_ca, string name, bool auth_required = true)
{
  // Create a CA with a self-signed certificate
  auto ca = make_unique<tls::CA>(net_ca.cert.str());

  // Create a signing request and sign with the CA
  auto kp = crypto::make_key_pair();
  auto crt = generate_endorsed_cert(kp, "CN=" + name, net_ca.kp, net_ca.cert);
  LOG_DEBUG_FMT("New CA-signed certificate:\n{}", crt.str());

  // Verify node certificate with the CA's certificate
  auto v = crypto::make_verifier(crt);
  REQUIRE(v->verify_certificate({&net_ca.cert}));

  // Create a tls::Cert with the CA, the signed certificate and the private key
  auto pk = kp->private_key_pem();
  return make_unique<Cert>(std::move(ca), crt, pk, std::nullopt, auth_required);
}

/// Helper to write past the maximum buffer (16k)
int write_helper(Context& handler, const uint8_t* buf, size_t len)
{
  LOG_DEBUG_FMT("WRITE {} bytes", len);
  int rc = handler.write(buf, len);
  if (rc <= 0 || (size_t)rc == len)
    return rc;
  return rc + write_helper(handler, buf + rc, len - rc);
}

/// Helper to read past the maximum buffer (16k)
int read_helper(Context& handler, uint8_t* buf, size_t len)
{
  LOG_DEBUG_FMT("READ {} bytes", len);
  int rc = handler.read(buf, len);
  if (rc <= 0 || (size_t)rc == len)
    return rc;
  return rc + read_helper(handler, buf + rc, len - rc);
}

/// Helper to truncate long messages to make logs more readable
std::string truncate_message(const uint8_t* msg, size_t len)
{
  const size_t MAX_LEN = 32;
  if (len < MAX_LEN)
    return std::string((const char*)msg);
  std::string str((const char*)msg, MAX_LEN);
  str += "... + " + std::to_string(len - MAX_LEN);
  return str;
}

/// Test runner, with various options for different kinds of tests.
void run_test_case(
  const uint8_t* message,
  size_t message_length,
  const uint8_t* response,
  size_t response_length,
  unique_ptr<tls::Cert> server_cert,
  unique_ptr<tls::Cert> client_cert)
{
  uint8_t buf[max(message_length, response_length) + 1];

  // Create a pair of client/server
  tls::Server server(std::move(server_cert));
  tls::Client client(std::move(client_cert));

  // Connect BIOs together
  TestPipe pipe;
  server.set_bio(&pipe, send<TestPipe::SERVER>, recv<TestPipe::SERVER>);
  client.set_bio(&pipe, send<TestPipe::CLIENT>, recv<TestPipe::CLIENT>);

  std::atomic<bool> keep_going = true;
  std::optional<std::runtime_error> client_exception, server_exception;

  // Create a thread for the client handshake
  thread client_thread([&client, &keep_going, &client_exception]() {
    LOG_INFO_FMT("Client handshake");
    try
    {
      if (handshake(&client, keep_going))
        throw runtime_error("Client handshake error");
    }
    catch (std::runtime_error& ex)
    {
      keep_going = false;
      client_exception = ex;
    }
  });

  // Create a thread for the server handshake
  thread server_thread([&server, &keep_going, &server_exception]() {
    LOG_INFO_FMT("Server handshake");
    try
    {
      if (handshake(&server, keep_going))
        throw runtime_error("Server handshake error");
    }
    catch (std::runtime_error& ex)
    {
      keep_going = false;
      server_exception = ex;
    }
  });

  // Join threads
  client_thread.join();
  server_thread.join();
  LOG_INFO_FMT("Handshake completed");

  if (client_exception)
  {
    throw *client_exception;
  }
  if (server_exception)
  {
    throw *server_exception;
  }

  // The rest of the communication is deterministic and easy to simulate
  // so we take them out of the thread, to guarantee there will be bytes
  // to read at the right time.
  if (message_length == 0)
  {
    LOG_INFO_FMT("Empty message. Ignoring communication test");
    LOG_INFO_FMT("Closing connection");
    client.close();
    server.close();
    return;
  }

  // Send the first message
  LOG_INFO_FMT(
    "Client sending message [{}]", truncate_message(message, message_length));
  int written = write_helper(client, message, message_length);
  REQUIRE(written == message_length);

  // Receive the first message
  int read = read_helper(server, buf, message_length);
  REQUIRE(read == message_length);
  buf[message_length] = '\0';
  LOG_INFO_FMT(
    "Server message received [{}]", truncate_message(buf, message_length));
  REQUIRE(strncmp((const char*)buf, (const char*)message, message_length) == 0);

  // Send the response
  LOG_INFO_FMT(
    "Server sending message [{}]", truncate_message(response, message_length));
  written = write_helper(server, response, response_length);
  REQUIRE(written == response_length);

  // Receive the response
  read = read_helper(client, buf, response_length);
  REQUIRE(read == response_length);
  buf[response_length] = '\0';
  LOG_INFO_FMT(
    "Client message received [{}]", truncate_message(buf, message_length));
  REQUIRE(
    strncmp((const char*)buf, (const char*)response, response_length) == 0);

  LOG_INFO_FMT("Closing connection");
  client.close();
  server.close();
}

TEST_CASE("unverified handshake")
{
  // Create a CA
  auto ca = get_ca();

  // Create bogus certificate
  auto server_cert = get_dummy_cert(ca, "server", false);
  auto client_cert = get_dummy_cert(ca, "client", false);

  LOG_INFO_FMT("TEST: unverified handshake");

  // Just testing handshake, does not verify certificates, no communication.
  run_test_case(
    (const uint8_t*)"",
    0,
    (const uint8_t*)"",
    0,
    std::move(server_cert),
    std::move(client_cert));
}

TEST_CASE("unverified communication")
{
  const uint8_t message[] = "Hello World!";
  size_t message_length = strlen((const char*)message);
  const uint8_t response[] = "Hi back!";
  size_t response_length = strlen((const char*)response);

  // Create a CA
  auto ca = get_ca();

  // Create bogus certificate
  auto server_cert = get_dummy_cert(ca, "server", false);
  auto client_cert = get_dummy_cert(ca, "client", false);

  LOG_INFO_FMT("TEST: unverified communication");

  // Just testing communication channel, does not verify certificates.
  run_test_case(
    message,
    message_length,
    response,
    response_length,
    std::move(server_cert),
    std::move(client_cert));
}

TEST_CASE("verified handshake")
{
  // Create a CA
  auto ca = get_ca();

  // Create bogus certificate
  auto server_cert = get_dummy_cert(ca, "server");
  auto client_cert = get_dummy_cert(ca, "client");

  LOG_INFO_FMT("TEST: verified handshake");

  // Just testing handshake, no communication, but verifies certificates.
  run_test_case(
    (const uint8_t*)"",
    0,
    (const uint8_t*)"",
    0,
    std::move(server_cert),
    std::move(client_cert));
}

TEST_CASE("self-signed server certificate")
{
  auto kp = crypto::make_key_pair();
  auto pk = kp->private_key_pem();
  auto crt = generate_self_signed_cert(kp, "CN=server");
  auto server_cert = make_unique<Cert>(nullptr, crt, pk);

  // Create a CA
  auto ca = get_ca();
  auto client_cert = get_dummy_cert(ca, "client");

  // Client expected to complain about self-signedness.
  REQUIRE_THROWS_WITH_AS(
    run_test_case(
      (const uint8_t*)"",
      0,
      (const uint8_t*)"",
      0,
      std::move(server_cert),
      std::move(client_cert)),
    "Client handshake error",
    std::runtime_error);
}

TEST_CASE("server certificate from different CA")
{
  auto server_ca = get_ca();
  auto server_cert = get_dummy_cert(server_ca, "server");

  auto client_ca = get_ca();
  auto client_cert = get_dummy_cert(client_ca, "client");

  // Client expected to complain
  REQUIRE_THROWS_WITH_AS(
    run_test_case(
      (const uint8_t*)"",
      0,
      (const uint8_t*)"",
      0,
      std::move(server_cert),
      std::move(client_cert)),
    "Client handshake error",
    std::runtime_error);
}

TEST_CASE("self-signed client certificate")
{
  auto server_ca = get_ca();
  auto server_cert = get_dummy_cert(server_ca, "server", false);

  auto kp = crypto::make_key_pair();
  auto pk = kp->private_key_pem();
  auto crt = generate_self_signed_cert(kp, "CN=server");

  // With verification enabled, the client is expected to complain.
  auto client_cert = make_unique<Cert>(nullptr, crt, pk);

  REQUIRE_THROWS_WITH_AS(
    run_test_case(
      (const uint8_t*)"",
      0,
      (const uint8_t*)"",
      0,
      std::move(server_cert),
      std::move(client_cert)),
    "Client handshake error",
    std::runtime_error);

  // Without verification enabled on the client, the server should complain.
  server_cert = get_dummy_cert(server_ca, "server");
  client_cert = make_unique<Cert>(nullptr, crt, pk, std::nullopt, false);

  REQUIRE_THROWS_WITH_AS(
    run_test_case(
      (const uint8_t*)"",
      0,
      (const uint8_t*)"",
      0,
      std::move(server_cert),
      std::move(client_cert)),
    "Server handshake error",
    std::runtime_error);

  // Neither, neither.
  server_cert = get_dummy_cert(server_ca, "server", false);
  client_cert = make_unique<Cert>(nullptr, crt, pk, std::nullopt, false);
  REQUIRE_NOTHROW(run_test_case(
    (const uint8_t*)"",
    0,
    (const uint8_t*)"",
    0,
    std::move(server_cert),
    std::move(client_cert)));
}

TEST_CASE("verified communication")
{
  const uint8_t message[] = "Hello World!";
  size_t message_length = strlen((const char*)message);
  const uint8_t response[] = "Hi back!";
  size_t response_length = strlen((const char*)response);

  // Create a CA
  auto ca = get_ca();

  // Create bogus certificate
  auto server_cert = get_dummy_cert(ca, "server");
  auto client_cert = get_dummy_cert(ca, "client");

  LOG_INFO_FMT("TEST: verified communication");

  // Testing communication channel, verifying certificates.
  run_test_case(
    message,
    message_length,
    response,
    response_length,
    std::move(server_cert),
    std::move(client_cert));
}

TEST_CASE("large message")
{
  // Uninitialised on purpose, we don't care what's in here
  size_t len = 8192;
  uint8_t buf[len];
  auto message = crypto::b64_from_raw(buf, len);

  // Create a CA
  auto ca = get_ca();

  // Create bogus certificate
  auto server_cert = get_dummy_cert(ca, "server");
  auto client_cert = get_dummy_cert(ca, "client");

  LOG_INFO_FMT("TEST: large message");

  // Testing communication channel, verifying certificates.
  run_test_case(
    (const uint8_t*)message.data(),
    message.size(),
    (const uint8_t*)message.data(),
    message.size(),
    std::move(server_cert),
    std::move(client_cert));
}

TEST_CASE("very large message")
{
  // Uninitialised on purpose, we don't care what's in here
  size_t len = 16 * 1024; // 16k, base64 will be more
  uint8_t buf[len];
  auto message = crypto::b64_from_raw(buf, len);

  // Create a CA
  auto ca = get_ca();

  // Create bogus certificate
  auto server_cert = get_dummy_cert(ca, "server");
  auto client_cert = get_dummy_cert(ca, "client");

  LOG_INFO_FMT("TEST: very large message");

  // Testing communication channel, verifying certificates.
  run_test_case(
    (const uint8_t*)message.data(),
    message.size(),
    (const uint8_t*)message.data(),
    message.size(),
    std::move(server_cert),
    std::move(client_cert));
}
