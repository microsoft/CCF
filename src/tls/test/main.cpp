// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "crypto/certs.h"
#include "crypto/key_pair.h"
#include "crypto/verifier.h"
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "ds/buffer.h"
#include "ds/logger.h"
#include "tls/client.h"
#include "tls/msg_types.h"
#include "tls/server.h"

#include <chrono>
#include <doctest/doctest.h>
#include <iostream>
#include <memory>
#include <string>
#include <sys/socket.h>
#include <thread>

using namespace std;
using namespace crypto;
using namespace tls;

/// Server uses one descriptor while client uses the other.
/// Use the send/recv template wrappers below as callbacks.
class TestPipe
{
  int pfd[2];

public:
  static const int SERVER = 0;
  static const int CLIENT = 1;

  TestPipe(bool dgram)
  {
    int sock_type = 0;
    if (dgram)
      sock_type = SOCK_DGRAM;
    else
      sock_type = SOCK_STREAM;
    if (socketpair(PF_LOCAL, sock_type, 0, pfd) == -1)
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
    return write(pfd[id], buf, len);
  }

  size_t recv(int id, uint8_t* buf, size_t len)
  {
    return read(pfd[id], buf, len);
  }
};

/// Callback wrapper around TestPipe->send().
template <int end>
int send(void* ctx, const uint8_t* buf, size_t len)
{
  auto pipe = reinterpret_cast<TestPipe*>(ctx);
  return pipe->send(end, buf, len);
}

/// Callback wrapper around TestPipe->recv().
template <int end>
int recv(void* ctx, uint8_t* buf, size_t len)
{
  auto pipe = reinterpret_cast<TestPipe*>(ctx);
  return pipe->recv(end, buf, len);
}

/// Performs a TLS handshake, looping until there's nothing more to read/write.
/// Returns 0 on success, throws a runtime error with SSL error str on failure.
int handshake(Context* ctx)
{
  while (true)
  {
    int rc = ctx->handshake();

    // FIXME: Make the cases work with other implementations
    switch (rc)
    {
      case 0:
        return 0;
      case MBEDTLS_ERR_SSL_WANT_READ:
      case MBEDTLS_ERR_SSL_WANT_WRITE:
        // Continue calling handshake until finished
        break;
      case MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE:
      case MBEDTLS_ERR_SSL_PEER_VERIFY_FAILED:
      {
        LOG_FAIL_FMT("Handshake error: {}", crypto::error_string(rc));
        return 1;
      }

      case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
      {
        LOG_FAIL_FMT("Handshake error: {}", crypto::error_string(rc));
        return 1;
      }

      case MBEDTLS_ERR_X509_CERT_VERIFY_FAILED:
      {
        std::vector<char> buf(512);
        auto r = mbedtls_x509_crt_verify_info(
          buf.data(),
          buf.size(),
          "Certificate verify failed: ",
          ctx->verify_result());

        if (r > 0)
        {
          buf.resize(r);
          LOG_FAIL_FMT("{}", std::string(buf.data(), buf.size()));
        }

        LOG_FAIL_FMT("Handshake error: {}", crypto::error_string(rc));
        return 1;
      }

      default:
      {
        LOG_FAIL_FMT("Handshake error: {}", crypto::error_string(rc));
        return 1;
      }
    }
  }
}

struct NetworkCA
{
  shared_ptr<crypto::KeyPair> kp;
  crypto::Pem cert;
};

/// Get self-signed CA certificate.
NetworkCA get_ca()
{
  // Create a CA with a self-signed certificate
  auto kp = crypto::make_key_pair();
  auto crt = kp->self_sign("CN=issuer");
  LOG_DEBUG_FMT("New self-signed CA certificate:{}", crt.str());
  return {kp, crt};
}

/// Creates a tls::Cert with a new CA using a new self-signed Pem certificate.
unique_ptr<tls::Cert> get_dummy_cert(NetworkCA& net_ca, string name)
{
  // Create a CA with a self-signed certificate
  auto ca = make_unique<tls::CA>(CBuffer(net_ca.cert.str()));

  // Create a signing request and sign with the CA
  auto kp = crypto::make_key_pair();
  auto csr = kp->create_csr("CN=" + name);
  LOG_DEBUG_FMT("CSR for {} is:{}", name, csr.str());

  auto crt = net_ca.kp->sign_csr(net_ca.cert, csr);
  LOG_DEBUG_FMT("New CA-signed certificate:{}", crt.str());

  // Verify node certificate with the CA's certificate
  auto v = crypto::make_verifier(crt);
  REQUIRE(v->verify_certificate({&net_ca.cert}));

  // Create a tls::Cert with the CA, the signed certificate and the private key
  auto pk = kp->private_key_pem();
  return make_unique<Cert>(move(ca), crt, pk);
}

/// Test runner, with various options for different kinds of tests.
void run_test_case(
  int dgram,
  const uint8_t* message,
  size_t message_length,
  const uint8_t* response,
  size_t response_length,
  unique_ptr<tls::Cert> server_cert,
  unique_ptr<tls::Cert> client_cert,
  bool requires_auth)
{
  uint8_t buf[max(message_length, response_length) + 1];

  // Create a pair of client/server
  tls::Server server(move(server_cert), dgram);
  server.set_require_auth(requires_auth);
  tls::Client client(move(client_cert), dgram);
  client.set_require_auth(requires_auth);

  // Connect BIOs together
  TestPipe pipe(dgram);
  server.set_bio(
    &pipe, send<TestPipe::SERVER>, recv<TestPipe::SERVER>, nullptr);
  client.set_bio(
    &pipe, send<TestPipe::CLIENT>, recv<TestPipe::CLIENT>, nullptr);

  // There could be multiple communications between client/server while
  // doing the handshake, and they won't return an error until there's
  // nothing more to read/write, so we put them in separate threads.

  // Create a thread for the client handshake
  thread client_thread([&client]() {
    LOG_INFO_FMT("Client handshake");
    if (handshake(&client))
      throw runtime_error("Client handshake error");
  });

  // Create a thread for the server handshake
  thread server_thread([&server]() {
    LOG_INFO_FMT("Server handshake");
    if (handshake(&server))
      throw runtime_error("Server handshake error");
  });

  // Join threads
  client_thread.join();
  server_thread.join();
  LOG_INFO_FMT("Handshake completed");

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
  LOG_INFO_FMT("Client sending message [{}]", string((const char*)message));
  int written = client.write(message, message_length);
  REQUIRE(written == message_length);

  // Receive the first message
  int read = server.read(buf, message_length);
  REQUIRE(read == message_length);
  buf[message_length] = '\0';
  LOG_INFO_FMT("Server message received [{}]", string((const char*)buf));
  REQUIRE(strncmp((const char*)buf, (const char*)message, message_length) == 0);

  // Send the response
  LOG_INFO_FMT("Server sending message [{}]", string((const char*)response));
  written = server.write(response, response_length);
  REQUIRE(written == response_length);

  // Receive the response
  read = client.read(buf, response_length);
  REQUIRE(read == response_length);
  buf[response_length] = '\0';
  LOG_INFO_FMT("Client message received [{}]", string((const char*)buf));
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
  auto server_cert = get_dummy_cert(ca, "server");
  auto client_cert = get_dummy_cert(ca, "client");

  // Just testing handshake, does not verify certificates, no communication.
  run_test_case(
    0,
    (const uint8_t*)"",
    0,
    (const uint8_t*)"",
    0,
    move(server_cert),
    move(client_cert),
    false);
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
  auto server_cert = get_dummy_cert(ca, "server");
  auto client_cert = get_dummy_cert(ca, "client");

  // Just testing communication channel, does not verify certificates.
  run_test_case(
    0,
    message,
    message_length,
    response,
    response_length,
    move(server_cert),
    move(client_cert),
    false);
}

TEST_CASE("verified handshake")
{
  // Create a CA
  auto ca = get_ca();

  // Create bogus certificate
  auto server_cert = get_dummy_cert(ca, "server");
  auto client_cert = get_dummy_cert(ca, "client");

  // Just testing handshake, no communication, but verifies certificates.
  run_test_case(
    0,
    (const uint8_t*)"",
    0,
    (const uint8_t*)"",
    0,
    move(server_cert),
    move(client_cert),
    true);
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

  // Testing communication channel, verifying certificates.
  run_test_case(
    0,
    message,
    message_length,
    response,
    response_length,
    move(server_cert),
    move(client_cert),
    true);
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

  // Testing communication channel, verifying certificates.
  run_test_case(
    0,
    (const uint8_t*)message.data(),
    message.size(),
    (const uint8_t*)message.data(),
    message.size(),
    move(server_cert),
    move(client_cert),
    true);
}
