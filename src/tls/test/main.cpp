// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ccf/crypto/ec_key_pair.h"
#include "ccf/crypto/verifier.h"
#include "ccf/ds/nonstd.h"
#include "crypto/certs.h"
#include "ds/internal_logger.h"
#include "tcp/msg_types.h"
#include "tls/client.h"
#include "tls/server.h"
#include "tls/tls.h"

#include <chrono>
#include <exception>
#include <openssl/err.h>
#include <openssl/ssl.h>
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <iostream>
#include <memory>
#include <string>

using namespace std;
using namespace ccf::crypto;
using namespace tls;

/// Moves all the encrypted bytes that 'from' wants to send into 'to', as if
/// they had traversed the network. Returns the number of bytes transferred.
size_t transfer(ccf::tls::Context& from, ccf::tls::Context& to)
{
  size_t total = 0;
  std::vector<uint8_t> buf(16384);
  size_t got = 0;
  while ((got = from.send(buf.data(), buf.size())) > 0)
  {
    to.recv(buf.data(), got);
    total += got;
  }
  return total;
}

/// Returns true if the handshake status code indicates a genuine error, as
/// opposed to success or a request for more data.
bool is_handshake_error(int rc)
{
  return rc != 0 && rc != SSL_ERROR_WANT_READ && rc != SSL_ERROR_WANT_WRITE;
}

/// Drives the handshake between a client and a server connected via in-memory
/// BIOs, pumping bytes across after each step.
/// Returns 0 on success, 1 on client error, 2 on server error.
int handshake(ccf::tls::Context& client, ccf::tls::Context& server)
{
  constexpr int max_iterations = 50;
  for (int i = 0; i < max_iterations; ++i)
  {
    int cs = client.handshake();
    transfer(client, server);
    int ss = server.handshake();
    transfer(server, client);

    if (is_handshake_error(cs))
    {
      LOG_FAIL_FMT(
        "Client handshake error: {}", ::tls::error_string(ERR_get_error()));
      return 1;
    }
    if (is_handshake_error(ss))
    {
      LOG_FAIL_FMT(
        "Server handshake error: {}", ::tls::error_string(ERR_get_error()));
      return 2;
    }

    if (cs == 0 && ss == 0)
    {
      return 0;
    }
  }

  LOG_FAIL_FMT("Handshake did not complete in {} iterations", max_iterations);
  return 1;
}

struct NetworkCA
{
  shared_ptr<ccf::crypto::ECKeyPair> kp;
  ccf::crypto::Pem cert;
};

static ccf::crypto::Pem generate_self_signed_cert(
  const ccf::crypto::ECKeyPairPtr& kp, const std::string& name)
{
  using namespace std::literals;
  constexpr size_t certificate_validity_period_days = 365;
  auto valid_from =
    ccf::ds::to_x509_time_string(std::chrono::system_clock::now() - 24h);

  return ccf::crypto::create_self_signed_cert(
    kp, name, {}, valid_from, certificate_validity_period_days);
}

static ccf::crypto::Pem generate_endorsed_cert(
  const ccf::crypto::ECKeyPairPtr& kp,
  const std::string& name,
  const ccf::crypto::ECKeyPairPtr& issuer_kp,
  const ccf::crypto::Pem& issuer_cert)
{
  constexpr size_t certificate_validity_period_days = 365;

  using namespace std::literals;
  auto valid_from =
    ccf::ds::to_x509_time_string(std::chrono::system_clock::now() - 24h);

  return ccf::crypto::create_endorsed_cert(
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
  auto kp = ccf::crypto::make_ec_key_pair();
  auto crt = generate_self_signed_cert(kp, "CN=issuer");
  LOG_DEBUG_FMT("New self-signed CA certificate:\n{}", crt.str());
  return {kp, crt};
}

/// Creates a ::tls::Cert with a new CA using a new self-signed Pem certificate.
unique_ptr<::tls::Cert> get_dummy_cert(
  NetworkCA& net_ca, string name, bool auth_required = true)
{
  // Create a CA with a self-signed certificate
  auto ca = make_unique<::tls::CA>(net_ca.cert.str());

  // Create a signing request and sign with the CA
  auto kp = ccf::crypto::make_ec_key_pair();
  auto crt = generate_endorsed_cert(kp, "CN=" + name, net_ca.kp, net_ca.cert);
  LOG_DEBUG_FMT("New CA-signed certificate:\n{}", crt.str());

  // Verify node certificate with the CA's certificate
  auto v = ccf::crypto::make_verifier(crt);
  REQUIRE(v->verify_certificate({&net_ca.cert}));

  // Create a ::tls::Cert with the CA, the signed certificate and the private
  // key
  auto pk = kp->private_key_pem();
  return make_unique<Cert>(std::move(ca), crt, pk, std::nullopt, auth_required);
}

TEST_CASE("CA configures trusted certificate store")
{
  auto ca = get_ca();
  ::tls::CA trusted_ca(ca.cert.str(), true);
  ccf::crypto::OpenSSL::Unique_SSL_CTX ctx(TLS_method());

  trusted_ca.configure_trusted_cert_store(ctx);

  auto* store = SSL_CTX_get_cert_store(ctx);
  REQUIRE(store != nullptr);
  auto* params = X509_STORE_get0_param(store);
  REQUIRE(params != nullptr);
  REQUIRE(
    (X509_VERIFY_PARAM_get_flags(params) & X509_V_FLAG_PARTIAL_CHAIN) != 0);
}

TEST_CASE("Cert configures TLS verification and own certificate")
{
  auto ca = get_ca();
  auto cert = get_dummy_cert(ca, "server");
  ccf::crypto::OpenSSL::Unique_SSL_CTX ctx(TLS_method());
  ccf::crypto::OpenSSL::Unique_SSL ssl(ctx);

  cert->configure_ssl(ssl, ctx);

  constexpr auto expected_verify_mode =
    SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
  REQUIRE(SSL_CTX_get_verify_mode(ctx) == expected_verify_mode);
  REQUIRE(SSL_get_verify_mode(ssl) == expected_verify_mode);
  REQUIRE(SSL_CTX_get0_certificate(ctx) != nullptr);
  REQUIRE(SSL_get_certificate(ssl) != nullptr);
}

/// Helper to write a full message, transferring the encrypted bytes to the
/// peer as they are produced. Returns the number of plaintext bytes written.
size_t write_helper(
  ccf::tls::Context& handler,
  ccf::tls::Context& peer,
  const uint8_t* buf,
  size_t len)
{
  LOG_DEBUG_FMT("WRITE {} bytes", len);
  size_t total = 0;
  while (total < len)
  {
    size_t written = 0;
    int rc = handler.write(buf + total, len - total, written);
    total += written;
    transfer(handler, peer);
    if (rc != 0)
    {
      break;
    }
  }
  return total;
}

/// Helper to read a full message from already-received encrypted bytes.
/// Returns the number of plaintext bytes read.
size_t read_helper(ccf::tls::Context& handler, uint8_t* buf, size_t len)
{
  LOG_DEBUG_FMT("READ {} bytes", len);
  size_t total = 0;
  while (total < len)
  {
    size_t readbytes = 0;
    int rc = handler.read(buf + total, len - total, readbytes);
    total += readbytes;
    if (rc != 0)
    {
      break;
    }
  }
  return total;
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
  unique_ptr<::tls::Cert> server_cert,
  unique_ptr<::tls::Cert> client_cert)
{
  std::vector<uint8_t> buf(max(message_length, response_length) + 1);

  // Create a pair of client/server
  tls::Server server(std::move(server_cert));
  tls::Client client(std::move(client_cert));

  // Set up the in-memory BIOs used to exchange encrypted bytes
  server.set_bio();
  client.set_bio();

  LOG_INFO_FMT("Handshake");
  switch (handshake(client, server))
  {
    case 0:
      break;
    case 1:
      throw runtime_error("Client handshake error");
    default:
      throw runtime_error("Server handshake error");
  }
  LOG_INFO_FMT("Handshake completed");

  // The rest of the communication is deterministic and easy to simulate
  // so we drive it directly, transferring bytes between the peers as needed.
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
  size_t written = write_helper(client, server, message, message_length);
  REQUIRE(written == message_length);

  // Receive the first message
  size_t read = read_helper(server, buf.data(), message_length);
  REQUIRE(read == message_length);
  buf[message_length] = '\0';
  LOG_INFO_FMT(
    "Server message received [{}]",
    truncate_message(buf.data(), message_length));
  REQUIRE(
    strncmp((const char*)buf.data(), (const char*)message, message_length) ==
    0);

  // Send the response
  LOG_INFO_FMT(
    "Server sending message [{}]", truncate_message(response, message_length));
  written = write_helper(server, client, response, response_length);
  REQUIRE(written == response_length);

  // Receive the response
  read = read_helper(client, buf.data(), response_length);
  REQUIRE(read == response_length);
  buf[response_length] = '\0';
  LOG_INFO_FMT(
    "Client message received [{}]",
    truncate_message(buf.data(), message_length));
  REQUIRE(
    strncmp((const char*)buf.data(), (const char*)response, response_length) ==
    0);

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
  auto kp = ccf::crypto::make_ec_key_pair();
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

  auto kp = ccf::crypto::make_ec_key_pair();
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
  std::vector<uint8_t> buf(len);
  auto message = ccf::crypto::b64_from_raw(buf.data(), len);

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
  std::vector<uint8_t> buf(len);
  auto message = ccf::crypto::b64_from_raw(buf.data(), len);

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
