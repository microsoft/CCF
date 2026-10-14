// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "host/node_tls.h"

#include "ccf/crypto/ec_key_pair.h"
#include "crypto/certs.h"

#include <doctest/doctest.h>

namespace
{
  struct Identity
  {
    ccf::crypto::ECKeyPairPtr key = ccf::crypto::make_ec_key_pair();
    ccf::crypto::Pem cert;
    ccf::NodeId id = ccf::crypto::Sha256Hash(key->public_key_der()).hex_str();

    Identity() :
      cert(ccf::crypto::create_self_signed_cert(
        key, "CN=Test service", {}, "20000101000000Z", 1))
    {}

    explicit Identity(const Identity& service, int) :
      cert(ccf::crypto::create_endorsed_cert(
        key,
        "CN=Test node",
        {},
        "20000101000000Z",
        1,
        service.key->private_key_pem(),
        service.cert))
    {}

    std::shared_ptr<asynchost::NodeTLSContext> context(
      const Identity& service) const
    {
      return std::make_shared<asynchost::NodeTLSContext>(
        asynchost::NodeTLSCredentials{
          service.cert, cert, key->private_key_pem()});
    }
  };

  struct Pair
  {
    asynchost::NodeTLSSession client;
    asynchost::NodeTLSSession server;
    std::vector<uint8_t> to_client;
    std::vector<uint8_t> to_server;
    std::vector<uint8_t> received;
    size_t ciphertext_bytes = 0;

    Pair(
      std::shared_ptr<asynchost::NodeTLSContext> client_context,
      std::shared_ptr<asynchost::NodeTLSContext> server_context,
      const ccf::NodeId& expected,
      size_t client_record_limit = asynchost::max_node_tls_records_per_key,
      size_t server_record_limit = asynchost::max_node_tls_records_per_key) :
      client(std::move(client_context), expected, 1 << 20, client_record_limit),
      server(
        std::move(server_context), std::nullopt, 1 << 20, server_record_limit)
    {}

    bool exchange(bool fragment = false)
    {
      const auto pump = [&](auto& session, auto& in, auto& out) {
        const auto count =
          fragment ? std::min<size_t>(in.size(), 13) : in.size();
        std::vector<uint8_t> chunk(in.begin(), in.begin() + count);
        in.erase(in.begin(), in.begin() + count);
        return session.pump(
          chunk,
          [&](size_t n, const uint8_t* p) {
            ciphertext_bytes += n;
            out.insert(out.end(), p, p + n);
            return true;
          },
          [&](size_t n, const uint8_t* p) {
            received.insert(received.end(), p, p + n);
            return true;
          });
      };
      for (size_t i = 0; i < 10000; ++i)
      {
        if (
          !pump(client, to_client, to_server) ||
          !pump(server, to_server, to_client))
        {
          return false;
        }
        if (to_client.empty() && to_server.empty())
        {
          return true;
        }
      }
      FAIL("TLS exchange did not quiesce");
      return false;
    }
  };
}

TEST_CASE("Node TLS authenticates expired service-endorsed signing identities")
{
  Identity service;
  Identity a(service, 0);
  Identity b(service, 0);
  Pair pair(a.context(service), b.context(service), b.id);
  // Queue before the handshake, fragment TLS records and send more than one
  // record. Includes the bytes which would hold appended ledger entries.
  const std::vector<uint8_t> message(65536, 42);
  pair.client.enqueue(message);
  REQUIRE(pair.exchange(true));
  CHECK(pair.client.peer() == b.id);
  CHECK(pair.server.peer() == a.id);
  CHECK(pair.received == message);
  CHECK(pair.ciphertext_bytes > message.size());
  pair.received.clear();
  pair.server.enqueue(message);
  REQUIRE(pair.exchange());
  CHECK(pair.received == message);
}

TEST_CASE("Node TLS rejects a different service")
{
  Identity service;
  Identity other_service;
  Identity a(service, 0);
  Identity b(other_service, 0);
  Pair pair(a.context(service), b.context(other_service), b.id);
  pair.client.enqueue({1, 2, 3});
  CHECK_FALSE(pair.exchange());
  CHECK(pair.received.empty());
}

TEST_CASE("Node TLS rejects an unexpected node in the same service")
{
  Identity service;
  Identity a(service, 0);
  Identity b(service, 0);
  Pair pair(a.context(service), b.context(service), a.id);
  pair.client.enqueue({1, 2, 3});
  CHECK_FALSE(pair.exchange());
  CHECK(pair.received.empty());
}

TEST_CASE("Node TLS requires a client certificate")
{
  Identity service;
  Identity a(service, 0);
  Identity b(service, 0);
  auto anonymous_client = a.context(service);
  // Deliberately create a client with no certificate. Production contexts
  // always load an endorsed certificate and matching private key.
  anonymous_client->ctx.reset(SSL_CTX_new(TLS_method()));
  ccf::crypto::OpenSSL::CHECKNULL(anonymous_client->ctx);
  Pair pair(anonymous_client, b.context(service), b.id);
  pair.client.enqueue({1, 2, 3});
  CHECK_FALSE(pair.exchange());
  CHECK_FALSE(pair.server.peer().has_value());
  CHECK(pair.received.empty());
}

TEST_CASE("Node TLS bounds sends queued during handshake")
{
  Identity service;
  Identity a(service, 0);
  Identity b(service, 0);
  Pair pair(a.context(service), b.context(service), b.id);
  const std::vector<uint8_t> message(1 << 20);
  pair.client.enqueue(message);
  CHECK_THROWS(pair.client.enqueue({1}));
}

TEST_CASE("Node TLS updates directional keys across fragmented frames")
{
  Identity service;
  Identity a(service, 0);
  Identity b(service, 0);
  Pair pair(a.context(service), b.context(service), b.id, 4, 4);
  // Each frame spans four records, exceeding the number of application-data
  // records allowed under one key once KeyUpdate overhead is reserved.
  const std::vector<uint8_t> message(65536, 42);
  for (size_t i = 0; i < 3; ++i)
  {
    pair.client.enqueue(message);
    REQUIRE(pair.exchange(true));
    CHECK(pair.received == message);
    pair.received.clear();
    pair.server.enqueue(message);
    REQUIRE(pair.exchange(true));
    CHECK(pair.received == message);
    pair.received.clear();
  }
  CHECK(pair.client.key_updates_sent() >= 3);
  CHECK(pair.server.key_updates_sent() >= 3);
  CHECK(pair.client.peer() == b.id);
  CHECK(pair.server.peer() == a.id);
}

TEST_CASE("Node TLS rejects a peer exceeding the receiving key budget")
{
  Identity service;
  Identity a(service, 0);
  Identity b(service, 0);
  Pair pair(
    a.context(service),
    b.context(service),
    b.id,
    asynchost::max_node_tls_records_per_key,
    4);
  const std::vector<uint8_t> message(131072, 42);
  pair.client.enqueue(message);
  CHECK_FALSE(pair.exchange());
  CHECK(pair.received.size() < message.size());
}
