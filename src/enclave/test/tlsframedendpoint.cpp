// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "../tlsframedendpoint.h"

#include "../ds/oversized.h"
#include "../tls/ca.h"
#include "../tls/cert.h"
#include "../tls/context.h"
#include "../tls/server.h"

#include <doctest/doctest.h>
#include <string>

using namespace enclave;

constexpr auto circuit_size = 1 << 18;
ringbuffer::Circuit circuit(circuit_size);
oversized::WriterFactory writer_factory(
  &circuit, {circuit_size / 4, circuit_size / 2});

class TestEndpoint : public FramedTLSEndpoint
{
public:
  std::vector<uint8_t> received;

  template <typename... Ts>
  TestEndpoint(Ts&&... args) : FramedTLSEndpoint(std::forward<Ts>(args)...)
  {}

  bool handle_data(const std::vector<uint8_t>& data) override
  {
    received.insert(received.end(), data.begin(), data.end());
    return true;
  }
};

struct Client
{
  tls::Context ctx = tls::Context(true, true);
  size_t id;
  std::unique_ptr<ringbuffer::AbstractWriter> to_server;
  std::vector<uint8_t> pending_inbound;
};

static int client_send_callback(void* o, const unsigned char* buf, size_t len)
{
  auto c = reinterpret_cast<Client*>(o);

  auto wrote = RINGBUFFER_TRY_WRITE_MESSAGE(
    tls::tls_inbound, c->to_server, c->id, serializer::ByteRange{buf, len});

  if (!wrote)
    return MBEDTLS_ERR_SSL_WANT_WRITE;

  return (int)len;
}

static int client_recv_callback(void* o, unsigned char* buf, size_t len)
{
  auto c = reinterpret_cast<Client*>(o);
  auto& pending = c->pending_inbound;
  if (pending.size() > 0)
  {
    size_t rd = std::min(len, pending.size());
    ::memcpy(buf, pending.data(), rd);

    if (rd >= pending.size())
    {
      pending.clear();
    }
    else
    {
      pending.erase(pending.begin(), pending.begin() + rd);
    }

    return (int)rd;
  }

  return MBEDTLS_ERR_SSL_WANT_READ;
}

TEST_CASE("handshake")
{
  Client c;
  c.to_server = writer_factory.create_writer_to_inside();

  mbedtls_ssl_set_bio(
    &c.ssl, &c, client_send_callback, client_recv_callback, nullptr);

  while (true)
  {
    auto err = mbedtls_ssl_handshake(&c.ssl);
    if (err == 0)
    {
      break;
    }
    else if (
      (err != MBEDTLS_ERR_SSL_WANT_READ) && (err != MBEDTLS_ERR_SSL_WANT_WRITE))
    {
      constexpr auto buf_len = 100;
      char str_err[buf_len];
      mbedtls_strerror(err, str_err, buf_len);
      throw std::logic_error(
        "Unexpected mbedtls error code: " + std::string(str_err));
    }
  }
}

TEST_CASE("recv")
{
  std::vector<uint8_t> raw_ca;
  auto ca = std::make_shared<tls::CA>(raw_ca);
  auto cert = std::make_shared<tls::Cert>("users", ca);
  auto server = std::make_unique<tls::Server>(cert);
  TestEndpoint endpoint(0, writer_factory, std::move(server));

  std::vector<uint8_t> in{0, 1, 2, 3, 4, 5, 6, 7};
  endpoint.recv(in.data(), in.size());

  REQUIRE(endpoint.received == in);
}