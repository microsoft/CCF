// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "node/node_client.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

namespace
{
  class TestNodeClient : public ccf::NodeClient
  {
  public:
    using ccf::NodeClient::NodeClient;

    bool make_request([[maybe_unused]] ::http::Request& request) override
    {
      return true;
    }

    ccf::crypto::Pem get_node_cert() const
    {
      return get_node_certificate();
    }
  };
}

TEST_CASE("NodeClient obtains owned snapshots of current certificates")
{
  ccf::crypto::Pem self_signed_node_cert(
    "-----BEGIN CERTIFICATE-----\nself\n-----END CERTIFICATE-----");
  std::optional<ccf::crypto::Pem> endorsed_node_cert;

  TestNodeClient node_client(nullptr, nullptr, [&]() {
    return endorsed_node_cert.value_or(self_signed_node_cert);
  });

  const auto initial_self_signed_node_cert = node_client.get_node_cert();
  CHECK(initial_self_signed_node_cert == self_signed_node_cert);

  self_signed_node_cert = ccf::crypto::Pem(
    "-----BEGIN CERTIFICATE-----\nnew self\n-----END CERTIFICATE-----");
  CHECK(node_client.get_node_cert() == self_signed_node_cert);
  CHECK(initial_self_signed_node_cert != self_signed_node_cert);

  endorsed_node_cert = ccf::crypto::Pem(
    "-----BEGIN CERTIFICATE-----\nendorsed\n-----END CERTIFICATE-----");
  const auto initial_endorsed_node_cert = node_client.get_node_cert();
  CHECK(initial_endorsed_node_cert == endorsed_node_cert.value());

  endorsed_node_cert = ccf::crypto::Pem(
    "-----BEGIN CERTIFICATE-----\nnew endorsed\n-----END CERTIFICATE-----");
  CHECK(node_client.get_node_cert() == endorsed_node_cert.value());
  CHECK(initial_endorsed_node_cert != endorsed_node_cert.value());
}
