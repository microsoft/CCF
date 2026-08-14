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

    const ccf::crypto::Pem& get_self_signed_node_cert() const
    {
      return self_signed_node_cert;
    }

    const std::optional<ccf::crypto::Pem>& get_endorsed_node_cert() const
    {
      return endorsed_node_cert;
    }
  };
}

TEST_CASE("NodeClient owns certificate snapshots")
{
  ccf::crypto::Pem self_signed_node_cert(
    "-----BEGIN CERTIFICATE-----\nself\n-----END CERTIFICATE-----");
  std::optional<ccf::crypto::Pem> endorsed_node_cert(
    ccf::crypto::Pem(
      "-----BEGIN CERTIFICATE-----\nendorsed\n-----END CERTIFICATE-----"));
  const auto initial_self_signed_node_cert = self_signed_node_cert;
  const auto initial_endorsed_node_cert = endorsed_node_cert.value();

  TestNodeClient node_client(
    nullptr, nullptr, self_signed_node_cert, endorsed_node_cert);

  self_signed_node_cert = ccf::crypto::Pem(
    "-----BEGIN CERTIFICATE-----\nnew self\n-----END CERTIFICATE-----");
  endorsed_node_cert = ccf::crypto::Pem(
    "-----BEGIN CERTIFICATE-----\nnew endorsed\n-----END CERTIFICATE-----");

  CHECK(
    node_client.get_self_signed_node_cert() == initial_self_signed_node_cert);
  REQUIRE(node_client.get_endorsed_node_cert().has_value());
  CHECK(
    node_client.get_endorsed_node_cert().value() == initial_endorsed_node_cert);
}
