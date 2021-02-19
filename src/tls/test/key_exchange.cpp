// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN

#include "../key_exchange.h"

#include <doctest/doctest.h>

TEST_CASE("Simple key exchange")
{
  INFO("Try to compute shared secret before peer public have been exchanged");
  {
    // These key exchange contexts should not be used after negative testing.
    tls::KeyExchangeContext peer1_ctx, peer2_ctx;

    // Cannot compute the shared secret until the peer's public has been
    // loaded
    REQUIRE_THROWS_AS(peer1_ctx.compute_shared_secret(), std::logic_error);
    REQUIRE_THROWS_AS(peer2_ctx.compute_shared_secret(), std::logic_error);

    // Trying to load empty peer's public
    std::vector<uint8_t> empty_peer;
    REQUIRE_THROWS_AS(
      peer1_ctx.load_peer_public(empty_peer.data(), empty_peer.size()),
      std::logic_error);
    REQUIRE_THROWS_AS(
      peer2_ctx.load_peer_public(empty_peer.data(), empty_peer.size()),
      std::logic_error);

    REQUIRE_THROWS_AS(peer1_ctx.compute_shared_secret(), std::logic_error);
    REQUIRE_THROWS_AS(peer2_ctx.compute_shared_secret(), std::logic_error);
  }

  INFO("Compute shared secret");
  {
    tls::KeyExchangeContext peer1_ctx, peer2_ctx;
    auto peer1_public = peer1_ctx.get_own_public();
    auto peer2_public = peer2_ctx.get_own_public();

    auto peer1_public_ = peer1_ctx.get_own_public();
    auto peer2_public_ = peer2_ctx.get_own_public();

    // Calling get_own_public() should always return the same result
    REQUIRE(peer1_public == peer1_public_);
    REQUIRE(peer2_public == peer2_public_);

    peer1_ctx.load_peer_public(peer2_public.data(), peer2_public.size());
    peer2_ctx.load_peer_public(peer1_public.data(), peer1_public.size());

    auto peer1_secret = peer1_ctx.compute_shared_secret();
    auto peer2_secret = peer2_ctx.compute_shared_secret();

    REQUIRE(peer1_secret == peer2_secret);
  }
}

TEST_CASE("Key exchange from static shares")
{
  auto peer1_kp =
    std::make_shared<tls::KeyPair_mbedTLS>(tls::service_identity_curve_choice);
  auto peer2_kp =
    std::make_shared<tls::KeyPair_mbedTLS>(tls::service_identity_curve_choice);

  auto peer1_ctx = tls::KeyExchangeContext(peer1_kp, peer2_kp);
  auto peer2_ctx = tls::KeyExchangeContext(peer2_kp, peer1_kp);

  REQUIRE(
    peer1_ctx.compute_shared_secret() == peer2_ctx.compute_shared_secret());
}