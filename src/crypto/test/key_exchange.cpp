// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN

#include "crypto/key_exchange.h"

#include "crypto/openssl/key_pair.h"

#include <doctest/doctest.h>

TEST_CASE("Simple key exchange")
{
  INFO("Try to compute shared secret before peer public have been exchanged");
  {
    // These key exchange contexts should not be used after negative testing.
    tls::KeyExchangeContext peer1_ctx, peer2_ctx;

    // Cannot compute the shared secret until the peer's public has been
    // loaded
    REQUIRE_THROWS_AS(peer1_ctx.get_shared_secret(), std::logic_error);
    REQUIRE_THROWS_AS(peer2_ctx.get_shared_secret(), std::logic_error);

    // Trying to load empty peer's public
    std::vector<uint8_t> empty_peer;
    REQUIRE_THROWS_AS(
      peer1_ctx.load_peer_key_share(empty_peer), std::runtime_error);
    REQUIRE_THROWS_AS(
      peer2_ctx.load_peer_key_share(empty_peer), std::runtime_error);

    REQUIRE_THROWS_AS(peer1_ctx.get_shared_secret(), std::logic_error);
    REQUIRE_THROWS_AS(peer2_ctx.get_shared_secret(), std::logic_error);
  }

  INFO("Compute shared secret");
  {
    tls::KeyExchangeContext peer1_ctx, peer2_ctx;
    auto peer1_public = peer1_ctx.get_own_key_share();
    auto peer2_public = peer2_ctx.get_own_key_share();

    auto peer1_public_ = peer1_ctx.get_own_key_share();
    auto peer2_public_ = peer2_ctx.get_own_key_share();

    // Calling get_own_key_share() should always return the same result
    REQUIRE(peer1_public == peer1_public_);
    REQUIRE(peer2_public == peer2_public_);

    peer1_ctx.load_peer_key_share(peer2_public);
    peer2_ctx.load_peer_key_share(peer1_public);

    auto peer1_secret = peer1_ctx.get_shared_secret();
    auto peer2_secret = peer2_ctx.get_shared_secret();

    REQUIRE(peer1_secret == peer2_secret);
  }
}
