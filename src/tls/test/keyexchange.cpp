// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN

#include "../keyexchange.h"

#include <doctest/doctest.h>

TEST_CASE("Simple key exchange")
{
  std::cout << "A" << std::endl;
  INFO("Try to compute shared secret before peer public have been exchanged");
  {
    std::cout << "B" << std::endl;

    // These key exchange contexts should not be used after negative testing.
    tls::KeyExchangeContext peer1_ctx, peer2_ctx;

    std::cout << "C" << std::endl;

    // Cannot compute the shared secret until the peer's public has been
    // loaded
    REQUIRE_THROWS_AS(peer1_ctx.compute_shared_secret(), std::logic_error);
    std::cout << "D" << std::endl;
    REQUIRE_THROWS_AS(peer2_ctx.compute_shared_secret(), std::logic_error);
    std::cout << "E" << std::endl;

    // Trying to load empty peer's public
    std::vector<uint8_t> empty_peer;
    std::cout << "F" << std::endl;
    REQUIRE_THROWS_AS(
      peer1_ctx.load_peer_public(empty_peer.data(), empty_peer.size()),
      std::logic_error);
    std::cout << "G" << std::endl;
    REQUIRE_THROWS_AS(
      peer2_ctx.load_peer_public(empty_peer.data(), empty_peer.size()),
      std::logic_error);
    std::cout << "H" << std::endl;

    REQUIRE_THROWS_AS(peer1_ctx.compute_shared_secret(), std::logic_error);
    std::cout << "I" << std::endl;
    REQUIRE_THROWS_AS(peer2_ctx.compute_shared_secret(), std::logic_error);
    std::cout << "J" << std::endl;
  }

  INFO("Compute shared secret");
  {
    std::cout << "K" << std::endl;
    tls::KeyExchangeContext peer1_ctx, peer2_ctx;
    std::cout << "L" << std::endl;
    auto peer1_public = peer1_ctx.get_own_public();
    std::cout << "M" << std::endl;
    auto peer2_public = peer2_ctx.get_own_public();
    std::cout << "N" << std::endl;

    auto peer1_public_ = peer1_ctx.get_own_public();
    std::cout << "O" << std::endl;
    auto peer2_public_ = peer2_ctx.get_own_public();
    std::cout << "Q" << std::endl;

    // Calling get_own_public() should always return the same result
    REQUIRE(peer1_public == peer1_public_);
    std::cout << "R" << std::endl;
    REQUIRE(peer2_public == peer2_public_);
    std::cout << "S" << std::endl;

    peer1_ctx.load_peer_public(peer2_public.data(), peer2_public.size());
    std::cout << "T" << std::endl;
    peer2_ctx.load_peer_public(peer1_public.data(), peer1_public.size());
    std::cout << "U" << std::endl;

    auto peer1_secret = peer1_ctx.compute_shared_secret();
    std::cout << "V" << std::endl;
    auto peer2_secret = peer2_ctx.compute_shared_secret();
    std::cout << "W" << std::endl;

    REQUIRE(peer1_secret == peer2_secret);
    std::cout << "X" << std::endl;
  }
  std::cout << "Y" << std::endl;
}