// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <random>

#define FMT_HEADER_ONLY
#include "crypto/sharing.h"

#include <charconv>
#include <fmt/format.h>

using namespace crypto::sharing;

void check_share_is_not_trivially_wrong(const Share& share)
{
  REQUIRE(share.x != 0);
  bool all_limbs_are_zero = true;
  bool all_limbs_are_max = true;
  for (size_t i = 0; i < LIMBS; ++i)
  {
    if (share.y[i] != 0)
    {
      all_limbs_are_zero = false;
    }
    if (share.y[i] != 0xFFFFFFFF)
    {
      all_limbs_are_max = false;
    }
    if (!all_limbs_are_zero && !all_limbs_are_max)
    {
      break;
    }
  }
  REQUIRE(!all_limbs_are_zero);
  REQUIRE(!all_limbs_are_max);
}

void share_and_recover(
  std::mt19937& rng, size_t num_shares, size_t threshold, size_t recoveries)
{
  fmt::println(
    "Testing {} shares with threshold {} for {} recoveries",
    num_shares,
    threshold,
    recoveries);
  std::vector<Share> shares(num_shares);

  Share secret;
  sample_secret_and_shares(secret, shares, threshold);

  for (const auto& share : shares)
  {
    check_share_is_not_trivially_wrong(share);
  }

  for (size_t i = 0; i < recoveries; ++i)
  {
    std::vector<Share> recovered_shares;
    std::sample(
      shares.begin(),
      shares.end(),
      std::back_inserter(recovered_shares),
      threshold,
      rng);
    {
      Share recovered;
      recover_unauthenticated_secret(recovered, recovered_shares, threshold);
      INFO(fmt::format(
        "Recovering secret with threshold {} from {} shares",
        threshold,
        recovered_shares.size()));
      REQUIRE(secret == recovered);
    }

    {
      Share recovered;
      recovered_shares.pop_back();
      INFO(fmt::format(
        "Recovering secret with threshold {} from {} shares",
        threshold - 1,
        recovered_shares.size()));
      REQUIRE_THROWS_AS(
        recover_unauthenticated_secret(recovered, recovered_shares, threshold),
        std::invalid_argument);
    }
  }
}

TEST_CASE("The number of shares needs to allow recovery")
{
  std::vector<Share> shares(0);

  Share secret, recovered;
  REQUIRE_THROWS_AS(
    sample_secret_and_shares(secret, shares, 3), std::invalid_argument);

  shares.resize(3);
  REQUIRE_THROWS_AS(
    sample_secret_and_shares(secret, shares, 4), std::invalid_argument);
}

TEST_CASE("Simple sharing and recovery")
{
  constexpr size_t num_shares = 10;
  constexpr size_t threshold = 3;

  std::vector<Share> shares(num_shares);

  Share secret, recovered;
  sample_secret_and_shares(secret, shares, threshold);

  recover_unauthenticated_secret(recovered, shares, threshold);
  REQUIRE(secret == recovered);
}

TEST_CASE("Simple sharing and recovery with duplicate shares")
{
  constexpr size_t num_shares = 10;
  constexpr size_t threshold = 3;

  std::vector<Share> shares(num_shares);

  Share secret, recovered;
  sample_secret_and_shares(secret, shares, threshold);

  std::vector<Share> shares_with_duplicates(threshold, shares[0]);
  REQUIRE_THROWS_AS(
    recover_unauthenticated_secret(
      recovered, shares_with_duplicates, threshold),
    std::invalid_argument);
}

TEST_CASE("Cover a range of share and recover combinations")
{
  uint32_t seed = 0;
  if (std::getenv("RNG_SEED") != nullptr)
  {
    std::string rng_seed(std::getenv("RNG_SEED"));
    std::from_chars(rng_seed.data(), rng_seed.data() + rng_seed.size(), seed);
  }
  if (seed == 0)
  {
    seed = std::random_device{}();
  }
  fmt::println("RNG Seed: {}", seed);

  std::mt19937 rng;
  rng.seed(seed);

  // Shares, Degree, Recoveries
  share_and_recover(rng, 1, 1, 1);
  share_and_recover(rng, 5, 1, 8);
  share_and_recover(rng, 10, 3, 8);
  share_and_recover(rng, 99, 6, 8);
  share_and_recover(rng, 30000, 100, 8);
  share_and_recover(rng, 200000, 400, 8);
}

TEST_CASE("Serialisation")
{
  Share share;
  share.x = 42;
  share.y[0] = 34;
  share.y[1] = 0;
  share.y[2] = 1;
  share.y[3] = 2;
  share.y[4] = 3;
  share.y[5] = 4;
  share.y[6] = 5;
  share.y[7] = 6;
  share.y[8] = 7;
  share.y[9] = 56;
  Share new_share(share.serialise());

  INFO(share.to_str());
  INFO(new_share.to_str());

  REQUIRE(share == new_share);
}

constexpr element prime = (1ul << 31) - 1ul; // a notorious Mersenne prime
static element reduce(element x)
{
  // Actually CT, as compiled by Clang 11+, but obviously not guaranteed to be
  // so
  return (x % prime);
}

TEST_CASE("Smoke test ct_reduce against reduce")
{
  for (size_t i = 0; i < (1ul << 16); ++i)
  {
    size_t under = prime * i - 1;
    size_t over = prime * i;
    size_t mid = prime * i + (prime / 2);

    REQUIRE_MESSAGE(reduce(under) == ct_reduce(under), std::to_string(under));
    REQUIRE_MESSAGE(reduce(over) == ct_reduce(over), std::to_string(over));
    REQUIRE_MESSAGE(reduce(mid) == ct_reduce(mid), std::to_string(mid));
  }
}