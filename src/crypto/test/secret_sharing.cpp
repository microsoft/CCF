// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <random>

#define FMT_HEADER_ONLY
#include "crypto/sharing.h"

#include <fmt/format.h>

using namespace crypto;

void share_and_recover(size_t num_shares, size_t degree, size_t recoveries)
{
  std::vector<Share> shares(num_shares);

  Share secret;
  sample_secret_and_shares(secret, shares, degree);

  std::mt19937 rng{std::random_device{}()};

  for (size_t i = 0; i < recoveries; ++i)
  {
    std::vector<Share> recovered_shares;
    std::sample(
      shares.begin(),
      shares.end(),
      std::back_inserter(recovered_shares),
      degree + 1,
      rng);
    {
      Share recovered;
      recover_secret(recovered, recovered_shares, degree);
      INFO(fmt::format(
        "Recovering secret of degree {} from {} shares",
        degree,
        recovered_shares.size()));
      REQUIRE(secret == recovered);
    }

    {
      Share recovered;
      recovered_shares.pop_back();
      INFO(fmt::format(
        "Recovering secret of degree {} from {} shares",
        degree,
        recovered_shares.size()));
      REQUIRE_THROWS_AS(
        recover_secret(recovered, recovered_shares, degree),
        std::invalid_argument);
    }
  }
}

TEST_CASE("There must be at least one share")
{
  std::vector<Share> shares(0);

  Share secret, recovered;
  REQUIRE_THROWS_AS(sample_secret_and_shares(secret, shares, 3), std::invalid_argument);
}

TEST_CASE("Simple sharing and recovery")
{
  constexpr size_t num_shares = 10;
  constexpr size_t degree = 3;

  std::vector<Share> shares(num_shares);

  Share secret, recovered;
  sample_secret_and_shares(secret, shares, degree);

  recover_secret(recovered, shares, degree);
  REQUIRE(secret == recovered);
}

TEST_CASE("Simple sharing and recovery with duplicate shares")
{
  constexpr size_t num_shares = 10;
  constexpr size_t degree = 3;

  std::vector<Share> shares(num_shares);

  Share secret, recovered;
  sample_secret_and_shares(secret, shares, degree);

  std::vector<Share> shares_with_duplicates(degree + 1, shares[0]);
  REQUIRE_THROWS_AS(
    recover_secret(recovered, shares_with_duplicates, degree),
    std::invalid_argument);
}

TEST_CASE("Cover a range of share and recover combinations")
{
  // Shares, Degree, Recoveries
  share_and_recover(1, 0, 1);
  share_and_recover(5, 0, 8);
  share_and_recover(10, 2, 8);
  share_and_recover(99, 5, 8);
  share_and_recover(30000, 100, 8);
  share_and_recover(200000, 400, 8);
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