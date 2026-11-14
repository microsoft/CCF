// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <random>

#define FMT_HEADER_ONLY
#include "crypto/sharing.h"

#include <array>
#include <bit>
#include <charconv>
#include <fmt/format.h>
#include <limits>

namespace ccf::crypto::sharing
{
  // The backend that is not selected by USE_RUST_SHAMIR, see sharing_reference
  // in CMakeLists.txt.
  element reference_ct_reduce(element x);

  void reference_sample_secret_and_shares(
    Share& raw_secret, const std::span<Share>& shares, size_t threshold);

  void reference_recover_unauthenticated_secret(
    Share& raw_secret, const std::span<Share const>& shares, size_t threshold);
}

using namespace ccf::crypto::sharing;

// Every behaviour is checked for both backends, whichever one is selected.
struct Backend
{
  const char* name;
  element (*reduce)(element);
  void (*sample)(Share&, const std::span<Share>&, size_t);
  void (*recover)(Share&, const std::span<Share const>&, size_t);
};

static const std::array<Backend, 2> backends = {
  Backend{
    "selected",
    &ct_reduce,
    &sample_secret_and_shares,
    &recover_unauthenticated_secret},
  Backend{
    "reference",
    &reference_ct_reduce,
    &reference_sample_secret_and_shares,
    &reference_recover_unauthenticated_secret}};

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
  const Backend& backend,
  std::mt19937& rng,
  size_t num_shares,
  size_t threshold,
  size_t recoveries)
{
  fmt::println(
    "Testing {} shares with threshold {} for {} recoveries ({} backend)",
    num_shares,
    threshold,
    recoveries,
    backend.name);
  std::vector<Share> shares(num_shares);

  Share secret;
  backend.sample(secret, shares, threshold);
  REQUIRE(secret.x == 0);

  for (size_t i = 0; i < num_shares; ++i)
  {
    REQUIRE(shares[i].x == i + 1);
    check_share_is_not_trivially_wrong(shares[i]);
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
      backend.recover(recovered, recovered_shares, threshold);
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
        backend.recover(recovered, recovered_shares, threshold),
        std::invalid_argument);
    }
  }
}

static std::mt19937 seeded_rng()
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
  return rng;
}

TEST_CASE("The number of shares needs to allow recovery")
{
  for (const auto& backend : backends)
  {
    INFO(backend.name);
    std::vector<Share> shares(0);

    Share secret, recovered;
    REQUIRE_THROWS_AS(backend.sample(secret, shares, 3), std::invalid_argument);

    shares.resize(3);
    REQUIRE_THROWS_AS(backend.sample(secret, shares, 4), std::invalid_argument);
    REQUIRE_THROWS_AS(backend.sample(secret, shares, 0), std::invalid_argument);
  }
}

TEST_CASE("Simple sharing and recovery")
{
  constexpr size_t num_shares = 10;
  constexpr size_t threshold = 3;

  for (const auto& backend : backends)
  {
    INFO(backend.name);
    std::vector<Share> shares(num_shares);

    Share secret, recovered;
    backend.sample(secret, shares, threshold);

    backend.recover(recovered, shares, threshold);
    REQUIRE(secret == recovered);
  }
}

TEST_CASE("Simple sharing and recovery with duplicate shares")
{
  constexpr size_t num_shares = 10;
  constexpr size_t threshold = 3;

  for (const auto& backend : backends)
  {
    INFO(backend.name);
    std::vector<Share> shares(num_shares);

    Share secret, recovered;
    backend.sample(secret, shares, threshold);

    std::vector<Share> shares_with_duplicates(threshold, shares[0]);
    REQUIRE_THROWS_AS(
      backend.recover(recovered, shares_with_duplicates, threshold),
      std::invalid_argument);
  }
}

TEST_CASE("Recovery rejects zero threshold without changing output")
{
  for (const auto& backend : backends)
  {
    INFO(backend.name);
    Share recovered;
    recovered.x = 42;
    recovered.y[0] = 17;
    const Share before = recovered;
    REQUIRE_THROWS_AS(backend.recover(recovered, {}, 0), std::invalid_argument);
    REQUIRE(recovered == before);
  }
}

TEST_CASE("Recovery preserves legacy field reduction and ignores extra shares")
{
  constexpr uint32_t field_prime = (1U << 31) - 1;
  for (const auto& backend : backends)
  {
    INFO(backend.name);
    std::vector<Share> shares(3);
    shares[0].x = field_prime + 1;
    shares[1].x = field_prime + 2;
    shares[2].x = shares[0].x;
    for (size_t limb = 0; limb < LIMBS; ++limb)
    {
      shares[0].y[limb] = field_prime + 16;
      shares[1].y[limb] = field_prime + 23;
    }
    Share recovered;
    backend.recover(recovered, shares, 2);
    REQUIRE(recovered.x == 0);
    for (const auto value : recovered.y)
    {
      REQUIRE(value == 9);
    }
    shares[1].x = 1;
    const Share before = recovered;
    REQUIRE_THROWS_AS(
      backend.recover(recovered, shares, 2), std::invalid_argument);
    REQUIRE(recovered == before);
  }
}

TEST_CASE("Cover a range of share and recover combinations")
{
  auto rng = seeded_rng();

  for (const auto& backend : backends)
  {
    // Shares, Degree, Recoveries
    share_and_recover(backend, rng, 1, 1, 1);
    share_and_recover(backend, rng, 5, 1, 8);
    share_and_recover(backend, rng, 10, 3, 8);
    share_and_recover(backend, rng, 99, 6, 8);
    share_and_recover(backend, rng, 30000, 100, 8);
    share_and_recover(backend, rng, 200000, 400, 8);
  }
}

TEST_CASE("Backends agree on arbitrary recovery inputs")
{
  // The member who submits a recovery share is authenticated, but the
  // contents of the share are not validated, so both backends must treat
  // every input identically, including coordinates and values that are not
  // canonical field elements.
  constexpr uint32_t field_prime = (1U << 31) - 1;
  constexpr std::array<uint32_t, 8> edge_values = {
    0,
    1,
    2,
    field_prime - 1,
    field_prime,
    field_prime + 1,
    2 * field_prime,
    std::numeric_limits<uint32_t>::max()};
  auto rng = seeded_rng();
  std::uniform_int_distribution<uint32_t> any_value;
  std::uniform_int_distribution<size_t> any_edge(0, edge_values.size() - 1);
  std::uniform_int_distribution<size_t> any_threshold(1, 6);
  std::bernoulli_distribution use_edge(0.5);
  const auto next = [&]() {
    return use_edge(rng) ? edge_values.at(any_edge(rng)) : any_value(rng);
  };

  size_t recovered_count = 0;
  size_t rejected_count = 0;
  for (size_t iteration = 0; iteration < 20000; ++iteration)
  {
    const auto threshold = any_threshold(rng);
    // One share more than the threshold, which must be ignored.
    std::vector<Share> shares(threshold + 1);
    for (auto& share : shares)
    {
      share.x = next();
      for (auto& limb : share.y)
      {
        limb = next();
      }
    }

    std::array<Share, backends.size()> outputs;
    std::array<bool, backends.size()> rejected = {};
    for (size_t b = 0; b < backends.size(); ++b)
    {
      outputs.at(b).x = 42;
      outputs.at(b).y[0] = 17;
      try
      {
        backends.at(b).recover(outputs.at(b), shares, threshold);
      }
      catch (const std::invalid_argument&)
      {
        rejected.at(b) = true;
      }
    }
    INFO(iteration);
    REQUIRE(rejected[0] == rejected[1]);
    REQUIRE(outputs[0] == outputs[1]);
    if (rejected[0])
    {
      ++rejected_count;
      REQUIRE(outputs[0].x == 42);
      REQUIRE(outputs[0].y[0] == 17);
    }
    else
    {
      ++recovered_count;
      REQUIRE(outputs[0].x == 0);
      for (const auto limb : outputs[0].y)
      {
        REQUIRE(limb < field_prime);
      }
    }
  }
  // Both outcomes must be exercised for the comparison to be meaningful.
  REQUIRE(recovered_count > 0);
  REQUIRE(rejected_count > 0);
}

TEST_CASE("C++ and Rust exchange serialized shares and derive identical keys")
{
  constexpr size_t num_shares = 7;
  for (size_t direction = 0; direction < backends.size(); ++direction)
  {
    const auto generate = backends.at(direction).sample;
    const auto recover = backends.at(1 - direction).recover;
    for (size_t threshold = 1; threshold <= num_shares; ++threshold)
    {
      INFO(direction);
      INFO(threshold);
      Share secret;
      std::vector<Share> shares(num_shares);
      generate(secret, shares, threshold);
      std::vector<uint8_t> secret_bytes(Share::serialised_size);
      secret.serialise(secret_bytes);
      const auto expected_key = secret.key(32);

      std::array<Share, 1> full_share = {Share(secret_bytes)};
      Share recovered_full;
      recover(recovered_full, full_share, 1);
      REQUIRE(recovered_full == secret);
      REQUIRE(recovered_full.key(32) == expected_key);

      for (unsigned mask = 1; mask < (1U << num_shares); ++mask)
      {
        if (static_cast<size_t>(std::popcount(mask)) != threshold)
        {
          continue;
        }
        INFO(mask);
        std::vector<Share> subset;
        for (size_t i = 0; i < num_shares; ++i)
        {
          if ((mask & (1U << i)) != 0)
          {
            std::vector<uint8_t> bytes(Share::serialised_size);
            shares[i].serialise(bytes);
            subset.emplace_back(bytes);
            std::vector<uint8_t> round_trip(Share::serialised_size);
            subset.back().serialise(round_trip);
            REQUIRE(round_trip == bytes);
          }
        }
        Share recovered;
        recover(recovered, subset, threshold);
        REQUIRE(recovered == secret);
        REQUIRE(recovered.key(32) == expected_key);
        std::vector<uint8_t> recovered_bytes(Share::serialised_size);
        recovered.serialise(recovered_bytes);
        REQUIRE(recovered_bytes == secret_bytes);
      }
    }
  }
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
  std::vector<uint8_t> serialised(share.serialised_size);
  share.serialise(serialised);
  const std::vector<uint8_t> expected = {
    42, 0, 0, 0, 34, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0,  0, 3, 0,
    0,  0, 4, 0, 0,  0, 5, 0, 0, 0, 6, 0, 0, 0, 7, 0, 0, 0, 56, 0, 0, 0};
  REQUIRE(serialised == expected);
  Share new_share(serialised);

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
  for (const auto& backend : backends)
  {
    INFO(backend.name);
    for (size_t i = 0; i < (1ul << 16); ++i)
    {
      size_t under = prime * i - 1;
      size_t over = prime * i;
      size_t mid = prime * i + (prime / 2);

      REQUIRE_MESSAGE(
        reduce(under) == backend.reduce(under), std::to_string(under));
      REQUIRE_MESSAGE(
        reduce(over) == backend.reduce(over), std::to_string(over));
      REQUIRE_MESSAGE(reduce(mid) == backend.reduce(mid), std::to_string(mid));
    }
    for (const element x :
         {element{0},
          element{1},
          prime - 1,
          prime,
          prime + 1,
          std::numeric_limits<element>::max() - 1,
          std::numeric_limits<element>::max()})
    {
      REQUIRE_MESSAGE(reduce(x) == backend.reduce(x), std::to_string(x));
    }
  }
}
