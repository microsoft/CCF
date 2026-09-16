// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "service/tables/identity_types.h"

#include "ccf/kv/unit.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <array>
#include <cstdint>
#include <doctest/doctest.h>
#include <limits>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

using IdentityTypeSerialiser =
  ccf::kv::serialisers::BlitSerialiser<ccf::IdentityType>;

static constexpr std::array<ccf::IdentityType, 2> IDENTITY_TYPES = {
  ccf::IdentityType::CLASSICAL, ccf::IdentityType::PQ};

TEST_CASE("CLASSICAL shares the serialised key of a single-Value table")
{
  // ServiceValue is a Map with a single entry, whose key is 8 null bytes. A
  // table keyed by IdentityType is therefore serialised identically to a
  // ServiceValue for as long as CLASSICAL is its only entry.
  REQUIRE(
    IdentityTypeSerialiser::to_serialised(ccf::IdentityType::CLASSICAL) ==
    ccf::kv::serialisers::ZeroBlitUnitCreator::get());

  REQUIRE(
    IdentityTypeSerialiser::to_serialised(ccf::IdentityType::PQ) !=
    ccf::kv::serialisers::ZeroBlitUnitCreator::get());
}

TEST_CASE("IdentityType serialisation round-trips")
{
  for (const auto identity_type : IDENTITY_TYPES)
  {
    const auto serialised =
      IdentityTypeSerialiser::to_serialised(identity_type);
    REQUIRE(serialised.size() == sizeof(uint64_t));
    REQUIRE(
      IdentityTypeSerialiser::from_serialised(serialised) == identity_type);
  }
}

TEST_CASE("Unknown identity types are rejected")
{
  const auto unknown =
    ccf::kv::serialisers::BlitSerialiser<uint64_t>::to_serialised(
      std::numeric_limits<uint64_t>::max());
  REQUIRE_THROWS_AS(
    IdentityTypeSerialiser::from_serialised(unknown), std::logic_error);
}

TEST_CASE("IdentityType names are distinct and stable")
{
  // These names will appear in the ledger, so they must not change.
  REQUIRE(nlohmann::json(ccf::IdentityType::CLASSICAL) == "CLASSICAL");
  REQUIRE(nlohmann::json(ccf::IdentityType::PQ) == "PQ");

  std::set<std::string> names;
  for (const auto identity_type : IDENTITY_TYPES)
  {
    const nlohmann::json name = identity_type;
    REQUIRE(names.insert(name.get<std::string>()).second);
  }
  REQUIRE(names.size() == IDENTITY_TYPES.size());
}

TEST_CASE("Identity round-trips through JSON")
{
  const ccf::Identity identity{
    ccf::IdentityKind::X509_SPKI_DER, std::vector<uint8_t>{1, 2, 3, 4}};

  const nlohmann::json j = identity;
  REQUIRE(j["kind"] == "X509_SPKI_DER");

  REQUIRE(j.get<ccf::Identity>() == identity);
}

TEST_CASE("Identities round-trips through JSON")
{
  const ccf::Identities identities{
    {ccf::IdentityType::CLASSICAL,
     {ccf::IdentityKind::X509_CERT_DER, std::vector<uint8_t>{1, 2}}},
    {ccf::IdentityType::PQ,
     {ccf::IdentityKind::X509_SPKI_DER, std::vector<uint8_t>{3, 4}}}};

  const nlohmann::json j = identities;
  REQUIRE(j.get<ccf::Identities>() == identities);
}
