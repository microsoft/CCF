// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN

#include "consensus/ledger_enclave.h"
#include "consensus/test/ledger_stub.h"

#include <doctest/doctest.h>

#undef FAIL

using namespace consensus;

TEST_CASE("Enclave rejects malformed entries")
{
  const auto check_rejected = [](const std::vector<uint8_t>& entry) {
    {
      const auto* data = entry.data();
      auto size = entry.size();
      REQUIRE_THROWS_AS(LedgerEnclave::get_entry(data, size), std::logic_error);
    }

    {
      const auto* data = entry.data();
      auto size = entry.size();
      REQUIRE_THROWS_AS(
        LedgerEnclave::skip_entry(data, size), std::logic_error);
    }
  };

  SUBCASE("Truncated header")
  {
    check_rejected(
      std::vector<uint8_t>(ccf::kv::serialised_entry_header_size - 1));
  }

  SUBCASE("Claimed body exceeds buffer")
  {
    ccf::kv::SerialisedEntryHeader header;
    header.set_size(2);

    std::vector<uint8_t> entry(ccf::kv::serialised_entry_header_size + 1);
    auto* data = entry.data();
    auto size = entry.size();
    serialized::write(data, size, header);

    check_rejected(entry);
  }
}

TEST_CASE("Enclave submits owned ledger mutations")
{
  auto writer = std::make_shared<consensus::test::StubLedgerWriter>();
  LedgerEnclave enclave(writer);

  std::vector<uint8_t> entry = {'a', 'b', 'c'};
  enclave.put_entry(entry, true, 1, 1);
  entry[0] = 'z';

  REQUIRE(writer->appends.size() == 1);
  REQUIRE(writer->appends.front().entry == std::vector<uint8_t>{'a', 'b', 'c'});
  REQUIRE(writer->appends.front().committable);

  enclave.init(4, 2);
  enclave.truncate(3);
  enclave.commit(3);

  REQUIRE(
    writer->initialisations == std::vector<std::pair<Index, Index>>{{4, 2}});
  REQUIRE(
    writer->truncations == std::vector<std::pair<Index, bool>>{{3, false}});
  REQUIRE(writer->commits == std::vector<Index>{3});
}

TEST_CASE("Enclave rejects stopped ledger")
{
  auto writer = std::make_shared<consensus::test::StubLedgerWriter>();
  writer->accepting = false;
  LedgerEnclave enclave(writer);

  REQUIRE_THROWS_AS(
    enclave.put_entry(std::vector<uint8_t>{'a'}, false, 1, 1),
    std::logic_error);
  REQUIRE_THROWS_AS(enclave.init(), std::logic_error);
  REQUIRE_THROWS_AS(enclave.truncate(0), std::logic_error);
  REQUIRE_THROWS_AS(enclave.commit(0), std::logic_error);
}
