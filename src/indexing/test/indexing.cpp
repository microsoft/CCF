// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "indexing/indexer.h"
#include "indexing/seqnos_by_key.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

TEST_CASE("foo")
{
  indexing::Indexer indexer;

  REQUIRE_THROWS(indexer.install_strategy(nullptr));

  indexer.install_strategy(
    std::make_unique<indexing::strategies::SeqnosByKey>("hello"));

  std::vector<uint8_t> entry;
  entry.push_back(1);
  entry.push_back(2);
  entry.push_back(3);
  indexer.append_entry({0, 0}, entry.data(), entry.size());
}
