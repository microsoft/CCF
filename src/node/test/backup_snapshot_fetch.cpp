// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "node/backup_snapshot_fetch.h"

#include <cstddef>
#include <stdexcept>

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

TEST_CASE("Backup snapshot lookup retries after compaction conflict")
{
  std::size_t attempts = 0;
  const bool succeeded = ccf::node::retry_backup_snapshot_lookup([&] {
    ++attempts;
    if (attempts == 1)
    {
      throw ccf::kv::CompactedVersionConflict("compacted");
    }
  });

  REQUIRE(succeeded);
  REQUIRE(attempts == 2);
}

TEST_CASE("Backup snapshot lookup stops after bounded compaction retries")
{
  std::size_t attempts = 0;
  const bool succeeded = ccf::node::retry_backup_snapshot_lookup([&] {
    ++attempts;
    throw ccf::kv::CompactedVersionConflict("compacted");
  });

  REQUIRE_FALSE(succeeded);
  REQUIRE(attempts == 3);
}

TEST_CASE("Backup snapshot lookup propagates unrelated exceptions")
{
  std::size_t attempts = 0;
  REQUIRE_THROWS_AS(
    ccf::node::retry_backup_snapshot_lookup([&] {
      ++attempts;
      throw std::runtime_error("unexpected");
    }),
    std::runtime_error);
  REQUIRE(attempts == 1);
}
