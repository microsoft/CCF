// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "node/backup_snapshot_fetch.h"

#include "ccf/kv/map.h"
#include "kv/null_encryptor.h"
#include "kv/store.h"

#include <cstddef>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>

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
    static_cast<void>(ccf::node::retry_backup_snapshot_lookup([&] {
      ++attempts;
      throw std::runtime_error("unexpected");
    })),
    std::runtime_error);
  REQUIRE(attempts == 1);
}

TEST_CASE("Backup snapshot lookup recovers from a KV compaction conflict")
{
  ccf::kv::Store store;
  store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());
  ccf::kv::Map<std::string, std::size_t> pin("public:pin");
  ccf::kv::Map<std::string, std::size_t> nodes("public:nodes");
  const std::string key = "primary";

  std::size_t next_value = 0;
  auto write_both = [&]() {
    auto tx = store.create_tx();
    tx.rw(pin)->put(key, next_value);
    tx.rw(nodes)->put(key, next_value);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    ++next_value;
  };
  write_both();

  std::size_t attempts = 0;
  std::optional<std::size_t> value;
  const bool succeeded = ccf::node::retry_backup_snapshot_lookup([&] {
    ++attempts;
    auto tx = store.create_read_only_tx();
    // Pin the read version through another map, then advance and compact the
    // store before the nodes handle is created, as a concurrent compaction
    // would. The nodes handle then throws the real CompactedVersionConflict.
    tx.ro(pin);
    if (attempts == 1)
    {
      write_both();
      store.compact(store.current_version());
    }
    value = tx.ro(nodes)->get(key);
  });

  REQUIRE(succeeded);
  REQUIRE(attempts == 2);
  REQUIRE(value == 1U);
}
