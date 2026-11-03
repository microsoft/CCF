// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "node/retry_on_compacted_version_conflict.h"

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

TEST_CASE("Retries after a transient compaction conflict")
{
  std::size_t attempts = 0;
  const bool completed =
    ccf::retry_on_compacted_version_conflict("Test lookup", [&] {
      ++attempts;
      if (attempts == 1)
      {
        throw ccf::kv::CompactedVersionConflict("compacted");
      }
    });

  REQUIRE(completed);
  REQUIRE(attempts == 2);
}

TEST_CASE("Stops after a bounded number of compaction conflicts")
{
  std::size_t attempts = 0;
  const bool completed =
    ccf::retry_on_compacted_version_conflict("Test lookup", [&] {
      ++attempts;
      throw ccf::kv::CompactedVersionConflict("compacted");
    });

  REQUIRE_FALSE(completed);
  REQUIRE(attempts == 3);
}

TEST_CASE("Propagates unrelated exceptions without retrying")
{
  std::size_t attempts = 0;
  REQUIRE_THROWS_AS(
    static_cast<void>(ccf::retry_on_compacted_version_conflict(
      "Test lookup",
      [&] {
        ++attempts;
        throw std::runtime_error("unexpected");
      })),
    std::runtime_error);
  REQUIRE(attempts == 1);
}

namespace
{
  struct CompactingStore
  {
    ccf::kv::Store store;
    ccf::kv::Map<std::string, std::size_t> first{"public:first"};
    ccf::kv::Map<std::string, std::size_t> second{"public:second"};
    const std::string key = "k";
    std::size_t next_value = 0;

    CompactingStore()
    {
      store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());
      write_both();
    }

    // Commits a write to both maps, as a concurrent transaction would
    void write_both()
    {
      auto tx = store.create_tx();
      tx.rw(first)->put(key, next_value);
      tx.rw(second)->put(key, next_value);
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
      ++next_value;
    }

    // Overtakes the read version of any transaction which has already
    // created a handle, so that its next handle creation over a map written
    // here throws the genuine CompactedVersionConflict
    void write_both_and_compact()
    {
      write_both();
      store.compact(store.current_version());
    }
  };
}

TEST_CASE("Read-only transaction recovers from a KV compaction conflict")
{
  CompactingStore cs;

  std::size_t attempts = 0;
  std::optional<std::size_t> value;
  const bool completed =
    ccf::retry_on_compacted_version_conflict("Test lookup", [&] {
      ++attempts;
      auto tx = cs.store.create_read_only_tx();
      tx.ro(cs.first);
      if (attempts == 1)
      {
        cs.write_both_and_compact();
      }
      value = tx.ro(cs.second)->get(cs.key);
    });

  REQUIRE(completed);
  REQUIRE(attempts == 2);
  REQUIRE(value == 1U);
}

TEST_CASE("Write transaction conflicting on a later handle commits once")
{
  CompactingStore cs;
  const auto version_before = cs.store.current_version();

  std::size_t attempts = 0;
  std::size_t commits = 0;
  const bool completed =
    ccf::retry_on_compacted_version_conflict("Test transaction", [&] {
      ++attempts;
      auto tx = cs.store.create_tx();
      tx.rw(cs.first)->put(cs.key, 42);
      if (attempts == 1)
      {
        cs.write_both_and_compact();
      }
      tx.rw(cs.second)->put(cs.key, 43);
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
      ++commits;
    });

  REQUIRE(completed);
  REQUIRE(attempts == 2);
  REQUIRE(commits == 1);
  // Only the concurrent write and the single successful commit were applied
  REQUIRE(cs.store.current_version() == version_before + 2);

  auto tx = cs.store.create_read_only_tx();
  REQUIRE(tx.ro(cs.first)->get(cs.key) == 42U);
  REQUIRE(tx.ro(cs.second)->get(cs.key) == 43U);
}
