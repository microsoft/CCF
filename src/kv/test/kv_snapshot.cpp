// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "kv/kv_serialiser.h"
#include "kv/store.h"
#include "kv/test/null_encryptor.h"
#include "kv/tx.h"

#include <doctest/doctest.h>
#undef FAIL

struct MapTypes
{
  using StringString = kv::Map<std::string, std::string>;
  using NumNum = kv::Map<size_t, size_t>;
};

TEST_CASE("Simple snapshot" * doctest::test_suite("snapshot"))
{
  kv::Store store;
  MapTypes::StringString string_map("public:string_map");
  MapTypes::NumNum num_map("public:num_map");

  kv::Version first_snapshot_version = kv::NoVersion;
  kv::Version second_snapshot_version = kv::NoVersion;

  INFO("Apply transactions to original store");
  {
    auto tx1 = store.create_tx();
    auto handle_1s = tx1.rw(string_map);
    handle_1s->put("foo", "bar");
    handle_1s->put("baz", "hello");
    auto handle_1n = tx1.rw(num_map);
    handle_1n->put(42, 100);
    REQUIRE(tx1.commit() == kv::CommitResult::SUCCESS);
    first_snapshot_version = tx1.commit_version();

    auto tx2 = store.create_tx();
    auto handle_2s = tx2.rw(string_map);
    handle_2s->remove("baz");
    auto handle_2n = tx2.rw(num_map);
    handle_2n->put(42, 123);
    REQUIRE(tx2.commit() == kv::CommitResult::SUCCESS);
    second_snapshot_version = tx2.commit_version();

    auto tx3 = store.create_tx();
    auto handle_3 = tx1.rw(string_map);
    handle_3->put("uncommitted", "not committed");
    // Do not commit tx3
  }

  auto first_snapshot = store.snapshot(first_snapshot_version);
  auto first_serialised_snapshot =
    store.serialise_snapshot(std::move(first_snapshot));

  INFO("Apply snapshot at 1 to new store");
  {
    kv::Store new_store;

    kv::ConsensusHookPtrs hooks;
    REQUIRE_EQ(
      new_store.deserialise_snapshot(first_serialised_snapshot, hooks),
      kv::ApplyResult::PASS);
    REQUIRE_EQ(new_store.current_version(), first_snapshot_version);

    auto tx1 = new_store.create_tx();
    {
      auto handle = tx1.rw(string_map);
      {
        auto v = handle->get("foo");
        REQUIRE(v.has_value());
        REQUIRE_EQ(v.value(), "bar");

        const auto ver = handle->get_version_of_previous_write("foo");
        REQUIRE(ver.has_value());
        REQUIRE_EQ(ver.value(), first_snapshot_version);
      }

      {
        auto v = handle->get("baz");
        REQUIRE(v.has_value());
        REQUIRE_EQ(v.value(), "hello");

        const auto ver = handle->get_version_of_previous_write("baz");
        REQUIRE(ver.has_value());
        REQUIRE_EQ(ver.value(), first_snapshot_version);
      }

      REQUIRE(!handle->has("uncommitted"));
    }

    {
      auto num_handle = tx1.rw(num_map);
      auto v = num_handle->get(42);
      REQUIRE(v.has_value());
      REQUIRE_EQ(v.value(), 100);

      const auto ver = num_handle->get_version_of_previous_write(42);
      REQUIRE(ver.has_value());
      REQUIRE_EQ(ver.value(), first_snapshot_version);
    }
  }

  auto second_snapshot = store.snapshot(second_snapshot_version);
  auto second_serialised_snapshot =
    store.serialise_snapshot(std::move(second_snapshot));

  INFO("Apply snapshot at 2 to new store");
  {
    kv::Store new_store;

    kv::ConsensusHookPtrs hooks;
    new_store.deserialise_snapshot(second_serialised_snapshot, hooks);
    REQUIRE_EQ(new_store.current_version(), second_snapshot_version);

    auto tx1 = new_store.create_tx();

    {
      auto handle = tx1.rw(string_map);

      {
        auto v = handle->get("foo");
        REQUIRE(v.has_value());
        REQUIRE_EQ(v.value(), "bar");

        const auto ver = handle->get_version_of_previous_write("foo");
        REQUIRE(ver.has_value());
        REQUIRE_EQ(ver.value(), first_snapshot_version);
      }

      {
        auto v = handle->get("baz");
        REQUIRE(!v.has_value());

        const auto ver = handle->get_version_of_previous_write("baz");
        REQUIRE(!ver.has_value());
      }

      REQUIRE(!handle->has("uncommitted"));
    }

    {
      auto num_handle = tx1.rw(num_map);
      auto num_v = num_handle->get(42);
      REQUIRE(num_v.has_value());
      REQUIRE_EQ(num_v.value(), 123);

      const auto ver = num_handle->get_version_of_previous_write(42);
      REQUIRE(ver.has_value());
      REQUIRE_EQ(ver.value(), second_snapshot_version);
    }
  }
}

TEST_CASE(
  "Commit transaction while applying snapshot" *
  doctest::test_suite("snapshot"))
{
  kv::Store store;
  MapTypes::StringString string_map("public:string_map");

  kv::Version snapshot_version = kv::NoVersion;
  INFO("Apply transactions to original store");
  {
    auto tx1 = store.create_tx();
    auto handle_1 = tx1.rw<MapTypes::StringString>("public:string_map");
    handle_1->put("foo", "foo");
    REQUIRE(tx1.commit() == kv::CommitResult::SUCCESS); // Committed at 1

    auto tx2 = store.create_tx();
    auto handle_2 = tx2.rw<MapTypes::StringString>("public:string_map");
    handle_2->put("bar", "bar");
    REQUIRE(tx2.commit() == kv::CommitResult::SUCCESS); // Committed at 2
    snapshot_version = tx2.commit_version();
  }

  auto snapshot = store.snapshot(snapshot_version);
  auto serialised_snapshot = store.serialise_snapshot(std::move(snapshot));

  INFO("Apply snapshot while committing a transaction");
  {
    kv::Store new_store;

    auto tx = new_store.create_tx();
    auto handle = tx.rw<MapTypes::StringString>("public:string_map");
    handle->put("in", "flight");
    // tx is not committed until the snapshot is deserialised

    kv::ConsensusHookPtrs hooks;
    new_store.deserialise_snapshot(serialised_snapshot, hooks);

    // Transaction conflicts as snapshot was applied while transaction was in
    // flight
    REQUIRE(tx.commit() == kv::CommitResult::FAIL_CONFLICT);

    // Try again
    auto tx2 = new_store.create_tx();
    auto handle2 = tx2.rw<MapTypes::StringString>("public:string_map");
    handle2->put("baz", "baz");
    REQUIRE(tx2.commit() == kv::CommitResult::SUCCESS);
  }
}

TEST_CASE("Commit hooks with snapshot" * doctest::test_suite("snapshot"))
{
  kv::Store store;
  constexpr auto string_map = "public:string_map";

  kv::Version snapshot_version = kv::NoVersion;
  INFO("Apply transactions to original store");
  {
    auto tx1 = store.create_tx();
    auto handle_1 = tx1.rw<MapTypes::StringString>(string_map);
    handle_1->put("foo", "foo");
    handle_1->put("bar", "bar");
    REQUIRE(tx1.commit() == kv::CommitResult::SUCCESS); // Committed at 1

    // New transaction, deleting content from the previous transaction
    auto tx2 = store.create_tx();
    auto handle_2 = tx2.rw<MapTypes::StringString>(string_map);
    handle_2->put("baz", "baz");
    handle_2->remove("bar");
    REQUIRE(tx2.commit() == kv::CommitResult::SUCCESS); // Committed at 2
    snapshot_version = tx2.commit_version();
  }

  auto snapshot = store.snapshot(snapshot_version);
  auto serialised_snapshot = store.serialise_snapshot(std::move(snapshot));

  INFO("Apply snapshot with local hook on target store");
  {
    kv::Store new_store;

    MapTypes::StringString new_string_map(string_map);

    using Write = MapTypes::StringString::Write;
    std::vector<Write> local_writes;
    std::vector<Write> global_writes;

    INFO("Set hooks on target store");
    {
      auto map_hook =
        [&](kv::Version v, const Write& w) -> kv::ConsensusHookPtr {
        local_writes.push_back(w);
        return kv::ConsensusHookPtr(nullptr);
      };
      auto global_hook = [&](kv::Version v, const Write& w) {
        global_writes.push_back(w);
      };

      new_store.set_map_hook(
        string_map, new_string_map.wrap_map_hook(map_hook));
      new_store.set_global_hook(
        string_map, new_string_map.wrap_commit_hook(global_hook));
    }

    kv::ConsensusHookPtrs hooks;
    new_store.deserialise_snapshot(serialised_snapshot, hooks);

    INFO("Verify content of snapshot");
    {
      auto tx = new_store.create_tx();
      auto handle = tx.rw<MapTypes::StringString>(string_map);
      REQUIRE(handle->get("foo").has_value());
      REQUIRE(!handle->get("bar").has_value());
      REQUIRE(handle->get("baz").has_value());
    }

    INFO("Verify local hook execution");
    {
      REQUIRE_EQ(local_writes.size(), 1);
      auto writes = local_writes.at(0);
      REQUIRE_EQ(writes.at("foo"), "foo");
      REQUIRE_EQ(writes.find("bar"), writes.end());
      REQUIRE_EQ(writes.at("baz"), "baz");
    }

    INFO("Verify global hook execution after compact");
    {
      new_store.compact(snapshot_version);

      REQUIRE_EQ(global_writes.size(), 1);
      auto writes = global_writes.at(0);
      REQUIRE_EQ(writes.at("foo"), "foo");
      REQUIRE_EQ(writes.find("bar"), writes.end());
      REQUIRE_EQ(writes.at("baz"), "baz");
    }
  }
}