// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "kv/kv_serialiser.h"
#include "kv/store.h"
#include "kv/test/null_encryptor.h"

#include <doctest/doctest.h>
#undef FAIL

struct MapTypes
{
  using StringString = kv::Map<std::string, std::string>;
  using NumNum = kv::Map<size_t, size_t>;
  using StringValue = kv::Value<std::string>;
  using StringSet = kv::Set<std::string>;
};

MapTypes::StringString string_map("public:string_map");
MapTypes::NumNum num_map("public:num_map");

TEST_CASE("Simple snapshot" * doctest::test_suite("snapshot"))
{
  kv::Store store;
  auto encryptor = std::make_shared<kv::NullTxEncryptor>();
  store.set_encryptor(encryptor);

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
    new_store.set_encryptor(encryptor);

    kv::ConsensusHookPtrs hooks;
    REQUIRE_EQ(
      new_store.deserialise_snapshot(
        first_serialised_snapshot.data(),
        first_serialised_snapshot.size(),
        hooks),
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

    new_store.set_encryptor(encryptor);

    kv::ConsensusHookPtrs hooks;
    new_store.deserialise_snapshot(
      second_serialised_snapshot.data(),
      second_serialised_snapshot.size(),
      hooks);
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

TEST_CASE("Old snapshots" * doctest::test_suite("snapshot"))
{
  // Test that this code can still parse snapshots produced by old versions of
  // the code
  // NB: These raw strings are base64 encodings from
  // `sencond_serialised_snapshot` in the "Simple snapshot" test
  std::string raw_snapshot_b64;
  SUBCASE("Tombstone deletions")
  {
    raw_snapshot_b64 =
      "AQDYAAAAAADQAAAAAAAAAAECAAAAAAAAAAAAAAAAAAAADgAAAAAAAABwdWJsaWM6bnVtX21h"
      "cAIAAAAAAAAAKAAAAAAAAAACAAAAAAAAADQyAAAAAAAACwAAAAAAAAACAAAAAAAAADEyMwAA"
      "AAAAEQAAAAAAAABwdWJsaWM6c3RyaW5nX21hcAIAAAAAAAAASAAAAAAAAAAFAAAAAAAAACJi"
      "YXoiAAAACAAAAAAAAAD+/////////"
      "wUAAAAAAAAAImZvbyIAAAANAAAAAAAAAAEAAAAAAAAAImJhciIAAAA=";
  }
  SUBCASE("True deletions")
  {
    raw_snapshot_b64 =
      "AQC4AAAAAACwAAAAAAAAAAECAAAAAAAAAAAAAAAAAAAADgAAAAAAAABwdWJsaWM6bnVtX21h"
      "cAIAAAAAAAAAKAAAAAAAAAACAAAAAAAAADQyAAAAAAAACwAAAAAAAAACAAAAAAAAADEyMwAA"
      "AAAAEQAAAAAAAABwdWJsaWM6c3RyaW5nX21hcAIAAAAAAAAAKAAAAAAAAAAFAAAAAAAAACJm"
      "b28iAAAADQAAAAAAAAABAAAAAAAAACJiYXIiAAAA";
  }
  const auto raw_snapshot = crypto::raw_from_b64(raw_snapshot_b64);

  kv::Store new_store;

  auto encryptor = std::make_shared<kv::NullTxEncryptor>();
  new_store.set_encryptor(encryptor);

  kv::ConsensusHookPtrs hooks;
  new_store.deserialise_snapshot(
    raw_snapshot.data(), raw_snapshot.size(), hooks);

  REQUIRE_EQ(new_store.current_version(), 2);

  {
    auto tx1 = new_store.create_tx();

    {
      auto handle = tx1.rw(string_map);

      {
        auto v = handle->get("foo");
        REQUIRE(v.has_value());
        REQUIRE_EQ(v.value(), "bar");

        const auto ver = handle->get_version_of_previous_write("foo");
        REQUIRE(ver.has_value());
        REQUIRE_EQ(ver.value(), 1);
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
      REQUIRE_EQ(ver.value(), 2);
    }
  }
}

TEST_CASE(
  "Commit transaction while applying snapshot" *
  doctest::test_suite("snapshot"))
{
  kv::Store store;
  auto encryptor = std::make_shared<kv::NullTxEncryptor>();
  store.set_encryptor(encryptor);

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
    new_store.set_encryptor(encryptor);

    auto tx = new_store.create_tx();
    auto handle = tx.rw<MapTypes::StringString>("public:string_map");
    handle->put("in", "flight");
    // tx is not committed until the snapshot is deserialised

    kv::ConsensusHookPtrs hooks;
    new_store.deserialise_snapshot(
      serialised_snapshot.data(), serialised_snapshot.size(), hooks);

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
  auto encryptor = std::make_shared<kv::NullTxEncryptor>();
  store.set_encryptor(encryptor);

  constexpr auto string_map = "public:string_map";
  constexpr auto string_value = "public:string_value";
  constexpr auto string_set = "public:string_set";

  kv::Version snapshot_version = kv::NoVersion;

  using MapWrite = MapTypes::StringString::Write;
  using ValueWrite = MapTypes::StringValue::Write;
  using SetWrite = MapTypes::StringSet::Write;
  std::vector<MapWrite> local_map_writes;
  std::vector<MapWrite> global_map_writes;
  std::vector<ValueWrite> local_value_writes;
  std::vector<ValueWrite> global_value_writes;
  std::vector<SetWrite> local_set_writes;
  std::vector<SetWrite> global_set_writes;

  auto map_hook =
    [&](kv::Version v, const MapWrite& w) -> kv::ConsensusHookPtr {
    local_map_writes.push_back(w);
    return kv::ConsensusHookPtr(nullptr);
  };
  auto global_map_hook = [&](kv::Version v, const MapWrite& w) {
    global_map_writes.push_back(w);
  };
  auto value_hook =
    [&](kv::Version v, const ValueWrite& w) -> kv::ConsensusHookPtr {
    local_value_writes.push_back(w);
    return kv::ConsensusHookPtr(nullptr);
  };
  auto global_value_hook = [&](kv::Version v, const ValueWrite& w) {
    global_value_writes.push_back(w);
  };
  auto set_hook =
    [&](kv::Version v, const SetWrite& w) -> kv::ConsensusHookPtr {
    local_set_writes.push_back(w);
    return kv::ConsensusHookPtr(nullptr);
  };
  auto global_set_hook = [&](kv::Version v, const SetWrite& w) {
    global_set_writes.push_back(w);
  };

  INFO("Apply transactions to original store");
  {
    {
      auto tx = store.create_tx();
      auto map_handle = tx.rw<MapTypes::StringString>(string_map);
      map_handle->put("foo", "foo");
      map_handle->put("bar", "bar");
      auto value_handle = tx.rw<MapTypes::StringValue>(string_value);
      value_handle->put("foo");
      auto set_handle = tx.rw<MapTypes::StringSet>(string_set);
      set_handle->insert("foo");
      set_handle->insert("bar");
      REQUIRE(tx.commit() == kv::CommitResult::SUCCESS); // Committed at 1
    }

    {
      // New transaction, deleting some content from the previous transaction
      auto tx = store.create_tx();
      auto map_handle = tx.rw<MapTypes::StringString>(string_map);
      map_handle->put("baz", "baz");
      map_handle->remove("bar");
      auto value_handle = tx.rw<MapTypes::StringValue>(string_value);
      value_handle->put("baz");
      auto set_handle = tx.rw<MapTypes::StringSet>(string_set);
      set_handle->insert("baz");
      set_handle->remove("bar");
      REQUIRE(tx.commit() == kv::CommitResult::SUCCESS); // Committed at 2
      snapshot_version = tx.commit_version();
    }
  }

  auto snapshot = store.snapshot(snapshot_version);
  auto serialised_snapshot = store.serialise_snapshot(std::move(snapshot));

  kv::Store new_store;
  new_store.set_encryptor(encryptor);

  MapTypes::StringString new_string_map(string_map);
  MapTypes::StringValue new_string_value(string_value);
  MapTypes::StringSet new_string_set(string_set);

  INFO("Set hooks on target store");
  {
    new_store.set_map_hook(string_map, new_string_map.wrap_map_hook(map_hook));
    new_store.set_global_hook(
      string_map, new_string_map.wrap_commit_hook(global_map_hook));
    new_store.set_map_hook(
      string_value, new_string_value.wrap_map_hook(value_hook));
    new_store.set_global_hook(
      string_value, new_string_value.wrap_commit_hook(global_value_hook));
    new_store.set_map_hook(string_set, new_string_set.wrap_map_hook(set_hook));
    new_store.set_global_hook(
      string_set, new_string_set.wrap_commit_hook(global_set_hook));
  }

  INFO("Apply snapshot with local hook on target store");
  {
    INFO("Deserialise snapshot");
    {
      kv::ConsensusHookPtrs hooks;
      new_store.deserialise_snapshot(
        serialised_snapshot.data(), serialised_snapshot.size(), hooks);
    }

    INFO("Verify content of snapshot");
    {
      auto tx = new_store.create_tx();
      auto map_handle = tx.ro<MapTypes::StringString>(string_map);
      REQUIRE(map_handle->get("foo").has_value());
      REQUIRE(!map_handle->get("bar").has_value());
      REQUIRE(map_handle->get("baz").has_value());
      auto value_handle = tx.ro<MapTypes::StringValue>(string_value);
      REQUIRE_EQ(value_handle->get().value(), "baz");
      auto set_handle = tx.rw<MapTypes::StringSet>(string_set);
      REQUIRE(set_handle->contains("foo"));
      REQUIRE(!set_handle->contains("bar"));
      REQUIRE(set_handle->contains("baz"));
    }

    INFO("Verify local hook execution");
    {
      {
        REQUIRE_EQ(local_map_writes.size(), 1);
        auto writes = local_map_writes.at(0);
        REQUIRE_EQ(writes.size(), 2);
        REQUIRE_EQ(writes.at("foo"), "foo");
        // Deletions are NOT passed to hook!
        REQUIRE_EQ(writes.find("bar"), writes.end());
        REQUIRE_EQ(writes.at("baz"), "baz");
        local_map_writes.clear();
      }

      {
        REQUIRE_EQ(local_value_writes.size(), 1);
        auto write = local_value_writes.at(0);
        REQUIRE(write.has_value());
        REQUIRE_EQ(write.value(), "baz");
        local_value_writes.clear();
      }

      {
        REQUIRE_EQ(local_set_writes.size(), 1);
        auto writes = local_set_writes.at(0);
        REQUIRE_EQ(writes.size(), 2);
        REQUIRE(writes.at("foo").has_value());
        // Deletions are NOT passed to hook!
        REQUIRE_EQ(writes.find("bar"), writes.end());
        REQUIRE(writes.at("baz").has_value());
        local_set_writes.clear();
      }
    }

    INFO("Verify global hook execution after compact");
    {
      new_store.compact(snapshot_version);

      {
        REQUIRE_EQ(global_map_writes.size(), 1);
        auto writes = global_map_writes.at(0);
        REQUIRE_EQ(writes.size(), 2);
        REQUIRE_EQ(writes.at("foo"), "foo");
        // Deletions are NOT passed to hook!
        REQUIRE_EQ(writes.find("bar"), writes.end());
        REQUIRE_EQ(writes.at("baz"), "baz");
        global_map_writes.clear();
      }

      {
        REQUIRE_EQ(global_value_writes.size(), 1);
        auto write = global_value_writes.at(0);
        REQUIRE(write.has_value());
        REQUIRE_EQ(write.value(), "baz");
        global_value_writes.clear();
      }

      {
        REQUIRE_EQ(global_set_writes.size(), 1);
        auto writes = global_set_writes.at(0);
        REQUIRE_EQ(writes.size(), 2);
        REQUIRE(writes.at("foo").has_value());
        // Deletions are NOT passed to hook!
        REQUIRE_EQ(writes.find("bar"), writes.end());
        REQUIRE(writes.at("baz").has_value());
        global_set_writes.clear();
      }
    }
  }

  INFO(
    "Remove all elements in source store and deserialise resulting snapshot");
  {
    auto tx = store.create_tx();
    auto map_handle = tx.rw<MapTypes::StringString>(string_map);
    map_handle->clear();
    auto value_handle = tx.rw<MapTypes::StringValue>(string_value);
    value_handle->clear();
    auto set_handle = tx.rw<MapTypes::StringSet>(string_set);
    set_handle->clear();
    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
    snapshot_version = tx.commit_version();
    snapshot = store.snapshot(snapshot_version);
    serialised_snapshot = store.serialise_snapshot(std::move(snapshot));

    kv::ConsensusHookPtrs hooks;
    new_store.deserialise_snapshot(
      serialised_snapshot.data(), serialised_snapshot.size(), hooks);

    INFO("Verify content of snapshot");
    {
      auto tx = new_store.create_tx();
      auto map_handle = tx.ro<MapTypes::StringString>(string_map);
      REQUIRE(!map_handle->get("foo").has_value());
      REQUIRE(!map_handle->get("bar").has_value());
      REQUIRE(!map_handle->get("baz").has_value());
      auto value_handle = tx.ro<MapTypes::StringValue>(string_value);
      REQUIRE(!value_handle->get().has_value());
      auto set_handle = tx.rw<MapTypes::StringSet>(string_set);
      REQUIRE(!set_handle->contains("foo"));
      REQUIRE(!set_handle->contains("bar"));
      REQUIRE(!set_handle->contains("baz"));
    }

    INFO("Verify local hook execution");
    {
      {
        REQUIRE_EQ(local_map_writes.size(), 0);
        local_map_writes.clear();
      }

      {
        REQUIRE_EQ(local_value_writes.size(), 0);
        local_value_writes.clear();
      }

      {
        REQUIRE_EQ(local_set_writes.size(), 0);
        local_set_writes.clear();
      }
    }

    INFO("Verify global hook execution after compact");
    {
      new_store.compact(snapshot_version);

      {
        REQUIRE_EQ(global_map_writes.size(), 0);
        global_map_writes.clear();
      }

      {
        REQUIRE_EQ(global_value_writes.size(), 0);
        global_value_writes.clear();
      }

      {
        REQUIRE_EQ(global_set_writes.size(), 0);
        global_set_writes.clear();
      }
    }
  }
}