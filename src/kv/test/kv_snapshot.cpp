// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "kv/kv_serialiser.h"
#include "kv/null_encryptor.h"
#include "kv/store.h"
#include "node/encryptor.h"

#include <algorithm>
#include <cstring>
#include <doctest/doctest.h>
#include <functional>
#undef FAIL
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

struct MapTypes
{
  using StringString = ccf::kv::Map<std::string, std::string>;
  using NumNum = ccf::kv::Map<size_t, size_t>;
  using StringValue = ccf::kv::Value<std::string>;
  using StringSet = ccf::kv::Set<std::string>;
};

MapTypes::StringString string_map("public:string_map");
MapTypes::NumNum num_map("public:num_map");

TEST_CASE(
  "Snapshots are not subject to the transaction size limit" *
  doctest::test_suite("snapshot"))
{
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();

  ccf::kv::Store store;
  store.set_encryptor(encryptor);

  // A deliberately small per-transaction limit.
  constexpr size_t small_limit = 512;
  store.set_max_transaction_size(small_limit);

  // Accumulate committed state larger than the limit across several
  // transactions, each of which individually stays under the limit.
  constexpr size_t num_entries = 32;
  constexpr size_t value_size = 64;
  ccf::kv::Version snapshot_version = ccf::kv::NoVersion;
  for (size_t i = 0; i < num_entries; ++i)
  {
    auto tx = store.create_tx();
    auto handle = tx.rw(string_map);
    handle->put("key_" + std::to_string(i), std::string(value_size, 'x'));
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    snapshot_version = tx.commit_version();
  }
  REQUIRE(num_entries * value_size > small_limit);

  std::unique_ptr<ccf::kv::AbstractStore::AbstractSnapshot> snapshot = nullptr;
  {
    ccf::kv::ScopedStoreMapsLock maps_lock(&store);
    snapshot = store.snapshot_unsafe_maps(snapshot_version);
  }

  // Serialising a snapshot larger than the per-transaction limit must not be
  // rejected by that limit.
  std::vector<uint8_t> serialised_snapshot;
  REQUIRE_NOTHROW(
    serialised_snapshot = store.serialise_snapshot(std::move(snapshot)));

  // And it can be read back into a store configured with the same small limit.
  ccf::kv::Store new_store;
  new_store.set_encryptor(encryptor);
  new_store.set_max_transaction_size(small_limit);

  ccf::kv::ConsensusHookPtrs hooks;
  REQUIRE_EQ(
    new_store.deserialise_snapshot(
      serialised_snapshot.data(), serialised_snapshot.size(), hooks),
    ccf::kv::ApplyResult::PASS);
  REQUIRE_EQ(new_store.current_version(), snapshot_version);
}

TEST_CASE(
  "Encrypted snapshot replays both domains" * doctest::test_suite("snapshot"))
{
  auto secrets = std::make_shared<ccf::LedgerSecrets>();
  secrets->init();
  auto encryptor = std::make_shared<ccf::NodeEncryptor>(secrets);
  ccf::kv::Store source;
  source.set_encryptor(encryptor);

  MapTypes::StringString private_map("private_map");
  auto tx = source.create_tx();
  tx.rw(string_map)->put("public", "value");
  tx.rw(private_map)->put("private", "secret");
  REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  const auto snapshot_version = tx.commit_version();
  secrets->set_secret(snapshot_version + 1, ccf::make_ledger_secret());

  std::unique_ptr<ccf::kv::AbstractStore::AbstractSnapshot> snapshot;
  {
    ccf::kv::ScopedStoreMapsLock maps_lock(&source);
    snapshot = source.snapshot_unsafe_maps(snapshot_version);
  }
  auto entry = source.serialise_snapshot(std::move(snapshot));

  ccf::kv::Store recovered;
  recovered.set_encryptor(encryptor);
  ccf::kv::ConsensusHookPtrs hooks;
  REQUIRE(
    recovered.deserialise_snapshot(entry.data(), entry.size(), hooks) ==
    ccf::kv::ApplyResult::PASS);
  auto recovered_tx = recovered.create_tx();
  REQUIRE(recovered_tx.ro(string_map)->get("public") == "value");
  REQUIRE(recovered_tx.ro(private_map)->get("private") == "secret");
}

TEST_CASE("Simple snapshot" * doctest::test_suite("snapshot"))
{
  ccf::kv::Store store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  store.set_encryptor(encryptor);

  ccf::kv::Version first_snapshot_version = ccf::kv::NoVersion;
  ccf::kv::Version second_snapshot_version = ccf::kv::NoVersion;

  INFO("Apply transactions to original store");
  {
    auto tx1 = store.create_tx();
    auto handle_1s = tx1.rw(string_map);
    handle_1s->put("foo", "bar");
    handle_1s->put("baz", "hello");
    auto handle_1n = tx1.rw(num_map);
    handle_1n->put(42, 100);
    REQUIRE(tx1.commit() == ccf::kv::CommitResult::SUCCESS);
    first_snapshot_version = tx1.commit_version();

    auto tx2 = store.create_tx();
    auto handle_2s = tx2.rw(string_map);
    handle_2s->remove("baz");
    auto handle_2n = tx2.rw(num_map);
    handle_2n->put(42, 123);
    REQUIRE(tx2.commit() == ccf::kv::CommitResult::SUCCESS);
    second_snapshot_version = tx2.commit_version();

    auto tx3 = store.create_tx();
    auto handle_3 = tx1.rw(string_map);
    handle_3->put("uncommitted", "not committed");
    // Do not commit tx3
  }

  std::unique_ptr<ccf::kv::AbstractStore::AbstractSnapshot> first_snapshot =
    nullptr;
  {
    ccf::kv::ScopedStoreMapsLock maps_lock(&store);
    first_snapshot = store.snapshot_unsafe_maps(first_snapshot_version);
  }
  auto first_serialised_snapshot =
    store.serialise_snapshot(std::move(first_snapshot));

  INFO("Apply snapshot at 1 to new store");
  {
    ccf::kv::Store new_store;
    new_store.set_encryptor(encryptor);

    ccf::kv::ConsensusHookPtrs hooks;
    REQUIRE_EQ(
      new_store.deserialise_snapshot(
        first_serialised_snapshot.data(),
        first_serialised_snapshot.size(),
        hooks),
      ccf::kv::ApplyResult::PASS);
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

  std::unique_ptr<ccf::kv::AbstractStore::AbstractSnapshot> second_snapshot =
    nullptr;
  {
    ccf::kv::ScopedStoreMapsLock maps_lock(&store);
    second_snapshot = store.snapshot_unsafe_maps(second_snapshot_version);
  }
  auto second_serialised_snapshot =
    store.serialise_snapshot(std::move(second_snapshot));

  INFO("Apply snapshot at 2 to new store");
  {
    ccf::kv::Store new_store;

    new_store.set_encryptor(encryptor);

    ccf::kv::ConsensusHookPtrs hooks;
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
  // `second_serialised_snapshot` in the "Simple snapshot" test
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
  const auto raw_snapshot = ccf::crypto::raw_from_b64(raw_snapshot_b64);

  ccf::kv::Store new_store;

  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  new_store.set_encryptor(encryptor);

  ccf::kv::ConsensusHookPtrs hooks;
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

TEST_CASE("Malformed snapshots are rejected" * doctest::test_suite("snapshot"))
{
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();

  // The target already has maps, which deserialise_snapshot() locks while it
  // parses a snapshot, and must release however that ends
  ccf::kv::Store target;
  target.set_encryptor(encryptor);
  MapTypes::StringString private_map("private_map");
  {
    auto tx = target.create_tx();
    tx.rw(string_map)->put("public", "before");
    tx.rw(private_map)->put("private", "before");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  // Serialises a snapshot containing an empty map snapshot for each of
  // map_names in turn
  auto serialise_snapshot =
    [&encryptor](const std::vector<std::string>& map_names) {
      ccf::kv::RawKvStoreSerialiser serialiser(
        encryptor, ccf::TxID{0, 1}, ccf::kv::EntryType::Snapshot, 0);
      for (const auto& map_name : map_names)
      {
        serialiser.start_map(map_name, ccf::kv::SecurityDomain::PUBLIC);
        serialiser.serialise_entry_version(0);
        serialiser.serialise_raw({});
      }
      return serialiser.get_raw_data();
    };

  SUBCASE("Duplicate writes for the same map")
  {
    auto data =
      serialise_snapshot({string_map.get_name(), string_map.get_name()});

    ccf::kv::ConsensusHookPtrs hooks;
    REQUIRE_EQ(
      target.deserialise_snapshot(data.data(), data.size(), hooks),
      ccf::kv::ApplyResult::FAIL);
  }

  SUBCASE("Trailing content after the last map")
  {
    auto data = serialise_snapshot({string_map.get_name()});

    // Append bytes which do not form another map. The header records the
    // entry's size, so it is rewritten to cover them too.
    const std::vector<uint8_t> trailing = {0xAA, 0xBB, 0xCC, 0xDD};
    data.insert(data.end(), trailing.begin(), trailing.end());
    ccf::kv::SerialisedEntryHeader header;
    std::memcpy(&header, data.data(), sizeof(header));
    header.set_size(header.size + trailing.size());
    std::memcpy(data.data(), &header, sizeof(header));

    // The trailing bytes are read as the size prefix of another map's name,
    // and rejected as too short to be one
    ccf::kv::ConsensusHookPtrs hooks;
    REQUIRE_THROWS_WITH_AS(
      target.deserialise_snapshot(data.data(), data.size(), hooks),
      "Expected 8 bytes for fixed-size entry, found only 4",
      std::runtime_error);
  }

  INFO("The failed snapshot left the target unchanged");
  REQUIRE_EQ(target.current_version(), 1);
  {
    auto tx = target.create_read_only_tx();
    REQUIRE_EQ(tx.ro(string_map)->get("public"), "before");
    REQUIRE_EQ(tx.ro(private_map)->get("private"), "before");
  }

  INFO("The target's maps are not left locked");
  {
    auto tx = target.create_tx();
    tx.rw(string_map)->put("public", "after");
    tx.rw(private_map)->put("private", "after");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  INFO("A valid snapshot can still be applied to the target");
  {
    ccf::kv::Store source;
    source.set_encryptor(encryptor);
    for (const auto* value : {"first", "second", "third"})
    {
      auto tx = source.create_tx();
      tx.rw(string_map)->put("public", value);
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    std::unique_ptr<ccf::kv::AbstractStore::AbstractSnapshot> snapshot =
      nullptr;
    {
      ccf::kv::ScopedStoreMapsLock maps_lock(&source);
      snapshot = source.snapshot_unsafe_maps(source.current_version());
    }
    const auto serialised_snapshot =
      source.serialise_snapshot(std::move(snapshot));

    ccf::kv::ConsensusHookPtrs hooks;
    REQUIRE_EQ(
      target.deserialise_snapshot(
        serialised_snapshot.data(), serialised_snapshot.size(), hooks),
      ccf::kv::ApplyResult::PASS);
    REQUIRE_EQ(target.current_version(), source.current_version());

    auto tx = target.create_read_only_tx();
    REQUIRE_EQ(tx.ro(string_map)->get("public"), "third");
    REQUIRE_EQ(tx.ro(private_map)->get("private"), "after");
  }
}

TEST_CASE(
  "Commit transaction while applying snapshot" *
  doctest::test_suite("snapshot"))
{
  ccf::kv::Store store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  store.set_encryptor(encryptor);

  ccf::kv::Version snapshot_version = ccf::kv::NoVersion;
  INFO("Apply transactions to original store");
  {
    auto tx1 = store.create_tx();
    auto handle_1 = tx1.rw<MapTypes::StringString>("public:string_map");
    handle_1->put("foo", "foo");
    REQUIRE(tx1.commit() == ccf::kv::CommitResult::SUCCESS); // Committed at 1

    auto tx2 = store.create_tx();
    auto handle_2 = tx2.rw<MapTypes::StringString>("public:string_map");
    handle_2->put("bar", "bar");
    REQUIRE(tx2.commit() == ccf::kv::CommitResult::SUCCESS); // Committed at 2
    snapshot_version = tx2.commit_version();
  }

  std::unique_ptr<ccf::kv::AbstractStore::AbstractSnapshot> snapshot = nullptr;
  {
    ccf::kv::ScopedStoreMapsLock maps_lock(&store);
    snapshot = store.snapshot_unsafe_maps(snapshot_version);
  }
  auto serialised_snapshot = store.serialise_snapshot(std::move(snapshot));

  INFO("Apply snapshot while committing a transaction");
  {
    ccf::kv::Store new_store;
    new_store.set_encryptor(encryptor);

    auto tx = new_store.create_tx();
    auto handle = tx.rw<MapTypes::StringString>("public:string_map");
    handle->put("in", "flight");
    // tx is not committed until the snapshot is deserialised

    ccf::kv::ConsensusHookPtrs hooks;
    new_store.deserialise_snapshot(
      serialised_snapshot.data(), serialised_snapshot.size(), hooks);

    // Transaction conflicts as snapshot was applied while transaction was in
    // flight
    REQUIRE(tx.commit() == ccf::kv::CommitResult::FAIL_CONFLICT);

    // Try again
    auto tx2 = new_store.create_tx();
    auto handle2 = tx2.rw<MapTypes::StringString>("public:string_map");
    handle2->put("baz", "baz");
    REQUIRE(tx2.commit() == ccf::kv::CommitResult::SUCCESS);
  }
}

TEST_CASE("Commit hooks with snapshot" * doctest::test_suite("snapshot"))
{
  ccf::kv::Store store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  store.set_encryptor(encryptor);

  constexpr auto string_map_name = "public:string_map";
  constexpr auto string_value = "public:string_value";
  constexpr auto string_set = "public:string_set";

  ccf::kv::Version snapshot_version = ccf::kv::NoVersion;

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
    [&](ccf::kv::Version v, const MapWrite& w) -> ccf::kv::ConsensusHookPtr {
    local_map_writes.push_back(w);
    return ccf::kv::ConsensusHookPtr(nullptr);
  };
  auto global_map_hook = [&](ccf::kv::Version v, const MapWrite& w) {
    global_map_writes.push_back(w);
  };
  auto value_hook =
    [&](ccf::kv::Version v, const ValueWrite& w) -> ccf::kv::ConsensusHookPtr {
    local_value_writes.push_back(w);
    return ccf::kv::ConsensusHookPtr(nullptr);
  };
  auto global_value_hook = [&](ccf::kv::Version v, const ValueWrite& w) {
    global_value_writes.push_back(w);
  };
  auto set_hook =
    [&](ccf::kv::Version v, const SetWrite& w) -> ccf::kv::ConsensusHookPtr {
    local_set_writes.push_back(w);
    return ccf::kv::ConsensusHookPtr(nullptr);
  };
  auto global_set_hook = [&](ccf::kv::Version v, const SetWrite& w) {
    global_set_writes.push_back(w);
  };

  INFO("Apply transactions to original store");
  {
    {
      auto tx = store.create_tx();
      auto map_handle = tx.rw<MapTypes::StringString>(string_map_name);
      map_handle->put("foo", "foo");
      map_handle->put("bar", "bar");
      auto value_handle = tx.rw<MapTypes::StringValue>(string_value);
      value_handle->put("foo");
      auto set_handle = tx.rw<MapTypes::StringSet>(string_set);
      set_handle->insert("foo");
      set_handle->insert("bar");
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS); // Committed at 1
    }

    {
      // New transaction, deleting some content from the previous transaction
      auto tx = store.create_tx();
      auto map_handle = tx.rw<MapTypes::StringString>(string_map_name);
      map_handle->put("baz", "baz");
      map_handle->remove("bar");
      auto value_handle = tx.rw<MapTypes::StringValue>(string_value);
      value_handle->put("baz");
      auto set_handle = tx.rw<MapTypes::StringSet>(string_set);
      set_handle->insert("baz");
      set_handle->remove("bar");
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS); // Committed at 2
      snapshot_version = tx.commit_version();
    }
  }

  std::unique_ptr<ccf::kv::AbstractStore::AbstractSnapshot> snapshot = nullptr;
  {
    ccf::kv::ScopedStoreMapsLock maps_lock(&store);
    snapshot = store.snapshot_unsafe_maps(snapshot_version);
  }
  auto serialised_snapshot = store.serialise_snapshot(std::move(snapshot));

  ccf::kv::Store new_store;
  new_store.set_encryptor(encryptor);

  MapTypes::StringString new_string_map(string_map_name);
  MapTypes::StringValue new_string_value(string_value);
  MapTypes::StringSet new_string_set(string_set);

  INFO("Set hooks on target store");
  {
    new_store.set_map_hook(
      string_map_name, new_string_map.wrap_map_hook(map_hook));
    new_store.set_global_hook(
      string_map_name, new_string_map.wrap_commit_hook(global_map_hook));
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
      ccf::kv::ConsensusHookPtrs hooks;
      new_store.deserialise_snapshot(
        serialised_snapshot.data(), serialised_snapshot.size(), hooks);
    }

    INFO("Verify content of snapshot");
    {
      auto tx = new_store.create_tx();
      auto map_handle = tx.ro<MapTypes::StringString>(string_map_name);
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
    auto map_handle = tx.rw<MapTypes::StringString>(string_map_name);
    map_handle->clear();
    auto value_handle = tx.rw<MapTypes::StringValue>(string_value);
    value_handle->clear();
    auto set_handle = tx.rw<MapTypes::StringSet>(string_set);
    set_handle->clear();
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    snapshot_version = tx.commit_version();
    {
      ccf::kv::ScopedStoreMapsLock maps_lock(&store);
      snapshot = store.snapshot_unsafe_maps(snapshot_version);
    }
    serialised_snapshot = store.serialise_snapshot(std::move(snapshot));

    ccf::kv::ConsensusHookPtrs hooks;
    new_store.deserialise_snapshot(
      serialised_snapshot.data(), serialised_snapshot.size(), hooks);

    INFO("Verify content of snapshot");
    {
      auto verify_tx = new_store.create_tx();
      auto verify_map_handle =
        verify_tx.ro<MapTypes::StringString>(string_map_name);
      REQUIRE(!verify_map_handle->get("foo").has_value());
      REQUIRE(!verify_map_handle->get("bar").has_value());
      REQUIRE(!verify_map_handle->get("baz").has_value());
      auto verify_value_handle =
        verify_tx.ro<MapTypes::StringValue>(string_value);
      REQUIRE(!verify_value_handle->get().has_value());
      auto verify_set_handle = verify_tx.rw<MapTypes::StringSet>(string_set);
      REQUIRE(!verify_set_handle->contains("foo"));
      REQUIRE(!verify_set_handle->contains("bar"));
      REQUIRE(!verify_set_handle->contains("baz"));
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

TEST_CASE(
  "Apply snapshot to a store which has rolled back" *
  doctest::test_suite("snapshot"))
{
  ccf::kv::Store store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  store.set_encryptor(encryptor);

  ccf::kv::Version snapshot_version = ccf::kv::NoVersion;
  {
    auto tx = store.create_tx();
    tx.rw(string_map)->put("foo", "bar");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    snapshot_version = tx.commit_version();
  }

  std::unique_ptr<ccf::kv::AbstractStore::AbstractSnapshot> snapshot = nullptr;
  {
    ccf::kv::ScopedStoreMapsLock maps_lock(&store);
    snapshot = store.snapshot_unsafe_maps(snapshot_version);
  }
  auto serialised_snapshot = store.serialise_snapshot(std::move(snapshot));

  ccf::kv::Store new_store;
  new_store.set_encryptor(encryptor);

  INFO("Roll back a transaction on the target store");
  {
    const auto txid_before = new_store.current_txid();

    auto tx = new_store.create_tx();
    tx.rw(num_map)->put(42, 100);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

    new_store.rollback(txid_before, new_store.commit_view());
    REQUIRE(new_store.check_rollback_count(1));
  }

  INFO("Apply snapshot to the rolled back target store");
  {
    ccf::kv::ConsensusHookPtrs hooks;
    REQUIRE_EQ(
      new_store.deserialise_snapshot(
        serialised_snapshot.data(), serialised_snapshot.size(), hooks),
      ccf::kv::ApplyResult::PASS);
    REQUIRE_EQ(new_store.current_version(), snapshot_version);

    auto tx = new_store.create_read_only_tx();
    const auto v = tx.ro(string_map)->get("foo");
    REQUIRE(v.has_value());
    REQUIRE_EQ(v.value(), "bar");
  }
}

TEST_CASE(
  "Installing a snapshot sets the committable gap" *
  doctest::test_suite("snapshot"))
{
  ccf::kv::Store store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  store.set_encryptor(encryptor);

  constexpr size_t tx_count = 5;
  for (size_t i = 0; i < tx_count; ++i)
  {
    auto tx = store.create_tx();
    tx.rw(num_map)->put(i, i);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  // Snapshots are only generated at signature seqnos, so the version a
  // snapshot is installed at is always committable
  const auto snapshot_version = store.current_version();
  REQUIRE(snapshot_version == tx_count);

  std::unique_ptr<ccf::kv::AbstractStore::AbstractSnapshot> snapshot = nullptr;
  {
    ccf::kv::ScopedStoreMapsLock maps_lock(&store);
    snapshot = store.snapshot_unsafe_maps(snapshot_version);
  }
  auto serialised_snapshot = store.serialise_snapshot(std::move(snapshot));

  ccf::kv::Store new_store;
  new_store.set_encryptor(encryptor);
  REQUIRE(new_store.committable_gap() == 0);

  INFO("A store which has just installed a snapshot has no committable gap");
  {
    ccf::kv::ConsensusHookPtrs hooks;
    REQUIRE_EQ(
      new_store.deserialise_snapshot(
        serialised_snapshot.data(), serialised_snapshot.size(), hooks),
      ccf::kv::ApplyResult::PASS);
    REQUIRE_EQ(new_store.current_version(), snapshot_version);
    REQUIRE_EQ(new_store.committable_gap(), 0);
  }

  INFO("Transactions committed after the snapshot are counted from it");
  for (size_t i = 1; i <= 3; ++i)
  {
    auto tx = new_store.create_tx();
    tx.rw(num_map)->put(snapshot_version + i, i);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    REQUIRE_EQ(new_store.current_version(), snapshot_version + i);
    REQUIRE_EQ(new_store.committable_gap(), i);
  }
}

namespace
{
  using MapSnapshots =
    std::vector<std::unique_ptr<ccf::kv::AbstractMap::Snapshot>>;

  MapSnapshots snapshot_maps(
    ccf::kv::Store& store,
    ccf::kv::Version version,
    const std::vector<std::string>& names)
  {
    ccf::kv::ScopedStoreMapsLock maps_lock(&store);
    MapSnapshots snapshots;
    for (const auto& name : names)
    {
      auto map = store.get_map_unsafe(version, name);
      REQUIRE(map != nullptr);
      snapshots.push_back(map->snapshot(version));
    }
    return snapshots;
  }

  // Serialises a snapshot's contents as StoreSnapshot::serialise() did before
  // snapshots were serialised in place: into a buffer for each domain, which
  // are then copied into the entry, encrypting the private domain (with
  // historical_hint, which StoreSnapshot::serialise() always sets)
  std::vector<uint8_t> serialise_buffered(
    const std::shared_ptr<ccf::kv::AbstractTxEncryptor>& encryptor,
    ccf::kv::Version version,
    const std::optional<std::vector<uint8_t>>& hash_at_snapshot,
    const std::optional<std::vector<ccf::kv::Version>>& view_history,
    const MapSnapshots& maps,
    bool historical_hint = true)
  {
    ccf::kv::RawKvStoreSerialiser serialiser(
      encryptor,
      {0, version},
      ccf::kv::EntryType::Snapshot,
      0,
      {},
      ccf::no_claims(),
      historical_hint);
    if (hash_at_snapshot.has_value())
    {
      serialiser.serialise_raw(hash_at_snapshot.value());
    }
    if (view_history.has_value())
    {
      serialiser.serialise_view_history(view_history.value());
    }
    for (const auto domain :
         {ccf::kv::SecurityDomain::PUBLIC, ccf::kv::SecurityDomain::PRIVATE})
    {
      for (const auto& map : maps)
      {
        if (map->get_security_domain() == domain)
        {
          map->serialise(serialiser);
        }
      }
    }
    return serialiser.get_raw_data();
  }

  // Requires that a snapshot of the given maps of store, at its current
  // version, is serialised in place exactly as it was through per-domain
  // buffers, and decodes to its contents
  void require_serialised_in_place(
    ccf::kv::Store& store,
    const std::shared_ptr<ccf::kv::AbstractTxEncryptor>& encryptor,
    const std::vector<std::string>& names,
    const std::optional<std::vector<uint8_t>>& hash_at_snapshot,
    const std::optional<std::vector<ccf::kv::Version>>& view_history)
  {
    const auto version = store.current_version();
    ccf::kv::StoreSnapshot snapshot(version);
    for (auto& map : snapshot_maps(store, version, names))
    {
      snapshot.add_map_snapshot(std::move(map));
    }
    if (hash_at_snapshot.has_value())
    {
      snapshot.add_hash_at_snapshot(
        std::vector<uint8_t>(hash_at_snapshot.value()));
    }
    if (view_history.has_value())
    {
      snapshot.add_view_history(
        std::vector<ccf::kv::Version>(view_history.value()));
    }
    const auto in_place = snapshot.serialise(encryptor);

    REQUIRE(
      in_place ==
      serialise_buffered(
        encryptor,
        version,
        hash_at_snapshot,
        view_history,
        snapshot_maps(store, version, names)));

    // The entry decodes to the snapshot's contents, in order
    ccf::kv::RawKvStoreDeserialiser d(encryptor);
    ccf::kv::Term term = 0;
    ccf::kv::EntryFlags flags = {};
    REQUIRE(
      d.init(in_place.data(), in_place.size(), term, flags, true) == version);
    if (hash_at_snapshot.has_value())
    {
      REQUIRE(d.deserialise_raw() == hash_at_snapshot.value());
    }
    if (view_history.has_value())
    {
      REQUIRE(d.deserialise_view_history() == view_history.value());
    }
    for (const auto& name : names)
    {
      REQUIRE(d.start_map() == name);
      REQUIRE(d.deserialise_entry_version() == version);
      REQUIRE_FALSE(d.deserialise_raw().empty());
    }
    REQUIRE_FALSE(d.start_map().has_value());
  }
}

TEST_CASE(
  "Snapshot serialised in place matches buffered serialisation" *
  doctest::test_suite("snapshot"))
{
  auto secrets = std::make_shared<ccf::LedgerSecrets>();
  secrets->init();
  const std::vector<
    std::pair<std::string, std::shared_ptr<ccf::kv::AbstractTxEncryptor>>>
    encryptors{
      {"none", nullptr},
      {"null", std::make_shared<ccf::kv::NullTxEncryptor>()},
      {"node", std::make_shared<ccf::NodeEncryptor>(secrets)}};
  const std::vector<uint8_t> hash_at_snapshot(32, 0x48);
  const std::vector<ccf::kv::Version> view_history{1, 5, 9};

  for (const auto& config : encryptors)
  {
    const auto& encryptor_name = config.first;
    const auto& encryptor = config.second;
    INFO(encryptor_name);
    // Private maps cannot be serialised without an encryptor
    const bool can_encrypt = encryptor != nullptr;

    ccf::kv::Store store;
    // Transactions cannot be committed without an encryptor, but snapshots
    // can be serialised without one
    store.set_encryptor(
      can_encrypt ? encryptor : std::make_shared<ccf::kv::NullTxEncryptor>());
    MapTypes::StringString private_map("private_map");
    {
      auto tx = store.create_tx();
      for (size_t i = 0; i < 100; ++i)
      {
        tx.rw(string_map)->put(fmt::format("pub{}", i), std::string(i, 'p'));
        if (can_encrypt)
        {
          tx.rw(private_map)
            ->put(fmt::format("priv{}", i), std::string(i, 's'));
        }
      }
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    // Snapshots of either domain, both or neither, with or without the
    // Merkle tree leaf and view history which a node adds to its snapshots
    for (const bool with_public : {false, true})
    {
      for (const bool with_private : {false, true})
      {
        if (with_private && !can_encrypt)
        {
          continue;
        }

        for (const bool with_history : {false, true})
        {
          INFO(with_public);
          INFO(with_private);
          INFO(with_history);
          std::vector<std::string> names;
          if (with_public)
          {
            names.emplace_back("public:string_map");
          }
          if (with_private)
          {
            names.emplace_back("private_map");
          }
          require_serialised_in_place(
            store,
            encryptor,
            names,
            with_history ? std::make_optional(hash_at_snapshot) : std::nullopt,
            with_history ? std::make_optional(view_history) : std::nullopt);
        }
      }
    }
  }
}

TEST_CASE(
  "Snapshot is encrypted with the ledger secret for its version" *
  doctest::test_suite("snapshot"))
{
  const auto first_secret = ccf::make_ledger_secret();
  const auto second_secret = ccf::make_ledger_secret();
  auto secrets = std::make_shared<ccf::LedgerSecrets>();
  secrets->init_from_map({{1, first_secret}});
  auto encryptor = std::make_shared<ccf::NodeEncryptor>(secrets);
  ccf::kv::Store store;
  store.set_encryptor(encryptor);

  MapTypes::StringString private_map("private_map");
  const auto write = [&](const std::string& value) {
    auto tx = store.create_tx();
    tx.rw(string_map)->put("public", value);
    tx.rw(private_map)->put("private", value);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    return tx.commit_version();
  };
  const auto version = write("snapshotted");
  const std::vector<std::string> names{"public:string_map", "private_map"};
  ccf::kv::StoreSnapshot snapshot(version);
  for (auto& map : snapshot_maps(store, version, names))
  {
    snapshot.add_map_snapshot(std::move(map));
  }
  const auto maps = snapshot_maps(store, version, names);

  // The service is rekeyed after the snapshot's version, and encrypts a later
  // transaction with the new ledger secret before the snapshot is serialised
  secrets->set_secret(version + 1, ccf::LedgerSecretPtr(second_secret));
  REQUIRE(write("later") == version + 1);

  // The snapshot is still encrypted with the ledger secret for its version,
  // rather than the one now used for new transactions
  const auto entry = snapshot.serialise(encryptor);
  REQUIRE(
    entry ==
    serialise_buffered(encryptor, version, std::nullopt, std::nullopt, maps));
  REQUIRE(
    entry !=
    serialise_buffered(
      encryptor, version, std::nullopt, std::nullopt, maps, false));

  // so that a node with both ledger secrets, e.g. joining or recovering the
  // service, can install it
  auto node_secrets = std::make_shared<ccf::LedgerSecrets>();
  node_secrets->init_from_map(
    {{1, first_secret}, {version + 1, second_secret}});
  ccf::kv::Store node_store;
  node_store.set_encryptor(std::make_shared<ccf::NodeEncryptor>(node_secrets));
  ccf::kv::ConsensusHookPtrs hooks;
  REQUIRE(
    node_store.deserialise_snapshot(entry.data(), entry.size(), hooks) ==
    ccf::kv::ApplyResult::PASS);
  auto tx = node_store.create_read_only_tx();
  REQUIRE(tx.ro(string_map)->get("public") == "snapshotted");
  REQUIRE(tx.ro(private_map)->get("private") == "snapshotted");
}

TEST_CASE(
  "Snapshot finalised in place cannot be encrypted again" *
  doctest::test_suite("snapshot"))
{
  auto secrets = std::make_shared<ccf::LedgerSecrets>();
  secrets->init();
  auto encryptor = std::make_shared<ccf::NodeEncryptor>(secrets);
  ccf::kv::Store store;
  store.set_encryptor(encryptor);

  MapTypes::StringString private_map("private_map");
  {
    auto tx = store.create_tx();
    tx.rw(string_map)->put("public", "value");
    tx.rw(private_map)->put("private", "secret");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }
  const auto version = store.current_version();
  const ccf::TxID tx_id{0, version};

  auto serialise_maps = [&](ccf::kv::KvStoreSerialiser& s) {
    for (const auto* name : {"public:string_map", "private_map"})
    {
      auto map = store.get_map_unsafe(version, name);
      REQUIRE(map != nullptr);
      map->snapshot(version)->serialise(s);
    }
  };

  // As StoreSnapshot::serialise(): measure, then serialise in place
  ccf::kv::SizeKvStoreSerialiser sizer(
    encryptor,
    tx_id,
    ccf::kv::EntryType::Snapshot,
    0,
    {},
    ccf::no_claims(),
    true);
  serialise_maps(sizer);
  const auto public_size = sizer.get_public_domain_size();
  const auto offset =
    ccf::kv::SpanKvStoreSerialiser::public_domain_offset(encryptor);
  const auto private_offset = offset + public_size;

  std::vector<uint8_t> entry(sizer.get_serialised_size());
  const auto entry_span = std::span<uint8_t>(entry);
  ccf::kv::SpanKvStoreSerialiser serialiser(
    ccf::kv::SpanWriter(entry_span.subspan(offset, public_size)),
    ccf::kv::SpanWriter(entry_span.subspan(private_offset)),
    encryptor,
    tx_id,
    ccf::kv::EntryType::Snapshot,
    0,
    {},
    ccf::no_claims(),
    true);
  serialise_maps(serialiser);

  auto private_domain = [&]() {
    const auto domain = entry_span.subspan(private_offset);
    return std::vector<uint8_t>(domain.begin(), domain.end());
  };
  const auto private_plaintext = private_domain();

  serialiser.finalise_in_place(entry_span);
  REQUIRE(private_domain() != private_plaintext);
  const auto finalised = entry;

  // The private domain was encrypted in place, with an IV determined by the
  // transaction ID, so encrypting it again would restore the plaintext
  REQUIRE_THROWS_AS(serialiser.finalise_in_place(entry_span), std::logic_error);
  REQUIRE_THROWS_AS(serialiser.get_raw_data(), std::logic_error);
  REQUIRE(entry == finalised);

  ccf::kv::Store new_store;
  new_store.set_encryptor(encryptor);
  ccf::kv::ConsensusHookPtrs hooks;
  REQUIRE(
    new_store.deserialise_snapshot(entry.data(), entry.size(), hooks) ==
    ccf::kv::ApplyResult::PASS);
  auto tx = new_store.create_read_only_tx();
  REQUIRE(tx.ro(string_map)->get("public") == "value");
  REQUIRE(tx.ro(private_map)->get("private") == "secret");
}

namespace
{
  // Writes a public and a private map's worth of data
  void serialise_test_maps(ccf::kv::KvStoreSerialiser& s)
  {
    s.start_map("public:map", ccf::kv::SecurityDomain::PUBLIC);
    s.serialise_raw(std::vector<uint8_t>(10, 0x11));
    s.start_map("map", ccf::kv::SecurityDomain::PRIVATE);
    s.serialise_raw(std::vector<uint8_t>(10, 0x22));
  }

  // An entry whose domains have been serialised in place, as by
  // StoreSnapshot::serialise(), but which has not been finalised. If
  // domain_elsewhere is set, that domain is serialised into elsewhere instead
  // of the entry.
  struct InPlaceEntry
  {
    std::vector<uint8_t> entry;
    std::vector<uint8_t> elsewhere;
    std::unique_ptr<ccf::kv::SpanKvStoreSerialiser> serialiser;

    InPlaceEntry(
      const std::shared_ptr<ccf::kv::AbstractTxEncryptor>& encryptor,
      size_t max_transaction_size = ccf::kv::max_serialised_entry_size,
      std::optional<ccf::kv::SecurityDomain> domain_elsewhere = std::nullopt)
    {
      const ccf::TxID tx_id{0, 1};
      ccf::kv::SizeKvStoreSerialiser sizer(
        encryptor, tx_id, ccf::kv::EntryType::Snapshot, 0);
      serialise_test_maps(sizer);
      const auto public_size = sizer.get_public_domain_size();
      const auto offset =
        ccf::kv::SpanKvStoreSerialiser::public_domain_offset(encryptor);
      entry.resize(sizer.get_serialised_size());
      const auto span = std::span<uint8_t>(entry);
      auto public_domain = span.subspan(offset, public_size);
      auto private_domain = span.subspan(offset + public_size);
      if (domain_elsewhere.has_value())
      {
        auto& moved = domain_elsewhere == ccf::kv::SecurityDomain::PUBLIC ?
          public_domain :
          private_domain;
        elsewhere.resize(moved.size());
        moved = elsewhere;
      }
      serialiser = std::make_unique<ccf::kv::SpanKvStoreSerialiser>(
        ccf::kv::SpanWriter(public_domain),
        ccf::kv::SpanWriter(private_domain),
        encryptor,
        tx_id,
        ccf::kv::EntryType::Snapshot,
        0,
        ccf::crypto::Sha256Hash{},
        ccf::no_claims(),
        true,
        max_transaction_size);
      serialise_test_maps(*serialiser);
    }
  };
}

TEST_CASE(
  "Snapshot finalised in place rejects invalid entries" *
  doctest::test_suite("snapshot"))
{
  auto secrets = std::make_shared<ccf::LedgerSecrets>();
  secrets->init();
  auto encryptor = std::make_shared<ccf::NodeEncryptor>(secrets);

  {
    // An entry of the wrong size is left as it was
    InPlaceEntry e(encryptor);
    const auto before = e.entry;
    REQUIRE_THROWS_WITH_AS(
      e.serialiser->finalise_in_place(
        std::span<uint8_t>(e.entry).first(e.entry.size() - 1)),
      doctest::Contains("does not match serialised size"),
      std::logic_error);
    REQUIRE(e.entry == before);

    // Finalisation is attempted at most once, even if it fails
    REQUIRE_THROWS_WITH_AS(
      e.serialiser->finalise_in_place(e.entry),
      doctest::Contains("already finalised"),
      std::logic_error);
    REQUIRE(e.entry == before);
  }

  {
    // An entry of the right size, other than the one which the domains were
    // serialised into, is left as it was, as is that one
    InPlaceEntry e(encryptor);
    const auto before = e.entry;
    std::vector<uint8_t> other(e.entry.size());
    REQUIRE_THROWS_WITH_AS(
      e.serialiser->finalise_in_place(other),
      doctest::Contains("not serialised in place"),
      std::logic_error);
    REQUIRE(other == std::vector<uint8_t>(e.entry.size()));
    REQUIRE(e.entry == before);
  }

  for (const auto domain :
       {ccf::kv::SecurityDomain::PUBLIC, ccf::kv::SecurityDomain::PRIVATE})
  {
    // An entry with either domain serialised elsewhere is left as it was, as
    // is that domain
    const auto* domain_name =
      domain == ccf::kv::SecurityDomain::PUBLIC ? "public" : "private";
    INFO(domain_name);
    InPlaceEntry e(encryptor, ccf::kv::max_serialised_entry_size, domain);
    const auto before = e.entry;
    const auto elsewhere_before = e.elsewhere;
    REQUIRE_THROWS_WITH_AS(
      e.serialiser->finalise_in_place(e.entry),
      doctest::Contains("not serialised in place"),
      std::logic_error);
    REQUIRE(e.entry == before);
    REQUIRE(e.elsewhere == elsewhere_before);
  }

  {
    // An entry larger than the maximum transaction size, which is inclusive
    const auto entry_size = InPlaceEntry(encryptor).entry.size();
    InPlaceEntry too_large(encryptor, entry_size - 1);
    const auto before = too_large.entry;
    REQUIRE_THROWS_AS(
      too_large.serialiser->finalise_in_place(too_large.entry),
      ccf::kv::KvSerialiserException);
    REQUIRE(too_large.entry == before);

    InPlaceEntry largest(encryptor, entry_size);
    REQUIRE_NOTHROW(largest.serialiser->finalise_in_place(largest.entry));
  }

  {
    // Encryption fails, as there is no ledger secret to encrypt with
    InPlaceEntry e(std::make_shared<ccf::NodeEncryptor>(
      std::make_shared<ccf::LedgerSecrets>()));
    REQUIRE_THROWS_AS(
      e.serialiser->finalise_in_place(e.entry), ccf::kv::KvSerialiserException);
  }

  {
    // Private data is never written unencrypted. start_map() prevents private
    // maps from being serialised without an encryptor, but a private writer
    // which already holds data may be supplied.
    const ccf::TxID tx_id{0, 1};
    ccf::kv::SizeKvStoreSerialiser sizer(
      nullptr, tx_id, ccf::kv::EntryType::Snapshot, 0);
    const auto public_size = sizer.get_public_domain_size();
    const auto offset =
      ccf::kv::SpanKvStoreSerialiser::public_domain_offset(nullptr);
    std::vector<uint8_t> entry(offset + public_size + 1);
    const auto span = std::span<uint8_t>(entry);
    ccf::kv::SpanWriter private_writer(span.subspan(offset + public_size));
    private_writer.append(uint8_t{0x22});
    ccf::kv::SpanKvStoreSerialiser serialiser(
      ccf::kv::SpanWriter(span.subspan(offset, public_size)),
      ccf::kv::SpanWriter(private_writer),
      nullptr,
      tx_id,
      ccf::kv::EntryType::Snapshot,
      0);
    const auto before = entry;
    REQUIRE_THROWS_WITH_AS(
      serialiser.finalise_in_place(entry),
      doctest::Contains("without an encryptor"),
      std::logic_error);
    REQUIRE(entry == before);
  }
}

namespace
{
  // A map snapshot whose serialised payload has the given size each time it
  // is serialised. A real map snapshot cannot change size between the passes
  // which measure and then write a snapshot: it is an immutable copy of the
  // map's state.
  class ResizingMapSnapshot : public ccf::kv::AbstractMap::Snapshot
  {
  private:
    ccf::kv::SecurityDomain domain;
    std::vector<size_t> payload_sizes;
    size_t serialisations = 0;

  public:
    ResizingMapSnapshot(
      ccf::kv::SecurityDomain domain_, std::vector<size_t> payload_sizes_) :
      domain(domain_),
      payload_sizes(std::move(payload_sizes_))
    {}

    static std::string map_name(ccf::kv::SecurityDomain map_domain)
    {
      return map_domain == ccf::kv::SecurityDomain::PUBLIC ? "public:map" :
                                                             "map";
    }

    void serialise(ccf::kv::KvStoreSerialiser& s) override
    {
      s.start_map(map_name(domain), domain);
      s.serialise_entry_version(1);
      s.serialise_raw_in_place(
        payload_sizes.at(serialisations++), [](std::span<uint8_t> payload) {
          std::ranges::fill(payload, uint8_t{0x42});
        });
    }

    [[nodiscard]] ccf::kv::SecurityDomain get_security_domain() const override
    {
      return domain;
    }
  };
}

TEST_CASE(
  "Snapshot serialisation rejects maps which change between passes" *
  doctest::test_suite("snapshot"))
{
  auto secrets = std::make_shared<ccf::LedgerSecrets>();
  secrets->init();
  auto encryptor = std::make_shared<ccf::NodeEncryptor>(secrets);
  constexpr ccf::kv::Version version = 1;

  const auto serialise =
    [&](ccf::kv::SecurityDomain domain, std::vector<size_t> payload_sizes) {
      ccf::kv::StoreSnapshot snapshot(version);
      snapshot.add_map_snapshot(std::make_unique<ResizingMapSnapshot>(
        domain, std::move(payload_sizes)));
      return snapshot.serialise(encryptor);
    };

  for (const auto domain :
       {ccf::kv::SecurityDomain::PUBLIC, ccf::kv::SecurityDomain::PRIVATE})
  {
    const auto name = ResizingMapSnapshot::map_name(domain);
    INFO(name);

    // A map which writes more than was measured cannot write beyond its
    // domain's region of the entry
    REQUIRE_THROWS_WITH_AS(
      serialise(domain, {16, 17}),
      doctest::Contains("capacity"),
      std::length_error);

    // and one which writes less cannot leave part of that region unwritten
    REQUIRE_THROWS_WITH_AS(
      serialise(domain, {16, 15}),
      doctest::Contains("but measured"),
      std::logic_error);

    // A map which writes what was measured is written in place
    const auto entry = serialise(domain, {16, 16});
    ccf::kv::RawKvStoreDeserialiser d(encryptor);
    ccf::kv::Term term = 0;
    ccf::kv::EntryFlags flags = {};
    REQUIRE(d.init(entry.data(), entry.size(), term, flags, true) == version);
    REQUIRE(d.start_map() == name);
    REQUIRE(d.deserialise_entry_version() == 1);
    REQUIRE(d.deserialise_raw() == std::vector<uint8_t>(16, 0x42));
    REQUIRE_FALSE(d.start_map().has_value());
  }
}

TEST_CASE(
  "Snapshot deserialised in place, reusing captured public maps" *
  doctest::test_suite("snapshot"))
{
  auto secrets = std::make_shared<ccf::LedgerSecrets>();
  secrets->init();
  auto encryptor = std::make_shared<ccf::NodeEncryptor>(secrets);
  ccf::kv::ConsensusHookPtrs hooks;

  MapTypes::StringString private_map("private_map");
  MapTypes::StringString other_public_map("public:other_map");

  // Each snapshot is of a single transaction, so all are at the same version
  const auto version = ccf::kv::Version{1};
  auto snapshot_of = [&](const std::function<void(ccf::kv::Tx&)>& write) {
    ccf::kv::Store store;
    store.set_encryptor(encryptor);
    auto tx = store.create_tx();
    write(tx);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    std::unique_ptr<ccf::kv::AbstractStore::AbstractSnapshot> snapshot;
    {
      ccf::kv::ScopedStoreMapsLock maps_lock(&store);
      snapshot = store.snapshot_unsafe_maps(store.current_version());
    }
    return store.serialise_snapshot(std::move(snapshot));
  };

  auto capture = [&](const std::vector<uint8_t>& entry) {
    ccf::kv::Store public_store;
    public_store.set_encryptor(encryptor);
    std::optional<ccf::kv::Store::SnapshotPublicMaps> captured;
    REQUIRE(
      public_store.deserialise_public_snapshot_capturing(
        entry.data(), entry.size(), hooks, nullptr, captured) ==
      ccf::kv::ApplyResult::PASS);
    REQUIRE(captured.has_value());
    // Rejections below are then due to contents, not versions
    REQUIRE(public_store.current_version() == version);
    return std::move(captured.value());
  };

  auto deserialise_reusing =
    [&](
      const std::vector<uint8_t>& entry,
      const ccf::kv::Store::SnapshotPublicMaps* captured) {
      auto buffer = entry;
      ccf::kv::Store store;
      store.set_encryptor(encryptor);
      return store.deserialise_snapshot_in_place(
        buffer, hooks, nullptr, captured);
    };

  const auto entry = snapshot_of([&](ccf::kv::Tx& tx) {
    tx.rw(string_map)->put("public", "value");
    tx.rw(num_map)->put(1, 2);
    tx.rw(private_map)->put("private", "secret");
  });

  // As during recovery: public domain first, before ledger secrets are known
  ccf::kv::Store public_store;
  public_store.set_encryptor(encryptor);
  std::optional<ccf::kv::Store::SnapshotPublicMaps> captured;
  REQUIRE(
    public_store.deserialise_public_snapshot_capturing(
      entry.data(), entry.size(), hooks, nullptr, captured) ==
    ccf::kv::ApplyResult::PASS);
  REQUIRE(captured.has_value());
  REQUIRE(public_store.current_version() == version);

  // Later writes to the public store are not visible through captured states
  {
    auto tx = public_store.create_tx();
    tx.rw(string_map)->put("public", "changed");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  INFO("Private domain decrypted in place, captured public maps installed");
  {
    auto buffer = entry;
    ccf::kv::Store recovery_store;
    recovery_store.set_encryptor(encryptor);
    REQUIRE(
      recovery_store.deserialise_snapshot_in_place(
        buffer, hooks, nullptr, &captured.value()) ==
      ccf::kv::ApplyResult::PASS);
    REQUIRE(recovery_store.current_version() == version);
    REQUIRE(buffer != entry);

    auto tx = recovery_store.create_read_only_tx();
    REQUIRE(tx.ro(string_map)->get("public") == "value");
    REQUIRE(tx.ro(num_map)->get(1) == 2);
    REQUIRE(tx.ro(private_map)->get("private") == "secret");
  }

  INFO("Without captured public maps, both domains are deserialised");
  REQUIRE(deserialise_reusing(entry, nullptr) == ccf::kv::ApplyResult::PASS);

  INFO("Public maps captured from a different snapshot are rejected");
  {
    const auto different = capture(snapshot_of([&](ccf::kv::Tx& tx) {
      tx.rw(string_map)->put("public", "other value");
      tx.rw(num_map)->put(1, 2);
      tx.rw(private_map)->put("private", "secret");
    }));
    REQUIRE(
      deserialise_reusing(entry, &different) == ccf::kv::ApplyResult::FAIL);

    const auto missing = capture(snapshot_of([&](ccf::kv::Tx& tx) {
      tx.rw(string_map)->put("public", "value");
      tx.rw(private_map)->put("private", "secret");
    }));
    REQUIRE(deserialise_reusing(entry, &missing) == ccf::kv::ApplyResult::FAIL);

    const auto extra = capture(snapshot_of([&](ccf::kv::Tx& tx) {
      tx.rw(string_map)->put("public", "value");
      tx.rw(num_map)->put(1, 2);
      tx.rw(other_public_map)->put("other", "value");
      tx.rw(private_map)->put("private", "secret");
    }));
    REQUIRE(deserialise_reusing(entry, &extra) == ccf::kv::ApplyResult::FAIL);
  }

  INFO("Tampering with either domain is detected");
  {
    auto public_tampered = entry;
    const auto offset =
      ccf::kv::RawKvStoreSerialiser::public_domain_offset(encryptor);
    public_tampered[offset + 20] ^= 1;
    REQUIRE(
      deserialise_reusing(public_tampered, &captured.value()) ==
      ccf::kv::ApplyResult::FAIL);

    auto private_tampered = entry;
    private_tampered.back() ^= 1;
    REQUIRE(
      deserialise_reusing(private_tampered, nullptr) ==
      ccf::kv::ApplyResult::FAIL);
  }
}
